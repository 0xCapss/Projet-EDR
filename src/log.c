/*
 * log.c - /var/log/edr.log writer
 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "log.h"

static int log_fd = -1;
static off_t log_size;
static char log_path[PATH_MAX];

/* Bounded string builder: on overflow the line is dropped, never truncated */
struct line {
	char  *buf;
	size_t size;
	size_t len;
	int    overflow;
};

__attribute__((format(printf, 2, 3)))
static void line_printf(struct line *l, const char *fmt, ...)
{
	va_list ap;
	int n;

	if (l->overflow)
		return;
	va_start(ap, fmt);
	n = vsnprintf(l->buf + l->len, l->size - l->len, fmt, ap);
	va_end(ap);
	if (n < 0 || (size_t)n >= l->size - l->len) {
		l->overflow = 1;
		return;
	}
	l->len += (size_t)n;
}

/* Append s (at most max bytes, stops at NUL) as a quoted JSON string.
 * Control characters, '"', '\\' and non-ASCII bytes are escaped. */
static void line_json_str(struct line *l, const char *s, size_t max)
{
	const unsigned char *p = (const unsigned char *)s;
	size_t i;

	line_printf(l, "\"");
	for (i = 0; i < max && p[i] != '\0'; i++) {
		if (p[i] == '"' || p[i] == '\\')
			line_printf(l, "\\%c", p[i]);
		else if (p[i] < 0x20 || p[i] >= 0x7f)
			line_printf(l, "\\u%04x", p[i]);
		else
			line_printf(l, "%c", p[i]);
	}
	line_printf(l, "\"");
}

static void line_time(struct line *l, uint64_t mono_ns)
{
	struct timespec real;
	struct timespec mono;
	struct tm tm;
	char date[32];
	char zone[8];
	int64_t ns;
	time_t sec;

	/* Events are stamped with bpf_ktime_get_ns() (CLOCK_MONOTONIC):
	 * shift them to wall time */
	clock_gettime(CLOCK_REALTIME, &real);
	clock_gettime(CLOCK_MONOTONIC, &mono);
	ns = (int64_t)mono_ns
	     + ((int64_t)real.tv_sec - (int64_t)mono.tv_sec) * 1000000000LL
	     + ((int64_t)real.tv_nsec - (int64_t)mono.tv_nsec);
	if (ns < 0)
		ns = 0;

	sec = (time_t)(ns / 1000000000LL);
	if (localtime_r(&sec, &tm) == NULL ||
	    strftime(date, sizeof(date), "%Y-%m-%dT%H:%M:%S", &tm) == 0 ||
	    strftime(zone, sizeof(zone), "%z", &tm) == 0) {
		line_printf(l, "\"time\":null");
		return;
	}
	line_printf(l, "\"time\":\"%s.%06lld%s\"", date,
		    (long long)(ns % 1000000000LL) / 1000, zone);
}

/* Event type -> LSM hook and event name, for every EVENT_* of edr.h */
static const struct {
	const char *hook;
	const char *event;
} event_names[] = {
	[EVENT_EXEC]		= { "bprm_check_security", "exec" },
	[EVENT_FILE_OPEN]	= { "file_open", "file_open" },
	[EVENT_SETUID]		= { "task_fix_setuid", "setuid" },
	[EVENT_PTRACE]		= { "ptrace_access_check", "ptrace" },
	[EVENT_KILL]		= { "task_kill", "kill" },
	[EVENT_NET_CONNECT]	= { "socket_connect", "connect" },
	[EVENT_MODULE]		= { "kernel_load_data", "module" },
	[EVENT_MOUNT]		= { "sb_mount", "mount" },
	[EVENT_UNMOUNT]		= { "sb_umount", "umount" },
	[EVENT_MMAP_EXEC]	= { "mmap_file", "mmap_exec" },
	[EVENT_PRCTL]		= { "task_prctl", "prctl" },
	[EVENT_FILE_CREATE]	= { "inode_create", "file_create" },
	[EVENT_FILE_UNLINK]	= { "inode_unlink", "file_unlink" },
	[EVENT_FILE_RENAME]	= { "inode_rename", "file_rename" },
	[EVENT_FILE_SETATTR]	= { "inode_setattr", "file_setattr" },
};

#define EVENT_NAMES_COUNT	(sizeof(event_names) / sizeof(event_names[0]))

static const char *hook_name(uint32_t type)
{
	if (type < EVENT_NAMES_COUNT && event_names[type].hook)
		return event_names[type].hook;
	return "unknown";
}

static const char *event_name(uint32_t type)
{
	if (type < EVENT_NAMES_COUNT && event_names[type].event)
		return event_names[type].event;
	return "unknown";
}

static const char *action_name(uint32_t action)
{
	switch (action) {
	case ACTION_BLOCK:	return "block";
	case ACTION_ALLOW:	return "allow";
	case ACTION_SIGNAL:	return "signal";
	default:		return "none";
	}
}

int log_format_event(const struct event *e, char *buf, size_t size)
{
	struct line l = { .buf = buf, .size = size };

	line_printf(&l, "{");
	line_time(&l, e->timestamp);
	line_printf(&l, ",\"hook\":\"%s\",\"event\":\"%s\",\"action\":\"%s\""
		    ",\"pid\":%u,\"ppid\":%u,\"uid\":%u,\"comm\":",
		    hook_name(e->type), event_name(e->type), action_name(e->action),
		    e->pid, e->ppid, e->uid);
	line_json_str(&l, e->comm, sizeof(e->comm));
	line_printf(&l, ",\"path\":");
	line_json_str(&l, e->path, sizeof(e->path));
	line_printf(&l, "}\n");

	return l.overflow ? -1 : (int)l.len;
}

/* —— File ———————————————————————————————————————————————— */

/*
 * Open log_path, then swap it with the current descriptor.
 * The owner and mode chosen at install time are kept (root:adm 0640, so
 * that rsyslog can read the file after dropping its privileges); only
 * the bits for others and group write are removed. tmpl, when given, is
 * the file being rotated: the new file gets its owner and mode.
 */
static int log_reopen(const struct stat *tmpl)
{
	struct stat st;
	int fd;

	/* O_NOFOLLOW: a symlink planted in /var/log must not redirect the log */
	fd = open(log_path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
	if (fd < 0)
		return -errno;
	if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode))
		goto fail;
	if (tmpl) {
		if (fchown(fd, tmpl->st_uid, tmpl->st_gid) < 0 ||
		    fchmod(fd, tmpl->st_mode & 0640) < 0)
			goto fail;
	} else if ((st.st_mode & 07777) & ~0640U) {
		if (fchmod(fd, st.st_mode & 0640) < 0)
			goto fail;
	}

	log_close();
	log_fd = fd;
	log_size = st.st_size;
	return 0;
fail:
	close(fd);
	return -EINVAL;
}

int log_open(const char *path)
{
	int n;

	n = snprintf(log_path, sizeof(log_path), "%s", path);
	if (n < 0 || (size_t)n >= sizeof(log_path))
		return -ENAMETOOLONG;
	return log_reopen(NULL);
}

void log_close(void)
{
	if (log_fd >= 0)
		close(log_fd);
	log_fd = -1;
}

int log_rotate_if_needed(void)
{
	char from[PATH_MAX + 8];
	char to[PATH_MAX + 8];
	struct stat old;
	int i;

	if (log_fd < 0 || log_size < LOG_MAX_SIZE)
		return 0;
	if (fstat(log_fd, &old) < 0)
		return -errno;

	for (i = LOG_KEEP - 1; i >= 1; i--) {
		snprintf(from, sizeof(from), "%s.%d", log_path, i);
		snprintf(to, sizeof(to), "%s.%d", log_path, i + 1);
		if (rename(from, to) < 0 && errno != ENOENT)
			return -errno;
	}
	snprintf(to, sizeof(to), "%s.1", log_path);
	if (rename(log_path, to) < 0)
		return -errno;
	return log_reopen(&old);
}

static int write_all(int fd, const char *buf, size_t len)
{
	ssize_t n;

	while (len > 0) {
		n = write(fd, buf, len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		buf += n;
		len -= (size_t)n;
	}
	return 0;
}

static int log_write(const char *buf, size_t len, int echo)
{
	int err = 0;

	if (echo)
		fputs(buf, stdout);
	if (log_fd >= 0) {
		/* One write per line: readers (tail -F, rsyslog) never see half a line */
		err = write_all(log_fd, buf, len);
		if (err == 0)
			log_size += (off_t)len;
	}
	return err;
}

int log_event(const struct event *e, int echo)
{
	char buf[4096];
	int len;

	len = log_format_event(e, buf, sizeof(buf));
	if (len < 0)
		return -EOVERFLOW;
	return log_write(buf, (size_t)len, echo);
}

int log_daemon(const char *action, const char *msg, int echo)
{
	struct event now = { 0 };
	struct timespec ts;
	struct line l;
	char buf[1024];

	clock_gettime(CLOCK_MONOTONIC, &ts);
	now.timestamp = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;

	l = (struct line){ .buf = buf, .size = sizeof(buf) };
	line_printf(&l, "{");
	line_time(&l, now.timestamp);
	line_printf(&l, ",\"hook\":\"edrd\",\"event\":\"daemon\",\"action\":\"%s\""
		    ",\"pid\":%d,\"msg\":", action, (int)getpid());
	line_json_str(&l, msg, SIZE_MAX);
	line_printf(&l, "}\n");
	if (l.overflow)
		return -EOVERFLOW;
	return log_write(buf, l.len, echo);
}
