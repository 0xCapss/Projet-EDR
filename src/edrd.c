/*
 * edrd - mini EDR daemon
 *
 * Loads the BPF-LSM programs, pins their maps and links in
 * /sys/fs/bpf/edr, then reads the ring buffer and writes every event to
 * /var/log/edr.log.
 *
 * The links are pinned: if edrd dies, the hooks stay attached and keep
 * blocking. A new edrd replaces them and reuses the pinned maps, so the
 * rules written by edrctl survive a restart.
 */
#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "edr.h"
#include "edr.skel.h"
#include "log.h"

#define BPF_FS_ROOT		"/sys/fs/bpf"
#define BPF_FS_MAGIC		0xcafe4a11
#define HEARTBEAT_SEC		2
#define POLL_TIMEOUT_MS		1000

struct options {
	int foreground;		/* echo events on stdout */
	int verbose;		/* libbpf debug output */
	int unload;
};

static volatile sig_atomic_t stop_requested;
static volatile sig_atomic_t reopen_requested;
static struct options opts;
static uint64_t events_logged;

static void handle_signal(int sig)
{
	if (sig == SIGHUP)
		reopen_requested = 1;
	else
		stop_requested = 1;
}

static int libbpf_print(enum libbpf_print_level level, const char *fmt, va_list ap)
{
	if (level == LIBBPF_DEBUG && !opts.verbose)
		return 0;
	return vfprintf(stderr, fmt, ap);
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [-f] [-v]\n"
		"       %s -u\n"
		"  -f  also print events on stdout\n"
		"  -v  verbose libbpf output\n"
		"  -u  detach every hook and remove " EDR_PIN_DIR ", then exit\n",
		prog, prog);
}

static int parse_options(int argc, char **argv)
{
	int c;

	while ((c = getopt(argc, argv, "fvuh")) != -1) {
		switch (c) {
		case 'f':
			opts.foreground = 1;
			break;
		case 'v':
			opts.verbose = 1;
			break;
		case 'u':
			opts.unload = 1;
			break;
		default:
			usage(argv[0]);
			return -1;
		}
	}
	if (optind != argc) {
		usage(argv[0]);
		return -1;
	}
	return 0;
}

/* —— bpffs ————————————————————————————————————————————————— */

static int make_dir(const char *path)
{
	if (mkdir(path, 0700) < 0 && errno != EEXIST) {
		fprintf(stderr, "edrd: mkdir %s: %s\n", path, strerror(errno));
		return -1;
	}
	return 0;
}

/* Mount bpffs if the boot did not, then create our directories */
static int prepare_bpffs(void)
{
	struct statfs st;

	if (statfs(BPF_FS_ROOT, &st) < 0 || st.f_type != BPF_FS_MAGIC) {
		if (mount("bpf", BPF_FS_ROOT, "bpf", 0, "mode=0700") < 0) {
			fprintf(stderr, "edrd: mount bpffs: %s\n", strerror(errno));
			return -1;
		}
	}
	if (make_dir(EDR_PIN_DIR) < 0 || make_dir(EDR_LINK_DIR) < 0)
		return -1;
	return 0;
}

/* Remove every file of a bpffs directory, then the directory itself */
static int remove_dir(const char *path)
{
	struct dirent *de;
	int ret = 0;
	DIR *dir;

	dir = opendir(path);
	if (!dir)
		return errno == ENOENT ? 0 : -1;
	while ((de = readdir(dir)) != NULL) {
		if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
			continue;
		if (unlinkat(dirfd(dir), de->d_name, 0) < 0 && errno != EISDIR) {
			fprintf(stderr, "edrd: unlink %s/%s: %s\n", path, de->d_name,
				strerror(errno));
			ret = -1;
		}
	}
	closedir(dir);
	if (rmdir(path) < 0 && errno != ENOENT)
		ret = -1;
	return ret;
}

/* edrd -u: unpinning the links detaches the hooks */
static int unload(void)
{
	int ret = 0;

	if (remove_dir(EDR_LINK_DIR) < 0)
		ret = 1;
	if (remove_dir(EDR_PIN_DIR) < 0)
		ret = 1;
	/* The kernel releases the links asynchronously, within a second */
	if (ret == 0)
		printf("edrd: %s removed, hooks detached\n", EDR_PIN_DIR);
	return ret;
}

/* —— Maps and hooks ——————————————————————————————————————————— */

/*
 * Pin every map but the ring buffer as EDR_PIN_DIR/<name>, so that edrctl
 * reaches them without edrd. Must be called before load: libbpf then
 * reuses a map already pinned by a previous edrd instead of creating it.
 */
static int set_pin_paths(struct edr *skel)
{
	struct bpf_map *map;
	char path[PATH_MAX];
	int n;

	bpf_object__for_each_map(map, skel->obj) {
		/* The ring buffer is not shared; internal maps (.rodata, .bss)
		 * have a dot in their name, which bpffs refuses */
		if (bpf_map__type(map) == BPF_MAP_TYPE_RINGBUF ||
		    bpf_map__is_internal(map))
			continue;
		n = snprintf(path, sizeof(path), "%s/%s", EDR_PIN_DIR, bpf_map__name(map));
		if (n < 0 || (size_t)n >= sizeof(path) || bpf_map__set_pin_path(map, path)) {
			fprintf(stderr, "edrd: pin path for %s\n", bpf_map__name(map));
			return -1;
		}
	}
	return 0;
}

/* "lsm/file_open" -> "file_open" */
static const char *hook_of(const struct bpf_program *prog)
{
	const char *sec = bpf_program__section_name(prog);

	if (strncmp(sec, "lsm/", 4) == 0)
		return sec + 4;
	return bpf_program__name(prog);
}

/*
 * Attach every program and pin its link as EDR_LINK_DIR/<hook>; edrctl
 * status lists this directory. A link left by a previous edrd is replaced
 * only once the new one is attached, so the hook is never missing. A hook
 * that fails is reported, the others go on.
 */
static int attach_hooks(struct edr *skel)
{
	struct bpf_program *prog;
	struct bpf_link *link;
	char path[PATH_MAX];
	int attached = 0;
	int err;
	int n;

	bpf_object__for_each_program(prog, skel->obj) {
		n = snprintf(path, sizeof(path), "%s/%s", EDR_LINK_DIR, hook_of(prog));
		if (n < 0 || (size_t)n >= sizeof(path))
			continue;

		link = bpf_program__attach(prog);
		if (!link) {
			fprintf(stderr, "edrd: attach %s: %s\n", hook_of(prog),
				strerror(errno));
			continue;
		}
		if (unlink(path) < 0 && errno != ENOENT)
			fprintf(stderr, "edrd: unlink %s: %s\n", path, strerror(errno));
		err = bpf_link__pin(link, path);
		if (err) {
			fprintf(stderr, "edrd: pin %s: %s\n", path, strerror(-err));
			bpf_link__destroy(link);
			continue;
		}
		/* Closes our fd only: the pinned link stays attached */
		bpf_link__destroy(link);
		attached++;
	}
	return attached;
}

/* —— Daemon state ————————————————————————————————————————————— */

/* Open EDR_PIN_DIR/daemon_state, creating and pinning it the first time */
static int daemon_state_open(void)
{
	const char *path = EDR_PIN_DIR "/" EDR_DAEMON_MAP;
	int fd;

	fd = bpf_obj_get(path);
	if (fd >= 0)
		return fd;

	fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, EDR_DAEMON_MAP, sizeof(uint32_t),
			    sizeof(struct daemon_state), 1, NULL);
	if (fd < 0) {
		fprintf(stderr, "edrd: create %s: %s\n", EDR_DAEMON_MAP, strerror(errno));
		return -1;
	}
	if (bpf_obj_pin(fd, path) < 0) {
		fprintf(stderr, "edrd: pin %s: %s\n", path, strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
}

static void daemon_state_write(int fd, uint32_t pid, uint64_t start)
{
	struct daemon_state state = {
		.pid = pid,
		.start_time = start,
		.heartbeat = (uint64_t)time(NULL),
		.events_logged = events_logged,
	};
	uint32_t zero = 0;

	if (fd >= 0 && bpf_map_update_elem(fd, &zero, &state, BPF_ANY) < 0)
		fprintf(stderr, "edrd: update %s: %s\n", EDR_DAEMON_MAP, strerror(errno));
}

/* —— Self-protection ————————————————————————————————————————— */

/* task_kill and ptrace_access_check protect the PID found in slot 0 of
 * protected_pid_map; 0 disables the protection */
static void protect_pid(struct edr *skel, uint32_t pid)
{
	uint32_t zero = 0;

	if (bpf_map__update_elem(skel->maps.protected_pid_map, &zero, sizeof(zero),
				 &pid, sizeof(pid), BPF_ANY) < 0)
		fprintf(stderr, "edrd: update protected_pid_map: %s\n", strerror(errno));
}

/* —— Events ————————————————————————————————————————————————— */

static int handle_event(void *ctx, void *data, size_t size)
{
	struct event e;
	int err;

	(void)ctx;
	if (size < sizeof(e))
		return 0;
	memcpy(&e, data, sizeof(e));

	err = log_event(&e, opts.foreground);
	if (err)
		fprintf(stderr, "edrd: write %s: %s\n", EDR_LOG_PATH, strerror(-err));
	else
		events_logged++;
	return 0;
}

static int install_signals(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = handle_signal;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGINT, &sa, NULL) < 0 || sigaction(SIGTERM, &sa, NULL) < 0 ||
	    sigaction(SIGHUP, &sa, NULL) < 0)
		return -1;
	sa.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &sa, NULL) < 0)
		return -1;
	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct edr *skel = NULL;
	int state_fd = -1;
	char msg[128];
	time_t last_beat = 0;
	uint64_t start;
	int hooks;
	int err;
	int ret = 1;

	if (parse_options(argc, argv) < 0)
		return 2;
	if (geteuid() != 0) {
		fprintf(stderr, "edrd: must run as root\n");
		return 1;
	}
	if (opts.unload)
		return unload();

	umask(077);
	libbpf_set_print(libbpf_print);
	if (install_signals() < 0) {
		perror("edrd: sigaction");
		return 1;
	}
	if (prepare_bpffs() < 0)
		return 1;

	skel = edr__open();
	if (!skel) {
		fprintf(stderr, "edrd: open BPF object: %s\n", strerror(errno));
		goto cleanup;
	}
	if (set_pin_paths(skel) < 0)
		goto cleanup;
	err = edr__load(skel);
	if (err) {
		fprintf(stderr, "edrd: load BPF object: %s (stale maps? try edrd -u)\n",
			strerror(-err));
		goto cleanup;
	}

	hooks = attach_hooks(skel);
	if (hooks == 0) {
		fprintf(stderr, "edrd: no hook attached\n");
		goto cleanup;
	}
	protect_pid(skel, (uint32_t)getpid());

	err = log_open(EDR_LOG_PATH);
	if (err)
		fprintf(stderr, "edrd: open %s: %s\n", EDR_LOG_PATH, strerror(-err));

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "edrd: ring buffer: %s\n", strerror(errno));
		goto cleanup;
	}

	state_fd = daemon_state_open();
	start = (uint64_t)time(NULL);
	daemon_state_write(state_fd, (uint32_t)getpid(), start);
	snprintf(msg, sizeof(msg), "started, %d hooks attached", hooks);
	log_daemon("start", msg, opts.foreground);
	fprintf(stderr, "edrd: %s (pid %d)\n", msg, (int)getpid());

	while (!stop_requested) {
		err = ring_buffer__poll(rb, POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "edrd: ring buffer poll: %s\n", strerror(-err));
			break;
		}

		/* SIGHUP: reopen the log (after an external rotation) */
		if (reopen_requested) {
			reopen_requested = 0;
			err = log_open(EDR_LOG_PATH);
			if (err)
				fprintf(stderr, "edrd: reopen %s: %s\n", EDR_LOG_PATH,
					strerror(-err));
		}

		if (time(NULL) - last_beat >= HEARTBEAT_SEC) {
			last_beat = time(NULL);
			daemon_state_write(state_fd, (uint32_t)getpid(), start);
			err = log_rotate_if_needed();
			if (err)
				fprintf(stderr, "edrd: rotate %s: %s\n", EDR_LOG_PATH,
					strerror(-err));
		}
	}

	/* The hooks stay attached: blocking goes on without edrd */
	/* A recycled PID must not inherit the protection */
	protect_pid(skel, 0);
	daemon_state_write(state_fd, 0, start);
	log_daemon("stop", "stopped, hooks left attached", opts.foreground);
	ret = 0;

cleanup:
	if (state_fd >= 0)
		close(state_fd);
	ring_buffer__free(rb);
	edr__destroy(skel);
	log_close();
	return ret;
}
