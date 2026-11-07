/*
 * edrctl - mini EDR control tool
 *
 * Works on the maps pinned by edrd in /sys/fs/bpf/edr, so the rules can be
 * changed even when edrd is stopped. watch follows /var/log/edr.log.
 */
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>

#include "edr.h"

#define HEARTBEAT_STALE_SEC	10	/* edrd refreshes it every 2 s */
#define WATCH_POLL_NS		200000000L
#define MAX_HOOKS		32
#define MAX_STATS		1024
#define LINE_MAX_LEN		4096
#define FIELD_MAX_LEN		1024

static void usage(void)
{
	fprintf(stderr,
		"usage: edrctl status\n"
		"       edrctl watch [-a]\n"
		"       edrctl block add|del <path|ip>\n"
		"       edrctl block list\n"
		"       edrctl jail add <pid> [etc,proc,root]\n"
		"       edrctl jail del <pid>\n"
		"       edrctl jail list\n"
		"       edrctl stats\n");
}

/* —— Maps ————————————————————————————————————————————————— */

static int open_map(const char *name)
{
	char path[PATH_MAX];
	int fd;
	int n;

	n = snprintf(path, sizeof(path), "%s/%s", EDR_PIN_DIR, name);
	if (n < 0 || (size_t)n >= sizeof(path))
		return -1;
	fd = bpf_obj_get(path);
	if (fd < 0)
		fprintf(stderr, "edrctl: %s: %s (has edrd been started?)\n", path,
			strerror(errno));
	return fd;
}

static unsigned int count_entries(const char *name, size_t key_size)
{
	unsigned char key[sizeof(struct exec_key)];
	unsigned char next[sizeof(struct exec_key)];
	unsigned int count = 0;
	void *prev = NULL;
	int fd;

	if (key_size > sizeof(key))
		return 0;
	fd = open_map(name);
	if (fd < 0)
		return 0;
	while (bpf_map_get_next_key(fd, prev, next) == 0) {
		memcpy(key, next, key_size);
		prev = key;
		count++;
	}
	close(fd);
	return count;
}

/* —— status ——————————————————————————————————————————————— */

static int compare_names(const void *a, const void *b)
{
	return strcmp(a, b);
}

static void print_hooks(void)
{
	char names[MAX_HOOKS][NAME_MAX + 1];
	struct dirent *de;
	size_t count = 0;
	size_t i;
	DIR *dir;

	dir = opendir(EDR_LINK_DIR);
	if (!dir) {
		printf("hooks:  none (%s: %s)\n", EDR_LINK_DIR, strerror(errno));
		return;
	}
	while ((de = readdir(dir)) != NULL && count < MAX_HOOKS) {
		if (de->d_name[0] == '.')
			continue;
		snprintf(names[count], sizeof(names[count]), "%s", de->d_name);
		count++;
	}
	closedir(dir);

	qsort(names, count, sizeof(names[0]), compare_names);
	printf("hooks:  %zu active\n", count);
	for (i = 0; i < count; i++)
		printf("        %s\n", names[i]);
}

static int cmd_status(void)
{
	struct daemon_state st;
	uint32_t zero = 0;
	uint64_t lost = 0;
	int64_t age;
	int64_t up;
	int fd;

	memset(&st, 0, sizeof(st));
	fd = open_map(EDR_DAEMON_MAP);
	if (fd < 0)
		return 1;
	if (bpf_map_lookup_elem(fd, &zero, &st) < 0) {
		fprintf(stderr, "edrctl: read %s: %s\n", EDR_DAEMON_MAP, strerror(errno));
		close(fd);
		return 1;
	}
	close(fd);

	age = (int64_t)time(NULL) - (int64_t)st.heartbeat;
	up = (int64_t)time(NULL) - (int64_t)st.start_time;
	if (st.pid == 0)
		printf("edrd:   stopped (hooks stay attached)\n");
	else if (age > HEARTBEAT_STALE_SEC)
		printf("edrd:   not responding (pid %u, last heartbeat %llds ago)\n",
		       st.pid, (long long)age);
	else
		printf("edrd:   running (pid %u, up %lldh%02lldm%02llds)\n", st.pid,
		       (long long)(up / 3600), (long long)(up / 60 % 60),
		       (long long)(up % 60));

	fd = open_map(EDR_MAP_LOST);
	if (fd >= 0) {
		if (bpf_map_lookup_elem(fd, &zero, &lost) < 0)
			lost = 0;
		close(fd);
	}
	printf("events: %llu logged, %llu lost\n", (unsigned long long)st.events_logged,
	       (unsigned long long)lost);

	print_hooks();
	printf("rules:  %u exec, %u ip, %u jailed pid\n",
	       count_entries(EDR_MAP_EXEC_BLACKLIST, sizeof(struct exec_key)),
	       count_entries(EDR_MAP_IP_BLACKLIST, sizeof(uint32_t)),
	       count_entries(EDR_MAP_JAIL, sizeof(uint32_t)));
	return 0;
}

/* —— watch ———————————————————————————————————————————————— */

/*
 * Copy the value of "key" from a line written by edrd. Strings stay
 * JSON-escaped: a forged comm or path cannot inject terminal sequences.
 */
static int json_field(const char *line, const char *key, char *out, size_t size)
{
	char pattern[32];
	const char *p;
	size_t i = 0;
	int n;

	n = snprintf(pattern, sizeof(pattern), "\"%s\":", key);
	if (n < 0 || (size_t)n >= sizeof(pattern) || size == 0)
		return -1;
	p = strstr(line, pattern);
	if (!p)
		return -1;
	p += n;

	if (*p == '"') {
		for (p++; *p != '\0' && *p != '"' && i + 2 < size; p++) {
			if (*p == '\\' && p[1] != '\0')
				out[i++] = *p++;
			out[i++] = *p;
		}
	} else {
		for (; *p != '\0' && *p != ',' && *p != '}' && i + 1 < size; p++)
			out[i++] = *p;
	}
	out[i] = '\0';
	return 0;
}

/* 2026-11-07T19:15:02.123456+0100 -> 2026-11-07 19:15:02 */
static void print_line(const char *line, int all)
{
	char time_s[FIELD_MAX_LEN] = "?";
	char hook[FIELD_MAX_LEN] = "?";
	char action[FIELD_MAX_LEN] = "?";
	char pid[FIELD_MAX_LEN] = "?";
	char uid[FIELD_MAX_LEN] = "?";
	char comm[FIELD_MAX_LEN] = "?";
	char detail[FIELD_MAX_LEN] = "";

	json_field(line, "action", action, sizeof(action));
	if (!all && strcmp(action, "allow") == 0)
		return;

	json_field(line, "time", time_s, sizeof(time_s));
	if (strlen(time_s) >= 19) {
		time_s[10] = ' ';
		time_s[19] = '\0';
	}
	json_field(line, "hook", hook, sizeof(hook));
	json_field(line, "pid", pid, sizeof(pid));

	if (strcmp(hook, "edrd") == 0) {
		json_field(line, "msg", detail, sizeof(detail));
		printf("%s  %-6s  %-20s  pid=%s  %s\n", time_s, "info", hook, pid, detail);
		fflush(stdout);
		return;
	}

	json_field(line, "uid", uid, sizeof(uid));
	json_field(line, "comm", comm, sizeof(comm));
	json_field(line, "path", detail, sizeof(detail));
	printf("%s  %-6s  %-20s  pid=%s uid=%s comm=%s  %s\n", time_s,
	       strcmp(action, "signal") == 0 ? "ALERT" :
	       strcmp(action, "block") == 0 ? "BLOCK" : action,
	       hook, pid, uid, comm, detail);
	fflush(stdout);
}

static void wait_a_bit(void)
{
	struct timespec ts = { .tv_sec = 0, .tv_nsec = WATCH_POLL_NS };

	nanosleep(&ts, NULL);
}

/* Follow the log like tail -F: survives the rotation done by edrd */
static int cmd_watch(int all)
{
	char line[LINE_MAX_LEN];
	struct stat now;
	struct stat st;
	FILE *f;
	long pos;

	f = fopen(EDR_LOG_PATH, "r");
	if (!f || fstat(fileno(f), &st) < 0 || fseek(f, 0, SEEK_END) < 0) {
		fprintf(stderr, "edrctl: %s: %s\n", EDR_LOG_PATH, strerror(errno));
		if (f)
			fclose(f);
		return 1;
	}
	fprintf(stderr, "watching %s (Ctrl-C to stop)\n", EDR_LOG_PATH);

	for (;;) {
		pos = ftell(f);
		if (fgets(line, sizeof(line), f) != NULL) {
			/* Half-written line: read it again once complete */
			if (strchr(line, '\n') == NULL && strlen(line) < sizeof(line) - 1) {
				clearerr(f);
				fseek(f, pos, SEEK_SET);
				wait_a_bit();
				continue;
			}
			print_line(line, all);
			continue;
		}

		clearerr(f);
		if (stat(EDR_LOG_PATH, &now) == 0 &&
		    (now.st_ino != st.st_ino || now.st_size < pos)) {
			FILE *next = fopen(EDR_LOG_PATH, "r");

			if (next && fstat(fileno(next), &st) == 0) {
				fclose(f);
				f = next;
				continue;
			}
			if (next)
				fclose(next);
		}
		wait_a_bit();
	}
}

/* —— block ———————————————————————————————————————————————— */

static int parse_ip(const char *s, uint32_t *ip)
{
	struct in_addr addr;

	if (inet_pton(AF_INET, s, &addr) != 1)
		return -1;
	*ip = addr.s_addr;	/* network byte order, like the BPF side */
	return 0;
}

static int exec_key_of(const char *path, struct exec_key *key)
{
	struct stat st;

	if (stat(path, &st) < 0)
		return -errno;
	if (!S_ISREG(st.st_mode))
		return -EINVAL;
	memset(key, 0, sizeof(*key));
	key->inode = st.st_ino;
	/* The kernel s_dev is (major << 20) | minor, not the glibc dev_t */
	key->dev = (major(st.st_dev) << 20) | minor(st.st_dev);
	return 0;
}

static int block_add(const char *arg)
{
	char real[PATH_MAX];
	struct exec_rule rule;
	struct exec_key key;
	uint32_t ip;
	uint32_t one = 1;
	int ret = 1;
	int err;
	int fd;

	if (parse_ip(arg, &ip) == 0) {
		fd = open_map(EDR_MAP_IP_BLACKLIST);
		if (fd < 0)
			return 1;
		if (bpf_map_update_elem(fd, &ip, &one, BPF_ANY) < 0)
			fprintf(stderr, "edrctl: add %s: %s\n", arg, strerror(errno));
		else {
			printf("blocked: connections to %s\n", arg);
			ret = 0;
		}
		close(fd);
		return ret;
	}

	if (realpath(arg, real) == NULL) {
		fprintf(stderr, "edrctl: %s: %s\n", arg, strerror(errno));
		return 1;
	}
	err = exec_key_of(real, &key);
	if (err) {
		fprintf(stderr, "edrctl: %s: %s\n", real,
			err == -EINVAL ? "not a regular file" : strerror(-err));
		return 1;
	}
	memset(&rule, 0, sizeof(rule));
	if ((size_t)snprintf(rule.path, sizeof(rule.path), "%s", real) >= sizeof(rule.path)) {
		fprintf(stderr, "edrctl: %s: path too long\n", real);
		return 1;
	}

	fd = open_map(EDR_MAP_EXEC_BLACKLIST);
	if (fd < 0)
		return 1;
	if (bpf_map_update_elem(fd, &key, &rule, BPF_ANY) < 0)
		fprintf(stderr, "edrctl: add %s: %s\n", real, strerror(errno));
	else {
		printf("blocked: execution of %s\n", real);
		ret = 0;
	}
	close(fd);
	return ret;
}

/* Find a rule by its recorded path: the file may be gone already */
static int find_exec_rule(int fd, const char *path, struct exec_key *found)
{
	struct exec_rule rule;
	struct exec_key key;
	struct exec_key next;
	void *prev = NULL;

	while (bpf_map_get_next_key(fd, prev, &next) == 0) {
		key = next;
		prev = &key;
		if (bpf_map_lookup_elem(fd, &key, &rule) == 0 &&
		    strncmp(rule.path, path, sizeof(rule.path)) == 0) {
			*found = key;
			return 0;
		}
	}
	return -1;
}

static int block_del(const char *arg)
{
	char real[PATH_MAX];
	struct exec_key key;
	uint32_t ip;
	int ret = 1;
	int fd;

	if (parse_ip(arg, &ip) == 0) {
		fd = open_map(EDR_MAP_IP_BLACKLIST);
		if (fd < 0)
			return 1;
		if (bpf_map_delete_elem(fd, &ip) < 0)
			fprintf(stderr, "edrctl: %s: no such rule\n", arg);
		else {
			printf("unblocked: %s\n", arg);
			ret = 0;
		}
		close(fd);
		return ret;
	}

	fd = open_map(EDR_MAP_EXEC_BLACKLIST);
	if (fd < 0)
		return 1;
	if (realpath(arg, real) == NULL)
		snprintf(real, sizeof(real), "%s", arg);
	if ((exec_key_of(real, &key) == 0 && bpf_map_delete_elem(fd, &key) == 0) ||
	    (find_exec_rule(fd, real, &key) == 0 && bpf_map_delete_elem(fd, &key) == 0)) {
		printf("unblocked: %s\n", real);
		ret = 0;
	} else {
		fprintf(stderr, "edrctl: %s: no such rule\n", arg);
	}
	close(fd);
	return ret;
}

static int block_list(void)
{
	char addr[INET_ADDRSTRLEN];
	struct exec_rule rule;
	struct exec_key key;
	struct exec_key next_key;
	uint32_t ip;
	uint32_t next_ip;
	void *prev = NULL;
	int fd;

	fd = open_map(EDR_MAP_EXEC_BLACKLIST);
	if (fd < 0)
		return 1;
	while (bpf_map_get_next_key(fd, prev, &next_key) == 0) {
		key = next_key;
		prev = &key;
		if (bpf_map_lookup_elem(fd, &key, &rule) == 0)
			printf("exec  %.*s\n", (int)sizeof(rule.path), rule.path);
	}
	close(fd);

	fd = open_map(EDR_MAP_IP_BLACKLIST);
	if (fd < 0)
		return 1;
	prev = NULL;
	while (bpf_map_get_next_key(fd, prev, &next_ip) == 0) {
		ip = next_ip;
		prev = &ip;
		if (inet_ntop(AF_INET, &ip, addr, sizeof(addr)) != NULL)
			printf("ip    %s\n", addr);
	}
	close(fd);
	return 0;
}

/* —— jail ————————————————————————————————————————————————— */

static int parse_pid(const char *s, uint32_t *pid)
{
	char *end;
	long v;

	errno = 0;
	v = strtol(s, &end, 10);
	if (errno != 0 || *end != '\0' || v <= 0 || v > INT_MAX)
		return -1;
	*pid = (uint32_t)v;
	return 0;
}

static int parse_jail_flags(const char *s, uint32_t *flags)
{
	char buf[64];
	char *save = NULL;
	char *tok;

	if ((size_t)snprintf(buf, sizeof(buf), "%s", s) >= sizeof(buf))
		return -1;
	*flags = 0;
	for (tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
		if (strcmp(tok, "etc") == 0)
			*flags |= JAIL_BLOCK_ETC;
		else if (strcmp(tok, "proc") == 0)
			*flags |= JAIL_BLOCK_PROC;
		else if (strcmp(tok, "root") == 0)
			*flags |= JAIL_BLOCK_ROOT;
		else
			return -1;
	}
	return *flags ? 0 : -1;
}

static void flags_str(uint32_t flags, char *out, size_t size)
{
	snprintf(out, size, "%s%s%s",
		 flags & JAIL_BLOCK_ETC ? "/etc " : "",
		 flags & JAIL_BLOCK_PROC ? "/proc " : "",
		 flags & JAIL_BLOCK_ROOT ? "/root " : "");
}

static int process_alive(uint32_t pid)
{
	return kill((pid_t)pid, 0) == 0 || errno == EPERM;
}

static int jail_add(const char *pid_s, const char *flags_s)
{
	struct jail_policy policy = { .flags = JAIL_BLOCK_ETC | JAIL_BLOCK_PROC | JAIL_BLOCK_ROOT };
	char what[32];
	uint32_t pid;
	int ret = 1;
	int fd;

	if (parse_pid(pid_s, &pid) < 0) {
		fprintf(stderr, "edrctl: %s: invalid pid\n", pid_s);
		return 1;
	}
	if (flags_s && parse_jail_flags(flags_s, &policy.flags) < 0) {
		fprintf(stderr, "edrctl: %s: expected a list of etc, proc, root\n", flags_s);
		return 1;
	}
	if (!process_alive(pid)) {
		fprintf(stderr, "edrctl: no process %u\n", pid);
		return 1;
	}

	fd = open_map(EDR_MAP_JAIL);
	if (fd < 0)
		return 1;
	if (bpf_map_update_elem(fd, &pid, &policy, BPF_ANY) < 0)
		fprintf(stderr, "edrctl: jail %u: %s\n", pid, strerror(errno));
	else {
		flags_str(policy.flags, what, sizeof(what));
		printf("jailed: pid %u can no longer open %s\n", pid, what);
		ret = 0;
	}
	close(fd);
	return ret;
}

static int jail_del(const char *pid_s)
{
	uint32_t pid;
	int ret = 1;
	int fd;

	if (parse_pid(pid_s, &pid) < 0) {
		fprintf(stderr, "edrctl: %s: invalid pid\n", pid_s);
		return 1;
	}
	fd = open_map(EDR_MAP_JAIL);
	if (fd < 0)
		return 1;
	if (bpf_map_delete_elem(fd, &pid) < 0)
		fprintf(stderr, "edrctl: pid %u is not jailed\n", pid);
	else {
		printf("released: pid %u\n", pid);
		ret = 0;
	}
	close(fd);
	return ret;
}

static int jail_list(void)
{
	struct jail_policy policy;
	char what[32];
	uint32_t pid;
	uint32_t next;
	void *prev = NULL;
	int fd;

	fd = open_map(EDR_MAP_JAIL);
	if (fd < 0)
		return 1;
	while (bpf_map_get_next_key(fd, prev, &next) == 0) {
		pid = next;
		prev = &pid;
		if (bpf_map_lookup_elem(fd, &pid, &policy) < 0)
			continue;
		flags_str(policy.flags, what, sizeof(what));
		printf("pid %-7u %s%s\n", pid, what, process_alive(pid) ? "" : "(exited)");
	}
	close(fd);
	return 0;
}

/* —— stats ———————————————————————————————————————————————— */

struct stat_row {
	uint32_t pid;
	struct pid_stats s;
};

static int compare_rows(const void *a, const void *b)
{
	const struct stat_row *x = a;
	const struct stat_row *y = b;
	uint64_t tx = x->s.alerts + x->s.blocks;
	uint64_t ty = y->s.alerts + y->s.blocks;

	return tx < ty ? 1 : tx > ty ? -1 : 0;
}

static void read_comm(uint32_t pid, char *out, size_t size)
{
	char path[64];
	FILE *f;

	snprintf(out, size, "-");
	snprintf(path, sizeof(path), "/proc/%u/comm", pid);
	f = fopen(path, "r");
	if (!f)
		return;
	if (fgets(out, (int)size, f) != NULL)
		out[strcspn(out, "\n")] = '\0';
	fclose(f);
}

static int cmd_stats(void)
{
	static struct stat_row rows[MAX_STATS];
	char comm[TASK_COMM_LEN + 1];
	uint32_t pid;
	uint32_t next;
	void *prev = NULL;
	size_t count = 0;
	size_t i;
	int fd;

	fd = open_map(EDR_MAP_PID_STATS);
	if (fd < 0)
		return 1;
	while (count < MAX_STATS && bpf_map_get_next_key(fd, prev, &next) == 0) {
		pid = next;
		prev = &pid;
		if (bpf_map_lookup_elem(fd, &pid, &rows[count].s) == 0) {
			rows[count].pid = pid;
			count++;
		}
	}
	close(fd);

	qsort(rows, count, sizeof(rows[0]), compare_rows);
	printf("%-8s %-16s %8s %8s\n", "PID", "COMM", "ALERTS", "BLOCKS");
	for (i = 0; i < count; i++) {
		read_comm(rows[i].pid, comm, sizeof(comm));
		printf("%-8u %-16s %8llu %8llu\n", rows[i].pid, comm,
		       (unsigned long long)rows[i].s.alerts,
		       (unsigned long long)rows[i].s.blocks);
	}
	return 0;
}

/* —— main ————————————————————————————————————————————————— */

int main(int argc, char **argv)
{
	const char *cmd = argc > 1 ? argv[1] : "";
	const char *sub = argc > 2 ? argv[2] : "";

	if (geteuid() != 0) {
		fprintf(stderr, "edrctl: must run as root\n");
		return 1;
	}

	if (strcmp(cmd, "status") == 0 && argc == 2)
		return cmd_status();
	if (strcmp(cmd, "watch") == 0 && argc == 2)
		return cmd_watch(0);
	if (strcmp(cmd, "watch") == 0 && argc == 3 && strcmp(sub, "-a") == 0)
		return cmd_watch(1);
	if (strcmp(cmd, "stats") == 0 && argc == 2)
		return cmd_stats();

	if (strcmp(cmd, "block") == 0) {
		if (strcmp(sub, "add") == 0 && argc == 4)
			return block_add(argv[3]);
		if (strcmp(sub, "del") == 0 && argc == 4)
			return block_del(argv[3]);
		if (strcmp(sub, "list") == 0 && argc == 3)
			return block_list();
	}
	if (strcmp(cmd, "jail") == 0) {
		if (strcmp(sub, "add") == 0 && (argc == 4 || argc == 5))
			return jail_add(argv[3], argc == 5 ? argv[4] : NULL);
		if (strcmp(sub, "del") == 0 && argc == 4)
			return jail_del(argv[3]);
		if (strcmp(sub, "list") == 0 && argc == 3)
			return jail_list();
	}

	usage();
	return 2;
}
