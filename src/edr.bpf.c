#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "edr.h"
#include <linux/errno.h>
#include <bpf/bpf_endian.h>

#define SIGHUP        1
#define SIGINT        2
#define SIGQUIT       3
#define SIGKILL       9
#define SIGTERM       15
#define SIGSTOP       19
#define AF_INET       2
#define ATTR_MODE     (1 << 0)
#define S_ISUID       0004000
#define S_ISGID       0002000
#define PTRACE_MODE_ATTACH 0x02

char LICENSE[] SEC("license") = "GPL";

/* —— Maps ———————————————————————————————— */

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);	/* 16 MiB */
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key,   __u32);
	__type(value, struct jail_policy);
} jail_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key,   struct exec_key);
	__type(value, __u32);
} exec_blacklist_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key,   __u32);
	__type(value, struct pid_stats);
} pid_stats_map SEC(".maps");

/* Blocked destination IPv4 addresses, in network byte order */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key,   __u32);
	__type(value, __u32);
} ip_blacklist_map SEC(".maps");

/* Events dropped because the ring buffer was full (slot 0) */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key,   __u32);
	__type(value, __u64);
} lost_events SEC(".maps");

/* PID of the daemon to protect (slot 0), written by edrd at startup; 0 = none */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key,   __u32);
	__type(value, __u32);
} protected_pid_map SEC(".maps");

static __always_inline void lost_inc(void)
{
	__u32 zero = 0;
	__u64 *lost = bpf_map_lookup_elem(&lost_events, &zero);

	if (lost)
		__sync_fetch_and_add(lost, 1);
}

static __always_inline void stats_inc(__u32 pid, __u32 action)
{
	/* Only alerts and blocks are counted: do not fill the map with allows */
	if (action != ACTION_SIGNAL && action != ACTION_BLOCK)
		return;
	struct pid_stats *stats = bpf_map_lookup_elem(&pid_stats_map, &pid);
	if (!stats) {
		struct pid_stats new_stats = {};
		bpf_map_update_elem(&pid_stats_map, &pid, &new_stats, BPF_NOEXIST);
		stats = bpf_map_lookup_elem(&pid_stats_map, &pid);
		if (!stats) {
			return;
		}
	}
	if (action == ACTION_SIGNAL) {
		__sync_fetch_and_add(&stats->alerts, 1);
	} else if (action == ACTION_BLOCK) {
		__sync_fetch_and_add(&stats->blocks, 1);
	}
}

/* Compare len bytes of a and b (len includes the terminating NUL) */
static __always_inline int bytes_equal(const char *a, const char *b, int len)
{
	int i;
#pragma unroll
	for (i = 0; i < len; i++) {
		if (a[i] != b[i])
			return 0;
	}
	return 1;
}

/*
 * The decision (ret) is always taken before the ring buffer is used: a full
 * buffer loses the log line, never the block.
 */

/* —— Hook file_open ———————————————————————————————— */

SEC("lsm/file_open")
int BPF_PROG(file_open_hook, struct file *file)
{
	static const char shadow_path[] = "/etc/shadow";
	char path[MAX_PATH_LEN];
	struct task_struct *t;
	struct jail_policy *p;
	struct event *e;
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 uid = (u32)bpf_get_current_uid_gid();
	u32 action = 0;
	int ret = 0;
	long n;

	n = bpf_d_path((struct path *)&file->f_path, path, sizeof(path));
	if (n < 0)
		return 0;

	/* Confined process: block the forbidden prefixes */
	p = bpf_map_lookup_elem(&jail_map, &pid);
	if (p) {
		if ((p->flags & JAIL_BLOCK_PROC) && bytes_equal(path, "/proc/", 6)) {
			ret = -EPERM;
			action = ACTION_BLOCK;
		} else if ((p->flags & JAIL_BLOCK_ETC) && bytes_equal(path, "/etc/", 5)) {
			ret = -EPERM;
			action = ACTION_BLOCK;
		} else if ((p->flags & JAIL_BLOCK_ROOT) && bytes_equal(path, "/root/", 6)) {
			ret = -EPERM;
			action = ACTION_BLOCK;
		}
	}

	/* Unprivileged read of /etc/shadow: alert only (len includes the NUL) */
	if (action == 0 && uid != 0 &&
	    bytes_equal(path, shadow_path, sizeof(shadow_path)))
		action = ACTION_SIGNAL;

	/* Nothing to report: do not touch the ring buffer */
	if (action == 0)
		return 0;

	stats_inc(pid, action);

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		lost_inc();
		return ret;
	}

	__builtin_memset(e, 0, sizeof(*e));
	e->type = EVENT_FILE_OPEN;
	e->pid = pid;
	e->uid = uid;
	e->action = action;
	e->timestamp = bpf_ktime_get_ns();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_probe_read_kernel_str(e->path, sizeof(e->path), path);
	t = (struct task_struct *)bpf_get_current_task_btf();
	e->ppid = BPF_CORE_READ(t, real_parent, tgid);

	bpf_ringbuf_submit(e, 0);
	return ret;
}

/* —— Hook bprm_check_security ———————————————————————— */

SEC("lsm/bprm_check_security")
int BPF_PROG(exec_hook, struct linux_binprm *bprm)
{
	struct exec_key key = {};
	struct task_struct *t;
	struct event *e;
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 action = ACTION_ALLOW;
	int ret = 0;

	key.inode = BPF_CORE_READ(bprm->file, f_inode, i_ino);
	key.dev = BPF_CORE_READ(bprm->file, f_inode, i_sb, s_dev);

	if (bpf_map_lookup_elem(&exec_blacklist_map, &key)) {
		action = ACTION_BLOCK;
		ret = -EPERM;
	}
	stats_inc(pid, action);

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		lost_inc();
		return ret;
	}

	__builtin_memset(e, 0, sizeof(*e));
	e->type = EVENT_EXEC;
	e->pid = pid;
	e->uid = (u32)bpf_get_current_uid_gid();
	e->action = action;
	e->timestamp = bpf_ktime_get_ns();
	bpf_probe_read_kernel_str(e->path, sizeof(e->path), bprm->filename);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	t = (struct task_struct *)bpf_get_current_task_btf();
	e->ppid = BPF_CORE_READ(t, real_parent, tgid);

	bpf_ringbuf_submit(e, 0);
	return ret;
}

/* —— Hook task_kill ———————————————————————— */

static __always_inline int is_signal_allowed(int sig)
{
	if (sig == SIGKILL || sig == SIGSTOP || sig == SIGINT || sig == SIGTERM ||
	    sig == SIGQUIT)
		return 0;
	return 1;
}

SEC("lsm/task_kill")
int BPF_PROG(task_kill_hook, struct task_struct *p, struct kernel_siginfo *info,
	     int sig, const struct cred *cred)
{
	__u32 zero = 0;
	__u32 *daemon = bpf_map_lookup_elem(&protected_pid_map, &zero);
	struct task_struct *t;
	struct event *e;
	u32 target = BPF_CORE_READ(p, tgid);
	u32 sender = bpf_get_current_pid_tgid() >> 32;

	if (!daemon || *daemon == 0)
		return 0;

	if (target != *daemon)
		return 0;

	if (sender == 1 || sender == *daemon)
		return 0;

	if (is_signal_allowed(sig))
		return 0;

	stats_inc(sender, ACTION_BLOCK);

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		lost_inc();
		return -EPERM;
	}

	__builtin_memset(e, 0, sizeof(*e));
	e->type = EVENT_KILL;
	e->pid = sender;
	e->uid = (u32)bpf_get_current_uid_gid();
	e->action = ACTION_BLOCK;
	e->timestamp = bpf_ktime_get_ns();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_probe_read_kernel_str(e->path, sizeof(e->path), p->comm);
	t = (struct task_struct *)bpf_get_current_task_btf();
	e->ppid = BPF_CORE_READ(t, real_parent, tgid);

	bpf_ringbuf_submit(e, 0);
	return -EPERM;
}

/* —— Hook socket_connect ———————————————————————— */

SEC("lsm/socket_connect")
int BPF_PROG(socket_connect_hook, struct socket *sock, struct sockaddr *address,
	     int addrlen)
{
	static const char format[] = "%pI4:%u";
	struct sockaddr_in sin = {};
	struct task_struct *t;
	struct event *e;
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 *blocked;
	u64 args[2];

	if (addrlen < (int)sizeof(struct sockaddr_in))
		return 0;

	bpf_probe_read_kernel(&sin, sizeof(sin), address);
	if (sin.sin_family != AF_INET)
		return 0;

	/* Only blacklisted destinations reach the ring buffer */
	blocked = bpf_map_lookup_elem(&ip_blacklist_map, &sin.sin_addr.s_addr);
	if (!blocked)
		return 0;

	stats_inc(pid, ACTION_BLOCK);

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		lost_inc();
		return -EPERM;
	}

	__builtin_memset(e, 0, sizeof(*e));
	e->type = EVENT_NET_CONNECT;
	e->action = ACTION_BLOCK;
	e->pid = pid;
	e->uid = (u32)bpf_get_current_uid_gid();
	e->timestamp = bpf_ktime_get_ns();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	t = (struct task_struct *)bpf_get_current_task_btf();
	e->ppid = BPF_CORE_READ(t, real_parent, tgid);

	/* "ip:port" in path: %pI4 reads the address through a pointer */
	args[0] = (u64)&sin.sin_addr.s_addr;
	args[1] = bpf_ntohs(sin.sin_port);
	bpf_snprintf(e->path, sizeof(e->path), format, args, sizeof(args));

	bpf_ringbuf_submit(e, 0);
	return -EPERM;
}

/* —— Hook inode_setattr ———————————————————————— */

SEC("lsm/inode_setattr")
int BPF_PROG(setattr_hook, struct mnt_idmap *idmap, struct dentry *dentry,
	     struct iattr *attr)
{
	struct task_struct *t;
	struct event *e;
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	unsigned int valid = BPF_CORE_READ(attr, ia_valid);
	unsigned int mode = BPF_CORE_READ(attr, ia_mode);

	/* Most calls (touch, truncate, chown...) stop here */
	if (!(valid & ATTR_MODE))
		return 0;
	if (!(mode & (S_ISUID | S_ISGID)))
		return 0;

	/* Setuid/setgid bit being set: alert only, never block */
	stats_inc(pid, ACTION_SIGNAL);

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		lost_inc();
		return 0;
	}

	__builtin_memset(e, 0, sizeof(*e));
	e->type = EVENT_FILE_SETATTR;
	e->pid = pid;
	e->uid = (u32)bpf_get_current_uid_gid();
	e->action = ACTION_SIGNAL;
	e->timestamp = bpf_ktime_get_ns();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	t = (struct task_struct *)bpf_get_current_task_btf();
	e->ppid = BPF_CORE_READ(t, real_parent, tgid);

	bpf_probe_read_kernel_str(e->path, sizeof(e->path),
				  BPF_CORE_READ(dentry, d_name.name));

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* —— Hook ptrace_access_check ———————————————————————— */

SEC("lsm/ptrace_access_check")
int BPF_PROG(ptrace_access_check_hook, struct task_struct *child,
	     unsigned int mode)
{
	__u32 zero = 0;
	__u32 *daemon = bpf_map_lookup_elem(&protected_pid_map, &zero);
	struct task_struct *t;
	struct event *e;
	u32 target = BPF_CORE_READ(child, tgid);
	u32 caller = bpf_get_current_pid_tgid() >> 32;

	if (!daemon || *daemon == 0)
		return 0;
	if (target != *daemon)
		return 0;

	/* Reads (ps, /proc/<pid>/exe) stay allowed: only attaching is refused */
	if (!(mode & PTRACE_MODE_ATTACH))
		return 0;
	if (caller == *daemon)
		return 0;

	stats_inc(caller, ACTION_BLOCK);

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		lost_inc();
		return -EPERM;
	}

	__builtin_memset(e, 0, sizeof(*e));
	e->type = EVENT_PTRACE;
	e->action = ACTION_BLOCK;
	e->pid = caller;
	e->uid = (u32)bpf_get_current_uid_gid();
	e->timestamp = bpf_ktime_get_ns();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	t = (struct task_struct *)bpf_get_current_task_btf();
	e->ppid = BPF_CORE_READ(t, real_parent, tgid);
	bpf_probe_read_kernel_str(e->path, sizeof(e->path),
				  BPF_CORE_READ(child, comm));

	bpf_ringbuf_submit(e, 0);
	return -EPERM;
}
