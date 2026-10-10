#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "edr.h"
#include <linux/errno.h>

char LICENSE[] SEC("license") = "GPL";

/* —— Maps ———————————————————————————————— */

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);   /* 16 MiB */
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

static __always_inline void stats_inc(__u32 pid, __u32 action)
{
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

/* —— Hook bprm_file_open ———————————————————————— */

SEC("lsm/file_open")
int BPF_PROG(file_open_hook, struct file *file)
{
	static const char shadow_path[] = "/etc/shadow";
	struct task_struct *t;
	struct jail_policy *p;
	struct event *e;
	long n;
	int ret = 0;
	u32 pid = bpf_get_current_pid_tgid() >> 32;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__builtin_memset(e, 0, sizeof(*e));
	e->type = EVENT_FILE_OPEN;
	e->pid = pid;
	e->uid = (u32)bpf_get_current_uid_gid();
	e->timestamp = bpf_ktime_get_ns();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	t = (struct task_struct *)bpf_get_current_task_btf();
	e->ppid = BPF_CORE_READ(t, real_parent, tgid);

	n = bpf_d_path((struct path *)&file->f_path, e->path, sizeof(e->path));
	if (n < 0) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}

	/* Confined process: block the forbidden prefixes */
	p = bpf_map_lookup_elem(&jail_map, &pid);
	if (p) {
		if ((p->flags & JAIL_BLOCK_PROC) && bytes_equal(e->path, "/proc/", 6)) {
			ret = -EPERM;
			e->action = ACTION_BLOCK;
		} else if ((p->flags & JAIL_BLOCK_ETC) && bytes_equal(e->path, "/etc/", 5)) {
			ret = -EPERM;
			e->action = ACTION_BLOCK;
		} else if ((p->flags & JAIL_BLOCK_ROOT) && bytes_equal(e->path, "/root/", 6)) {
			ret = -EPERM;
			e->action = ACTION_BLOCK;
		}
	}

	/* Unprivileged read of /etc/shadow: alert only (len includes the NUL) */
	if (e->action == 0 && e->uid != 0 &&
	    bytes_equal(e->path, shadow_path, sizeof(shadow_path)))
		e->action = ACTION_SIGNAL;

	/* Nothing to report: do not flood the ring buffer */
	if (e->action == 0) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}

	stats_inc(pid, e->action);
	bpf_ringbuf_submit(e, 0);
	return ret;
}

/* —— Hook bprm_check_security ———————————————————————— */

SEC("lsm/bprm_check_security")
int BPF_PROG(exec_hook, struct linux_binprm *bprm)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!e)
		return 0;

	__builtin_memset(e, 0, sizeof(*e));
	e->type = EVENT_EXEC;
	e->pid = pid;
	e->uid = (u32) bpf_get_current_uid_gid();
	e->timestamp = bpf_ktime_get_ns();
	e->action = ACTION_ALLOW;	/* default, may become ACTION_BLOCK */
	bpf_probe_read_kernel_str(e->path, sizeof(e->path), bprm->filename);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	struct task_struct *t = (struct task_struct *) bpf_get_current_task_btf();
	e->ppid = BPF_CORE_READ(t,real_parent, tgid);

	struct exec_key key = {};
	key.inode = BPF_CORE_READ(bprm->file, f_inode, i_ino);
	key.dev = BPF_CORE_READ(bprm->file, f_inode, i_sb, s_dev);

	int ret = 0;
	__u32 *blacklisted = bpf_map_lookup_elem(&exec_blacklist_map, &key);
	if (blacklisted) {
		e->action = ACTION_BLOCK;
		ret = -EPERM;
	}
	stats_inc(pid, e->action);
	bpf_ringbuf_submit(e, 0);
	return ret;
}

