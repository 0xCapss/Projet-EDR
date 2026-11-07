#pragma once
#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define MAX_PATH_LEN	256
#define TASK_COMM_LEN	16

/* Kind of event */
#define EVENT_EXEC		    1
#define EVENT_FILE_OPEN		2
#define EVENT_SETUID		3
#define EVENT_PTRACE		4
#define EVENT_KILL		    5
#define EVENT_NET_CONNECT	6
#define EVENT_MODULE		7
#define EVENT_MOUNT		    8
#define EVENT_UNMOUNT		9
#define EVENT_MMAP_EXEC		10
#define EVENT_PRCTL		    11
#define EVENT_FILE_CREATE	12
#define EVENT_FILE_UNLINK	13
#define EVENT_FILE_RENAME	14
#define EVENT_FILE_SETATTR	15

/* Jail flags */
#define JAIL_BLOCK_ETC		(1U << 0)	/* block /etc/  */
#define JAIL_BLOCK_PROC		(1U << 1)	/* block /proc/ */
#define JAIL_BLOCK_ROOT		(1U << 2)	/* block /root/ */

/* Actions */
#define ACTION_BLOCK		1
#define ACTION_ALLOW		2
#define ACTION_SIGNAL		3


struct event {
	__u64 timestamp;		/* ns since boot*/
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	__u32 type;			/* EVENT_* */
	__u32 action;			/* ACTION_* */
	__u32 reserved;			/* explicit padding, keep at 0 */
	char  comm[TASK_COMM_LEN];
	char  path[MAX_PATH_LEN];
};

struct jail_policy {
	__u32 flags;			/* ORed JAIL_BLOCK_* */
};

struct exec_key {
    __u64 inode;
    __u32 dev;			/* kernel encoding: (major << 20) | minor */
    __u32 pad;
};

/* Value of exec_blacklist_map: the path is only kept for edrctl block list */
struct exec_rule {
    char path[MAX_PATH_LEN];
};

struct pid_stats{
    __u64 alerts; /* events flagged ACTION_SIGNAL */
    __u64 blocks; /* events flagged ACTION_BLOCK */
};

/* —— Daemon (edrd) ——————————————————————————————————————————— */

#define EDR_PIN_DIR		"/sys/fs/bpf/edr"	/* maps pinned by name */
#define EDR_LINK_DIR		EDR_PIN_DIR "/links"	/* one pinned link per active hook */
#define EDR_DAEMON_MAP		"daemon_state"
#define EDR_LOG_PATH		"/var/log/edr.log"

/* Maps pinned by edrd (EDR_PIN_DIR/<name>), used by edrctl */
#define EDR_MAP_EXEC_BLACKLIST	"exec_blacklist_map"
#define EDR_MAP_IP_BLACKLIST	"ip_blacklist_map"
#define EDR_MAP_JAIL		"jail_map"
#define EDR_MAP_PID_STATS	"pid_stats_map"
#define EDR_MAP_LOST		"lost_events"

/* EDR_PIN_DIR/daemon_state: array of 1, created and written by edrd only */
struct daemon_state {
	__u32 pid;		/* 0 when edrd is not running */
	__u32 reserved;
	__u64 start_time;	/* seconds since the epoch */
	__u64 heartbeat;	/* seconds since the epoch, refreshed every few seconds */
	__u64 events_logged;
};
