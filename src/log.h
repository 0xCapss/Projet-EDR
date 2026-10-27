/*
 * log.h - /var/log/edr.log writer
 *
 * One JSON object per line: "time", "hook", "event", "action", "pid",
 * "ppid", "uid", "comm" and "path". Strings coming from the kernel are
 * attacker-controlled (comm, file names): they are escaped so that a
 * line can never be split or forged.
 */
#ifndef EDR_LOG_H
#define EDR_LOG_H

#include <stddef.h>
#include <stdint.h>

#include "edr.h"

#define LOG_MAX_SIZE	(10 * 1024 * 1024)	/* rotate above 10 MiB */
#define LOG_KEEP	5			/* edr.log.1 .. edr.log.5 */

/* Open (or reopen) the log file, mode 0600; 0 or a negative errno */
int log_open(const char *path);
void log_close(void);

/* Rotate the file if it grew above LOG_MAX_SIZE; 0 or a negative errno */
int log_rotate_if_needed(void);

/* Format one event into buf as a JSON line (with '\n'); length or -1 */
int log_format_event(const struct event *e, char *buf, size_t size);

/* Write one event; echo it to stdout too when echo is set */
int log_event(const struct event *e, int echo);

/* Write a message from edrd itself ("hook":"edrd") */
int log_daemon(const char *action, const char *msg, int echo);

#endif /* EDR_LOG_H */
