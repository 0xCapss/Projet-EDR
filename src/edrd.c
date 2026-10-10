#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "edr.skel.h"
#include "edr.h"

/* Cleared by the signal handler to leave the main loop */
static volatile sig_atomic_t running = 1;

static void handle_signal(int sig)
{
	(void)sig;
	running = 0;
}

/* Called by libbpf once for each event read from the ring buffer */
static int handle_event(void *ctx, void *data, size_t sz)
{
	struct event *e = data;

	(void)ctx;
	(void)sz;

	if (e->type == EVENT_EXEC) {
		printf("[EXEC] pid=%u ppid=%u uid=%u comm=%s path=%s action=%u\n",
		       e->pid, e->ppid, e->uid, e->comm, e->path, e->action);
	} else if (e->type == EVENT_FILE_OPEN) {
		printf("[FILE_OPEN] pid=%u ppid=%u uid=%u comm=%s path=%s action=%u\n",
		       e->pid, e->ppid, e->uid, e->comm, e->path, e->action);
	}

	return 0;
}

int main(void)
{
	struct sigaction sa = {0};
	struct edr *skel = NULL;
	struct ring_buffer *rb = NULL;
	int err;
	int ret = 1;

	sa.sa_handler = handle_signal;
	if (sigaction(SIGINT, &sa, NULL) == -1 ||
	    sigaction(SIGTERM, &sa, NULL) == -1) {
		perror("sigaction");
		return 1;
	}

	skel = edr__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load the BPF skeleton\n");
		goto cleanup;
	}
	
    /* Attach every hook: from here on the kernel calls our programs */
	err = edr__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach the BPF programs: %d\n", err);
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event,
			      NULL, NULL);
	if (!rb) {
		fprintf(stderr, "Failed to create the ring buffer\n");
		goto cleanup;
	}

	printf("edrd started (pid=%d), Ctrl-C to stop\n", getpid());

	while (running) {
		err = ring_buffer__poll(rb, 100 /* ms */);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "ring_buffer__poll failed: %d\n", err);
			break;
		}
	}

	ret = 0;

cleanup:
	ring_buffer__free(rb);
	edr__destroy(skel);
	return ret;
}
