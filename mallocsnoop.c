// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2023 Red Hat */
// Started from the libbpf-bootstrap examples/c/bootstrap.c
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "mallocsnoop.h"
#include "mallocsnoop.skel.h"

/*
 * mallocsnoop output example, using -X to 
   exclude the 3445 pid_t that is the gnome-terminal where it is running, so the
   output from mallocsnoop causes allocations in the gnome-terminal instance it
   is running, causing more events, looping, add -X to avoid that.

   -m 8192 == minimum alloc size

  [root@five c]# ./mallocsnoop -m 8192 -X 3445 | head -30
  TIME     EVENT(ADDR) COMM             PID
  10:35:40 MALLOC(10485856)=0x55a34b6f6130 sssd_kcm         497707
  10:35:40 MALLOC(10485848)=0x55a34caf63e0 sssd_kcm         497707
  10:35:40 FREE  (0x55a34caf63e0) 10485848 bytes sssd_kcm         497707  (0ms)
  10:35:40 FREE  (0x55a34b6f6130) 10485856 bytes sssd_kcm         497707  (1ms)
  10:35:40 CALLOC(1, 8192)=0x556b35cb00c0 ping             980870
  10:35:40 MALLOC(131072)=0x556b35cb0140 ping             980870
  10:35:40 MALLOC(131072)=0x560e18fae030 systemd-resolve  1134
  10:35:40 CALLOC(1, 8192)=0x560e18f74300 systemd-resolve  1134
  10:35:40 FREE  (0x556b35cb0140) 131072 bytes ping             980870  (0ms)
  10:35:40 FREE  (0x556b35cb00c0)  8192 bytes ping             980870  (0ms)
  10:35:40 FREE  (0x560e18fae030) 131072 bytes systemd-resolve  1134    (0ms)
  10:35:40 FREE  (0x560e18f74300)  8192 bytes systemd-resolve  1134    (0ms)
  10:35:41 MALLOC(131072)=0x560e18fae030 systemd-resolve  1134
  10:35:41 MALLOC(131072)=0x560e18e2ce40 systemd-resolve  1134
  10:35:41 CALLOC(1, 8192)=0x560e18f74300 systemd-resolve  1134
  10:35:41 FREE  (0x560e18e2ce40) 131072 bytes systemd-resolve  1134    (0ms)
  10:35:41 FREE  (0x560e18f74300)  8192 bytes systemd-resolve  1134    (0ms)
  10:35:41 CALLOC(1, 8192)=0x560e18f74390 systemd-resolve  1134
  10:35:41 FREE  (0x560e18fae030) 131072 bytes systemd-resolve  1134    (15ms)
  10:35:41 FREE  (0x560e18f74390)  8192 bytes systemd-resolve  1134    (0ms)
  10:35:41 CALLOC(1, 8192)=0x556b35cb0140 ping             980870
  10:35:41 MALLOC(131072)=0x560e18fae030 systemd-resolve  1134
  10:35:41 MALLOC(131072)=0x556b35cb01c0 ping             980870
  10:35:41 CALLOC(1, 8192)=0x560e18f74460 systemd-resolve  1134
  10:35:41 FREE  (0x556b35cb01c0) 131072 bytes ping             980870  (0ms)
  10:35:41 FREE  (0x556b35cb0140)  8192 bytes ping             980870  (0ms)
  10:35:41 FREE  (0x560e18fae030) 131072 bytes systemd-resolve  1134    (0ms)
  10:35:41 FREE  (0x560e18f74460)  8192 bytes systemd-resolve  1134    (0ms)
  10:35:42 CALLOC(1, 8192)=0x556b35cb01c0 ping             980870
  [root@five c]#
*/

static struct env {
	bool verbose;
	pid_t target_pid;
	pid_t exclude_pid;
	long min_duration_ms;
	long min_size;
	long max_size;
} env;

const char *argp_program_version = "mallocsnoop 0.0";
const char *argp_program_bug_address = "<acme@kernel.org>";
const char argp_program_doc[] =
"BPF mallocsnoop demo application.\n"
"\n"
"It traces memory allocation and freeing and shows associated \n"
"information (allocation size and duration, PID, etc).\n"
"\n"
"USAGE: ./mallocsnoop [-d <min-duration-ms>] [-v]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "duration", 'd', "DURATION-MS", 0, "Minimum allocation duration (ms) to report" },
	{ "min_size", 'm', "MIN_SIZE", 0, "Minimum size of allocations to report" },
	{ "max_size", 'M', "MAX_SIZE", 0, "Maximum size of allocations to report" },
	{ "pid", 'p', "PID", 0, "pid to trace" },
	{ "exclude_pid", 'X', "PID", 0, "pid to filter" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'd':
		errno = 0;
		env.min_duration_ms = strtol(arg, NULL, 10);
		if (errno || env.min_duration_ms <= 0) {
			fprintf(stderr, "Invalid duration: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'm':
		errno = 0;
		env.min_size = strtol(arg, NULL, 10);
		if (errno || env.min_size <= 0) {
			fprintf(stderr, "Invalid minimum size: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'M':
		errno = 0;
		env.max_size = strtol(arg, NULL, 10);
		if (errno || env.max_size <= 0) {
			fprintf(stderr, "Invalid maximum size: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'p':
		errno = 0;
		env.target_pid = strtol(arg, NULL, 10);
		if (errno || env.target_pid <= 0) {
			fprintf(stderr, "Invalid pid: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'X':
		errno = 0;
		env.exclude_pid = strtol(arg, NULL, 10);
		if (errno || env.exclude_pid <= 0) {
			fprintf(stderr, "Invalid exclude pid: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	switch (e->event) {
	case EV_FREE:
		printf("%-8s %-6s(%p) %5ld bytes %-16s %-7d", ts, "FREE", e->addr, e->size, e->comm, e->pid);

		if (e->duration_ns)
			printf(" (%llums)", e->duration_ns / 1000000);

		printf("\n");
		break;
	case EV_MALLOC:
		printf("%-8s %-6s(%zd)=%p %-16s %-7d\n", ts, "MALLOC", e->size, e->addr, e->comm, e->pid);
		break;
	case EV_CALLOC:
		printf("%-8s %-6s(%zd, %zd)=%p %-16s %-7d\n", ts, "CALLOC", e->nmemb, e->size, e->addr, e->comm, e->pid);
		break;
	case EV_REALLOC:
		printf("%-8s %-6s(%p, %zd)=%p %-16s %-7d\n", ts, "REALLOC", e->realloc_addr, e->size, e->addr, e->comm, e->pid);
		break;
	default:
		printf("%-8s INVALID event %d\n", ts, e->event);
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct mallocsnoop_bpf *skel;
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = mallocsnoop_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

        /* Parameterize BPF code with minimum duration parameter amd our pid */
        skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;
        skel->rodata->min_size = env.min_size;
        skel->rodata->max_size = env.max_size;
        skel->rodata->target_pid = env.target_pid;
        skel->rodata->exclude_pid = env.exclude_pid;
	skel->rodata->my_pid = getpid();

	/* Load & verify BPF programs */
	err = mallocsnoop_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = mallocsnoop_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Process events */
	printf("%-8s %-5s %-16s %-7s\n", "TIME", "EVENT(ADDR)", "COMM", "PID");
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	/* Clean up */
	ring_buffer__free(rb);
	mallocsnoop_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
