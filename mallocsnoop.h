/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2023 Red Hat */
#ifndef __MALLOCSNOOP_H
#define __MALLOCSNOOP_H

#define TASK_COMM_LEN 16

enum alloc_event {
	EV_MALLOC,
	EV_FREE,
	EV_CALLOC,
	EV_REALLOC,
};

struct event {
	unsigned long long duration_ns;
	char comm[TASK_COMM_LEN];
	void *realloc_addr;
	void *addr;
	size_t nmemb;
	size_t size;
	int pid;
	enum alloc_event event;
};

#endif /* __MALLOCSNOOP_H */
