// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Started from the libbpf-bootstrap examples/c/bootstrap.bpf.c
/* Copyright (c) 2023 Red Hat */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "mallocsnoop.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct alloc_entry {
	u64 ts;
	size_t size;
	size_t nmemb;
	void *realloc_addr;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, pid_t);
	__type(value, struct alloc_entry);
} alloc_start SEC(".maps");

// BPF verifier subtlety: If we use pid_t (32 bits) we end up with an
// alignment home after 'pid', that if we don't fill with some value
// the kernel BPF verifier will notice and refuse to load:
/*
  # ./mallocsnoop -m 32 |& tail
  44: (18) r1 = 0xffff9176136e4000      ; frame1: R1_w=map_ptr(off=0,ks=16,vs=32,imm=0)
  46: (b7) r4 = 0                       ; frame1: R4_w=P0
  47: (85) call bpf_map_update_elem#2
  invalid indirect read from stack R2 off -24+4 size 16
  processed 40 insns (limit 1000000) max_states_per_insn 0 total_states 2 peak_states 2 mark_read 2
  -- END PROG LOAD LOG --
  libbpf: prog 'malloc_out': failed to load: -13
  libbpf: failed to load object 'mallocsnoop_bpf'
  libbpf: failed to load BPF skeleton 'mallocsnoop_bpf': -13
  Failed to load and verify BPF skeleton
  #
*/
// This is an example of failure to load something that was successfully compiled.

// It is very important to do as small changes as possible, so that we can associate
// the sometimes cryptic log provided by the kernel BPF verifier in response to the
// sys_bpf(PROG_LOAD) with the provided BPF bytecode.

// Use the 'pahole' tool to find out about this by looking at the BTF debug info in
// the generated bpf bytecode:
/*
    $ pahole -C alloc_addrs_key .output/mallocsnoop.bpf.o
    struct alloc_addrs_key {
	pid_t                      pid;                  //     0     4

	// XXX 4 bytes hole, try to pack

	void *                     addr;                 //     8     8

	// size: 16, cachelines: 1, members: 2
	// sum members: 12, holes: 1, sum holes: 4
	// last cacheline: 16 bytes
    };
    $

    While using a u64, as in this example, we fill that 4 bytes hole and thus leave
    no uninitialized area.
*/
struct alloc_addrs_key {
	u64  pid;
	void *addr;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct alloc_addrs_key);
	__type(value, struct alloc_entry);
} alloc_addrs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const volatile unsigned long my_pid = 0;
const volatile unsigned long target_pid = 0;
const volatile unsigned long exclude_pid = 0;
const volatile unsigned long min_size = 0;
const volatile unsigned long max_size = 0;
const volatile unsigned long long min_duration_ns = 0;

// exclude_pid to avoid feedback loops, like when running mallocsnoop on
// a gnome-terminal that allocates/frees when printing stuff then generates
// events caught by mallocsnoop that prints, generating the loop.
static bool filtered_pid(pid_t pid)
{
	return pid == my_pid || (target_pid && pid != target_pid) || (exclude_pid && pid == exclude_pid);
}

static int alloc_in(void *realloc_addr, size_t nmemb, size_t size)
{
	unsigned long total_size = nmemb * size;

	if ((min_size && total_size < min_size) ||
	    (max_size && total_size > max_size))
		return 0;

	pid_t pid = bpf_get_current_pid_tgid() >> 32;

	if (filtered_pid(pid))
		return 0;

	struct alloc_entry entry = {
		.ts   = bpf_ktime_get_ns(),
		.nmemb = nmemb,
		.size = size,
		.realloc_addr = realloc_addr,
	};

	bpf_map_update_elem(&alloc_start, &pid, &entry, BPF_ANY);

	return 0;
}

static int alloc_out(enum alloc_event alloc_event, void *addr) // addr returned by malloc/calloc/etc
{
	// malloc/calloc/etc() failed, returning NULL
	if (!addr)
		return 0;

	pid_t pid = bpf_get_current_pid_tgid() >> 32;

	if (filtered_pid(pid))
		return 0;

	struct alloc_entry *entry = bpf_map_lookup_elem(&alloc_start, &pid);

	if (!entry)
		return 0;

	struct alloc_addrs_key addrs_key = {
		.addr = addr,
		.pid  = pid,
	};
	struct alloc_entry chunk = {
		.nmemb = entry->nmemb,
		.size = entry->size,
		.ts   = entry->ts,
		.realloc_addr = entry->realloc_addr,
	};

	bpf_map_update_elem(&alloc_addrs, &addrs_key, &chunk, BPF_ANY);
	bpf_map_delete_elem(&alloc_start, &pid);

        /* don't emit malloc events when minimum duration is specified */
        if (min_duration_ns)
                return 0;

	struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->event = alloc_event;
	e->pid = pid;
	e->addr = addr;
	e->nmemb = chunk.nmemb;
	e->size = chunk.size;
	e->realloc_addr = chunk.realloc_addr;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// Remember what was malloc's 'size' argument for this pid
SEC("uprobe/libc.so.6:malloc")
int BPF_KPROBE(malloc_in, size_t size)
{
	return alloc_in(NULL, 1, size);
}

// Now that we're exiting malloc, we need to create an entry using
// the returned address and the pid_t that allocated it as the key
// so that at free() time we can do the math
SEC("uretprobe/libc.so.6:malloc")
int BPF_KRETPROBE(malloc_out, void *addr) // addr returned by malloc
{
	return alloc_out(EV_MALLOC, addr);
}

SEC("uprobe/libc.so.6:calloc")
int BPF_KPROBE(calloc_in, size_t nmemb, size_t size)
{
	return alloc_in(NULL, nmemb, size);
}

SEC("uretprobe/libc.so.6:calloc")
int BPF_KRETPROBE(calloc_out, void *addr) // addr returned by calloc
{
	return alloc_out(EV_CALLOC, addr);
}

SEC("uprobe/libc.so.6:realloc")
int BPF_KPROBE(realloc_in, void *ptr, size_t size)
{
	return alloc_in(ptr, 1, size);
}

SEC("uretprobe/libc.so.6:realloc")
int BPF_KRETPROBE(realloc_out, void *addr) // addr returned by realloc
{
	return alloc_out(EV_REALLOC, addr);
}

SEC("uprobe/libc.so.6:free")
int BPF_KPROBE(handle_free, void *addr)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;

	if (filtered_pid(pid))
		return 0;

	struct alloc_addrs_key addrs_key = {
		.addr = addr,
		.pid  = pid,
	};
	struct alloc_entry *chunk = bpf_map_lookup_elem(&alloc_addrs, &addrs_key);

	if (chunk == NULL)
		return 0;

	u64 duration_ns = bpf_ktime_get_ns() - chunk->ts;

        if (min_duration_ns && duration_ns < min_duration_ns)
                return 0;

	struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->event = EV_FREE;
	e->pid = pid;
	e->addr = addr;
	e->nmemb = chunk->nmemb;
	e->size = chunk->size;
	e->realloc_addr = chunk->realloc_addr;
	e->duration_ns = duration_ns;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_map_delete_elem(&alloc_addrs, &addrs_key);

	/* send data to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}
