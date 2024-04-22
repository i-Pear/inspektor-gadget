// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2024 The Inspektor Gadget authors */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>

enum memop {
	MALLOC,
	FREE,
};

struct event {
	__u32 pid;
	enum memop operation;
	__u64 addr;
};

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(malloc, events, event);


SEC("lsm/mmap_file")
int trace_bpf(struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags)
{
	__u64 mntns_id = gadget_get_mntns_id();
	const char fmt_str[] = "%lu\n";
	bpf_trace_printk(fmt_str, sizeof(fmt_str), mntns_id);
	struct event e;
	e.pid = 1;
	e.operation = mntns_id % 2;
	e.addr = 2;

	bpf_ringbuf_output(&events, &e, sizeof(e), 0);

	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
