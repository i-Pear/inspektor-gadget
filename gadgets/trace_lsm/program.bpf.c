// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2024 The Inspektor Gadget authors */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>

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

SEC("lsm/bpf")
int trace_bpf(int cmd, union bpf_attr *uattr, unsigned int size)
{
	struct event e;
	e.pid = 1;
	e.operation = MALLOC;
	e.addr = 2;

	bpf_ringbuf_output(&events, &e, sizeof(e), 0);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
