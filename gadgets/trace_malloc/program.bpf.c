// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 The Inspektor Gadget authors */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <gadget/buffer.h>
#include <gadget/macros.h>

struct event {
	__u32 pid;
	__u64 addr;
	bool is_malloc;
	__u8 comm[TASK_COMM_LEN];
};

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(open, events, event);

SEC("uretprobe//usr/lib/x86_64-linux-gnu/libc.so.6:malloc")
int trace_uprobe_malloc(struct pt_regs * ctx)
{
	struct event *event;

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

	event->pid = bpf_get_current_pid_tgid() >> 32;
	event->addr = PT_REGS_RC(ctx);
	event->is_malloc = 1;
	bpf_get_current_comm(event->comm, sizeof(event->comm));

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

	return 0;
}

SEC("uprobe//usr/lib/x86_64-linux-gnu/libc.so.6:free")
int trace_uprobe_free(struct pt_regs * ctx)
{
	struct event *event;

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

	event->pid = bpf_get_current_pid_tgid() >> 32;
	event->addr = PT_REGS_PARM1(ctx);
	event->is_malloc = 0;
	bpf_get_current_comm(event->comm, sizeof(event->comm));

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
