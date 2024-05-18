// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2024 The Inspektor Gadget authors

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH 127
#endif

#define KERNEL_STACK_MAP_MAX_ENTRIES 10000

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
	__uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
	__uint(max_entries, KERNEL_STACK_MAP_MAX_ENTRIES);
} __kernel_stack_trace_map SEC(".maps");

long __get_kernel_stack(struct pt_regs *ctx)
{
	return bpf_get_stackid(ctx, &__kernel_stack_trace_map,
			       BPF_F_FAST_STACK_CMP);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
