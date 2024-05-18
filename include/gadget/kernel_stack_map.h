// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2024 The Inspektor Gadget authors

#ifndef __KERNEL_STACK_MAP_H
#define __KERNEL_STACK_MAP_H

/* Sync with operators/ebpf/bpf/kernel_stack.bpf.c */
/* Returns the kernel stack id, positive or null on success, negative on failure */
/* Placeholder only here, needs to be replaced by bpf extension using BPF_F_REPLACE */
__attribute__((optnone)) long __get_kernel_stack(struct pt_regs *ctx)
{
	return (long)ctx;
}

static __always_inline long gadget_get_kernel_stack(void *ctx)
{
	return __get_kernel_stack(ctx);
}

#endif /* __KERNEL_STACK_MAP_H */
