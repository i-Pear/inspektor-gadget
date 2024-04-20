// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2024 The Inspektor Gadget authors

#ifndef __USDT_ARGUMENT_H
#define __USDT_ARGUMENT_H

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

enum USDT_ARG_TYPE {
	/* Argument in register */
	USDT_ARG_TYPE_REG,
	/* Argument in memory */
	USDT_ARG_TYPE_MEM,
};

enum USDT_ARG_LENGTH {
	USDT_ARG_LENGTH_UINT8,
	USDT_ARG_LENGTH_INT8,
	USDT_ARG_LENGTH_UINT16,
	USDT_ARG_LENGTH_INT16,
	USDT_ARG_LENGTH_UINT32,
	USDT_ARG_LENGTH_INT32,
	USDT_ARG_LENGTH_UINT64,
	USDT_ARG_LENGTH_INT64,
};

#if defined(__TARGET_ARCH_arm64)

enum USDT_ARG_REG {
	USDT_ARG_REG_ZERO,
	USDT_ARG_REG_R0,
	USDT_ARG_REG_R1,
	USDT_ARG_REG_R2,
	USDT_ARG_REG_R3,
	USDT_ARG_REG_R4,
	USDT_ARG_REG_R5,
	USDT_ARG_REG_R6,
	USDT_ARG_REG_R7,
	USDT_ARG_REG_R8,
	USDT_ARG_REG_R9,
	USDT_ARG_REG_R10,
	USDT_ARG_REG_R11,
	USDT_ARG_REG_R12,
	USDT_ARG_REG_R13,
	USDT_ARG_REG_R14,
	USDT_ARG_REG_R15,
	USDT_ARG_REG_R16,
	USDT_ARG_REG_R17,
	USDT_ARG_REG_R18,
	USDT_ARG_REG_R19,
	USDT_ARG_REG_R20,
	USDT_ARG_REG_R21,
	USDT_ARG_REG_R22,
	USDT_ARG_REG_R23,
	USDT_ARG_REG_R24,
	USDT_ARG_REG_R25,
	USDT_ARG_REG_R26,
	USDT_ARG_REG_R27,
	USDT_ARG_REG_R28,
	USDT_ARG_REG_R29,
	USDT_ARG_REG_R30,
	USDT_ARG_REG_SP,
	USDT_ARG_REG_PC,
	USDT_ARG_REG_PSTATE,
};

static __always_inline __u64 usdt_get_register_val(struct pt_regs *_ctx,
						   unsigned reg_id)
{
	struct user_pt_regs *ctx = (struct user_pt_regs *)_ctx;
	switch (reg_id) {
	case USDT_ARG_REG_ZERO:
		return 0;
	case USDT_ARG_REG_R0:
		return ctx->regs[0];
	case USDT_ARG_REG_R1:
		return ctx->regs[1];
	case USDT_ARG_REG_R2:
		return ctx->regs[2];
	case USDT_ARG_REG_R3:
		return ctx->regs[3];
	case USDT_ARG_REG_R4:
		return ctx->regs[4];
	case USDT_ARG_REG_R5:
		return ctx->regs[5];
	case USDT_ARG_REG_R6:
		return ctx->regs[6];
	case USDT_ARG_REG_R7:
		return ctx->regs[7];
	case USDT_ARG_REG_R8:
		return ctx->regs[8];
	case USDT_ARG_REG_R9:
		return ctx->regs[9];
	case USDT_ARG_REG_R10:
		return ctx->regs[10];
	case USDT_ARG_REG_R11:
		return ctx->regs[11];
	case USDT_ARG_REG_R12:
		return ctx->regs[12];
	case USDT_ARG_REG_R13:
		return ctx->regs[13];
	case USDT_ARG_REG_R14:
		return ctx->regs[14];
	case USDT_ARG_REG_R15:
		return ctx->regs[15];
	case USDT_ARG_REG_R16:
		return ctx->regs[16];
	case USDT_ARG_REG_R17:
		return ctx->regs[17];
	case USDT_ARG_REG_R18:
		return ctx->regs[18];
	case USDT_ARG_REG_R19:
		return ctx->regs[19];
	case USDT_ARG_REG_R20:
		return ctx->regs[20];
	case USDT_ARG_REG_R21:
		return ctx->regs[21];
	case USDT_ARG_REG_R22:
		return ctx->regs[22];
	case USDT_ARG_REG_R23:
		return ctx->regs[23];
	case USDT_ARG_REG_R24:
		return ctx->regs[24];
	case USDT_ARG_REG_R25:
		return ctx->regs[25];
	case USDT_ARG_REG_R26:
		return ctx->regs[26];
	case USDT_ARG_REG_R27:
		return ctx->regs[27];
	case USDT_ARG_REG_R28:
		return ctx->regs[28];
	case USDT_ARG_REG_R29:
		return ctx->regs[29];
	case USDT_ARG_REG_R30:
		return ctx->regs[30];
	case USDT_ARG_REG_SP:
		return ctx->sp;
	case USDT_ARG_REG_PC:
		return ctx->pc;
	case USDT_ARG_REG_PSTATE:
		return ctx->pstate;
	}
}

#elif defined(__TARGET_ARCH_x86)

enum USDT_ARG_REG {
	USDT_ARG_REG_ZERO,
	USDT_ARG_REG_R15,
	USDT_ARG_REG_R14,
	USDT_ARG_REG_R13,
	USDT_ARG_REG_R12,
	USDT_ARG_REG_BP,
	USDT_ARG_REG_BX,
	USDT_ARG_REG_R11,
	USDT_ARG_REG_R10,
	USDT_ARG_REG_R9,
	USDT_ARG_REG_R8,
	USDT_ARG_REG_AX,
	USDT_ARG_REG_CX,
	USDT_ARG_REG_DX,
	USDT_ARG_REG_SI,
	USDT_ARG_REG_DI,
	USDT_ARG_REG_ORIG_AX,
	USDT_ARG_REG_IP,
	USDT_ARG_REG_CS,
	USDT_ARG_REG_FLAGS,
	USDT_ARG_REG_SP,
	USDT_ARG_REG_SS,
};

static __always_inline __u64 usdt_get_register_val(struct pt_regs *ctx,
						   unsigned reg_id)
{
	switch (reg_id) {
	case USDT_ARG_REG_ZERO:
		return 0;
	case USDT_ARG_REG_R15:
		return ctx->r15;
	case USDT_ARG_REG_R14:
		return ctx->r14;
	case USDT_ARG_REG_R13:
		return ctx->r13;
	case USDT_ARG_REG_R12:
		return ctx->r12;
	case USDT_ARG_REG_BP:
		return ctx->bp;
	case USDT_ARG_REG_BX:
		return ctx->bx;
	case USDT_ARG_REG_R11:
		return ctx->r11;
	case USDT_ARG_REG_R10:
		return ctx->r10;
	case USDT_ARG_REG_R9:
		return ctx->r9;
	case USDT_ARG_REG_R8:
		return ctx->r8;
	case USDT_ARG_REG_AX:
		return ctx->ax;
	case USDT_ARG_REG_CX:
		return ctx->cx;
	case USDT_ARG_REG_DX:
		return ctx->dx;
	case USDT_ARG_REG_SI:
		return ctx->si;
	case USDT_ARG_REG_DI:
		return ctx->di;
	case USDT_ARG_REG_ORIG_AX:
		return ctx->orig_ax;
	case USDT_ARG_REG_IP:
		return ctx->ip;
	case USDT_ARG_REG_CS:
		return ctx->cs;
	case USDT_ARG_REG_FLAGS:
		return ctx->flags;
	case USDT_ARG_REG_SP:
		return ctx->sp;
	case USDT_ARG_REG_SS:
		return ctx->ss;
	}
}

#else
#error "USDT argument support is not supported in the current architecture."
#endif

/* Some more complex USDT parameters may require multiple registers */
/* We use 64 bits for future scalability */
struct __usdt_argument {
	enum USDT_ARG_TYPE type : 1;
	enum USDT_ARG_LENGTH length : 3;
	enum USDT_ARG_REG reg : 8;
	int offset : 20;
	unsigned _padding : 32;
};

#define USDT_ARG_DEFINE_PLACEHOLDER(n)                            \
	volatile const struct __usdt_argument __usdt_argument_##n \
		__attribute__((unused));

#define USDT_ARG_PLACEHOLDER(n) __usdt_argument_##n

USDT_ARG_DEFINE_PLACEHOLDER(0)
USDT_ARG_DEFINE_PLACEHOLDER(1)
USDT_ARG_DEFINE_PLACEHOLDER(2)
USDT_ARG_DEFINE_PLACEHOLDER(3)
USDT_ARG_DEFINE_PLACEHOLDER(4)
USDT_ARG_DEFINE_PLACEHOLDER(5)
USDT_ARG_DEFINE_PLACEHOLDER(6)
USDT_ARG_DEFINE_PLACEHOLDER(7)
USDT_ARG_DEFINE_PLACEHOLDER(8)
USDT_ARG_DEFINE_PLACEHOLDER(9)
USDT_ARG_DEFINE_PLACEHOLDER(10)
USDT_ARG_DEFINE_PLACEHOLDER(11)

#define USDT_ARG_DEFINE_GETTER(n)                                           \
	static __always_inline __u64 __usdt_get_argument_##n(struct pt_regs *ctx)  \
	{                                                                   \
		const struct __usdt_argument arg = USDT_ARG_PLACEHOLDER(n);                        \
		__u64 register_val = usdt_get_register_val(ctx, arg.reg);   \
		__u64 offset_val = arg.offset;                              \
		__u64 argument_val;                                         \
                                                                            \
		switch (arg.type) {                                         \
		case USDT_ARG_TYPE_REG: {                                   \
			switch (arg.length) {                               \
			case USDT_ARG_LENGTH_UINT8:                         \
				return (uint8_t)register_val;               \
			case USDT_ARG_LENGTH_INT8:                          \
				return (int8_t)register_val;                \
			case USDT_ARG_LENGTH_UINT16:                        \
				return (uint16_t)register_val;              \
			case USDT_ARG_LENGTH_INT16:                         \
				return (int16_t)register_val;               \
			case USDT_ARG_LENGTH_UINT32:                        \
				return (uint32_t)register_val;              \
			case USDT_ARG_LENGTH_INT32:                         \
				return (int32_t)register_val;               \
			case USDT_ARG_LENGTH_UINT64:                        \
				return (uint64_t)register_val;              \
			case USDT_ARG_LENGTH_INT64:                         \
				return (int64_t)register_val;               \
			}                                                   \
		}                                                           \
		case USDT_ARG_TYPE_MEM: {                                   \
			__u64 memory_address = register_val + offset_val;   \
			__u64 buffer;                                       \
			switch (arg.length) {                               \
			case USDT_ARG_LENGTH_UINT8:                         \
			case USDT_ARG_LENGTH_INT8:                          \
				bpf_probe_read_user(&buffer, 1,             \
						    memory_address);        \
				return *(uint8_t *)&buffer;                 \
			case USDT_ARG_LENGTH_UINT16:                        \
			case USDT_ARG_LENGTH_INT16:                         \
				bpf_probe_read_user(&buffer, 2,             \
						    memory_address);        \
				return *(uint16_t *)&buffer;                \
			case USDT_ARG_LENGTH_UINT32:                        \
			case USDT_ARG_LENGTH_INT32:                         \
				bpf_probe_read_user(&buffer, 4,             \
						    memory_address);        \
				return *(uint32_t *)&buffer;                \
			case USDT_ARG_LENGTH_UINT64:                        \
			case USDT_ARG_LENGTH_INT64:                         \
				bpf_probe_read_user(&buffer, 8,             \
						    memory_address);        \
				return *(uint64_t *)&buffer;                \
			}                                                   \
		}                                                           \
		}                                                           \
	}

USDT_ARG_DEFINE_GETTER(0)
USDT_ARG_DEFINE_GETTER(1)
USDT_ARG_DEFINE_GETTER(2)
USDT_ARG_DEFINE_GETTER(3)
USDT_ARG_DEFINE_GETTER(4)
USDT_ARG_DEFINE_GETTER(5)
USDT_ARG_DEFINE_GETTER(6)
USDT_ARG_DEFINE_GETTER(7)
USDT_ARG_DEFINE_GETTER(8)
USDT_ARG_DEFINE_GETTER(9)
USDT_ARG_DEFINE_GETTER(10)
USDT_ARG_DEFINE_GETTER(11)

#define usdt_get_argument(ctx, n) __usdt_get_argument_##n(ctx)

#endif /* __USDT_ARGUMENT_H */
