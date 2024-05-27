#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define USTACK_MAX_PIDS 1024
#define USTACK_MAX_MAPPINGS_PER_PROCESS 1024
#define USTACK_MAX_UNWIND_INFO_ENTRIES 1024

struct ustack_process_mapping {
    u64 vaddr;
    u64 length;

    u64 unwind_info_id;
    u64 unwind_info_delta;
};

struct ustack_pid_info {
    // sorted in asc order
    u32 mappings_count;
    struct ustack_process_mapping mappings[USTACK_MAX_MAPPINGS_PER_PROCESS];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, USTACK_MAX_PIDS);
} __ustack_pid_info SEC(".maps");

struct ustack_unwind_entry {
    u64 addr;

    u64 opcode;
    u64 opcode_param;

    u64 fp_opcode;
    u64 fp_opcode_param;
};

struct ustack_unwind_infos {
    u32 entries_count;
    struct ustack_unwind_entry entries[1024];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u64)); // unwind_info_id
	__uint(value_size, sizeof(struct ustack_unwind_info));
	__uint(max_entries, USTACK_MAX_UNWIND_INFO_ENTRIES);
} __ustack_unwind_infos SEC(".maps");

static ErrorCode unwind_one_frame(u64 pid, u32 frame_idx, UnwindState *state, bool* stop) {
  *stop = false;

  u32 unwindInfo = 0;
  u64 rt_regs[18];
  int addrDiff = 0;
  u64 cfa = 0;

  // The relevant executable is compiled with frame pointer omission, so
  // stack deltas need to be retrieved from the relevant map.
  ErrorCode error = get_stack_delta(state->text_section_id, state->text_section_offset,
                                    &addrDiff, &unwindInfo);
  if (error) {
    return error;
  }


    UnwindInfo *info = bpf_map_lookup_elem(&unwind_info_array, &unwindInfo);
    if (!info) {
      return -1;
    }

    s32 param = info->param;

    // Resolve the frame's CFA (previous PC is fixed to CFA) address, and
    // the previous FP address if any.
    cfa = unwind_register_address(state, 0, info->opcode, param);
    u64 fpa = unwind_register_address(state, cfa, info->fpOpcode, info->fpParam);

    if (fpa) {
      bpf_probe_read(&state->fp, sizeof(state->fp), (void*)fpa);
    } else if (info->opcode == UNWIND_OPCODE_BASE_FP) {
      // FP used for recovery, but no new FP value received, clear FP
      state->fp = 0;
    }
  

  if (!cfa || bpf_probe_read(&state->pc, sizeof(state->pc), (void*)(cfa - 8))) {
  err_native_pc_read:
    increment_metric(metricID_UnwindNativeErrPCRead);
    return -1;
  }
  state->sp = cfa;
}
