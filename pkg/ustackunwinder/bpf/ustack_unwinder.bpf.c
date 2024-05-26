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

