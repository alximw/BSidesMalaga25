#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "dex_dumper.h"
#include "vmlinux.h"

// uids to watch
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u16));
    __uint(value_size, sizeof(__u16));
    __uint(max_entries, MAX_UIDS);
} uids_to_watch SEC(".maps");

/* ring buffer for dexload events*/
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} dexload_events SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* decide if we should hook the current process based on its uid */
static bool should_hook() {
    u32 uid = (bpf_get_current_uid_gid() & 0x00000000FFFFFFFF);
    u32* value = bpf_map_lookup_elem(&uids_to_watch, &uid);
    return value != NULL;
}

/* memory layout of a std::str */
struct std_string {
    u64 capacity;
    u64 size;
    u64 ptr;
};

SEC("uprobe/libdexfile_opencommon")
int uprobe_libdexfile(struct pt_regs* ctx) {
    if (!should_hook()) {
        return 0;
    }
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    /* Reserve an entry in the ringbuffer */
    struct dexload_event* entry =
        bpf_ringbuf_reserve(&dexload_events, sizeof(struct dexload_event), 0);
    if (!entry) {
        bpf_printk("Error reserving in ringbuffer kernel side");
        return 0;
    }
    __builtin_memset(entry->location, 0x00, MAX_PATH_LEN);
    entry->pid = pid;
    entry->begin = (void*)PT_REGS_PARM1(ctx);
    entry->size = PT_REGS_PARM2(ctx);
    struct std_string location;
    /* read std:str fatpointer */
    bpf_probe_read_user(&location, sizeof(struct std_string), (void*)PT_REGS_PARM5(ctx));
    /* read actual dex location */
    bpf_probe_read_user_str(entry->location, MAX_PATH_LEN, (void*)location.ptr);
    /* submit event */
    bpf_ringbuf_submit(entry, 0);

    return 0;
}