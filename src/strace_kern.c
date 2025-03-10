#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <vmlinux.h>

#include "strace.h"
// uids to watch
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u16));
    __uint(value_size, sizeof(__u16));
    __uint(max_entries, MAX_UIDS);
} uids_to_watch SEC(".maps");

/* ring buffer for syscall events*/
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} syscall_events SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* decide if we´re interested in the syscall */
int is_relevant_syscall(u64 syscall_nr) {
    if (syscall_nr == FACCESSAT || syscall_nr == OPENAT || syscall_nr == NEWFSTATAT ||
        syscall_nr == EXECVE) {
        return 1;
    }
    // if (syscall_nr == OPENAT) {
    //     return 1;
    // }
    return 0;
}

/* decide if we should hook the current process based on its uid */
static bool should_hook() {
    u32 uid = (bpf_get_current_uid_gid() & 0x00000000FFFFFFFF);
    u32* value = bpf_map_lookup_elem(&uids_to_watch, &uid);
    return value != NULL;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int syscall_enter(struct trace_event_raw_sys_enter* ctx) {
    if (!should_hook()) {
        return 0;
    }
    // Retrieve the system call number
    u64 snr = ctx->id;
    if (snr >= MAX_SYSCALL_NR || !is_relevant_syscall(snr)) {
        return 0;
    }

    /* Reserve an entry in the ringbuffer */
    struct syscall_event* entry =
        bpf_ringbuf_reserve(&syscall_events, sizeof(struct syscall_event), 0);
    if (!entry) {
        bpf_printk("Error reserving in ringbuffer kernel side");
        return 0;
    }

    /* Copy syscall name to event struct */
    int error = 0;
    error = bpf_probe_read_kernel_str(&entry->name, sizeof(syscalls[snr].name),
                                      (void*)syscalls[snr].name);
    /* Copy syscall arg values to event struct, if is a char * read the str from the pointer */
    for (int i = 0; i < MAX_ARGS; i++) {
        entry->args[i] = (void*)BPF_CORE_READ(ctx, args[i]);
        if (!is_fs_syscall(snr) && i == 0) {
            error = bpf_probe_read_user_str(&entry->path, MAX_PATH_LEN, entry->args[i]);
            // bpf_printk("%s: %d", entry->path, error);
        };
        if (is_fs_syscall(snr) && i == 1) {
            error = bpf_probe_read_user_str(&entry->path, MAX_PATH_LEN, entry->args[i]);
            // bpf_printk("%s: %d", entry->path, error);
        };
    }
    entry->num_args = syscalls[snr].num_args;
    entry->syscall_nr = snr;
    entry->mode = SYS_ENTER;

    bpf_ringbuf_submit(entry, 0);

    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int syscall_exit(struct trace_event_raw_sys_exit* ctx) {
    if (!should_hook()) {
        return 0;
    }
    // Retrieve the system call number
    u64 snr = ctx->id;
    if (snr >= MAX_SYSCALL_NR || !is_relevant_syscall(snr)) {
        return 0;
    }
    u64 ret = ctx->ret;
    struct syscall_event* entry =
        bpf_ringbuf_reserve(&syscall_events, sizeof(struct syscall_event), 0);
    if (!entry) {
        bpf_printk("Error reserving in ringbuffer kernel side");
        return 0;
    }
    entry->syscall_nr = snr;
    entry->retval = ret;
    entry->mode = SYS_EXIT;
    bpf_ringbuf_submit(entry, 0);
    return 0;
}
