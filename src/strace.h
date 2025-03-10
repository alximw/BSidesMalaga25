#define MAX_UIDS 10
#define MAX_SYSCALL_NR 222

#define FACCESSAT 48
#define NEWFSTATAT 79
#define OPENAT 56
#define EXECVE 221
#define UNLINKAT 35

#define MAX_ARGS 4
#define MAX_SYSCALL_NAME 32
#define MAX_PATH_LEN 128

// 48 faccessat 79 newfstatat 56 openat 221 execve 35 unlinkat
struct default_syscall_info {
    char name[MAX_SYSCALL_NAME];
    int num_args;
};
const struct default_syscall_info syscalls[MAX_SYSCALL_NR] = {
    [FACCESSAT] = {"faccessat", 3}, [NEWFSTATAT] = {"newfstatat", 4}, [OPENAT] = {"openat", 4},
    [EXECVE] = {"execve", 3},       [UNLINKAT] = {"unlinkat", 3},
};

typedef enum { SYS_ENTER, SYS_EXIT } event_mode;
struct syscall_event {
    event_mode mode;
    union {
        struct {
            char name[MAX_SYSCALL_NAME];
            int num_args;
            long syscall_nr;
            void* args[MAX_ARGS];
            char path[MAX_PATH_LEN];
        };
        long retval;
    };
};

static bool is_fs_syscall(uint64_t snr) {
    return (snr == FACCESSAT || snr == NEWFSTATAT || snr == OPENAT || snr == UNLINKAT);
}
