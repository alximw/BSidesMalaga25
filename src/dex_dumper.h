
#define LIBDEXFILE "/apex/com.android.art/lib64/libdexfile.so"
// objdump --syms libdexfile.so|grep _ZN3art13DexFileLoader10OpenCommon
#define OFFSET 0x0229f8
#define MAX_UIDS 10
#define MAX_PATH_LEN 128
#define MAX_COMM_LEN 128
#define DEBUG 1
#if DEBUG
#define DEBUGLOG(...)        \
    do {                     \
        printf(__VA_ARGS__); \
        fflush(stdout);      \
    } while (0)
#else
#define DEBUGLOG
#endif
struct dexload_event {
    char location[MAX_PATH_LEN];
    void* begin;
    size_t size;
    pid_t pid;
};