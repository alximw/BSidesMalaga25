#include <bpf/libbpf.h>
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
int attach_programs(const struct bpf_object* obj);
int load_bpf_elf_obj(struct bpf_object* obj);
void read_from_trace_pipe();
struct bpf_map* find_map_from_name(const struct bpf_object* obj, const char* name);
struct bpf_link* attach_kprobe(struct bpf_program* prog, bool is_ret);