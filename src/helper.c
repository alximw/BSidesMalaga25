#include "helper.h"

#include <bpf/libbpf.h>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// struct bpf_link* attach_uprobe(const struct bpf_object* obj, bool is_ret) {
//     // const char* pname = bpf_program__name(prog);
//     //  off_t offset = 0x0;
//     //  if (strstr(pname, "libart")) {
//     //      // objdump --syms libart.so|grep InvokeVirtualOrInterfaceWithVarArgs
//     //      // ToDo: find offset using libelf
//     //      offset = get_symbol_offset(LIBART, INVOKE_SYM_NAME);
//     //      return bpf_program__attach_uprobe(prog, is_ret, -1, LIBART, offset);
//     //  }
//     //  if (strstr(pname, "libc")) {
//     //      return bpf_program__attach_uprobe(prog, is_ret, -1, LIBC, 000000);
//     //  }
//     return NULL;
// }

struct bpf_link* attach_kprobe(struct bpf_program* prog, bool is_ret) {
    const char* name = bpf_program__section_name(prog);
    int idx = strcspn(name, (char*)"/");
    if (idx == strlen(name)) {
        fprintf(stderr, "Can not inferr kprobe target function from section name for %s\n", name);
        return NULL;
    }
    return bpf_program__attach_kprobe(prog, is_ret, name + idx + 1);
}

void read_from_trace_pipe() {
    int trace_fd;
    trace_fd = open("/sys/kernel/tracing/trace_pipe", O_RDONLY, 0);
    if (trace_fd < 0) return;

    while (1) {
        static char buf[4096];
        ssize_t sz;

        sz = read(trace_fd, buf, sizeof(buf) - 1);
        if (sz > 0) {
            buf[sz] = 0;
            printf("%s\n", buf);
        }
    }
}

struct bpf_map* find_map_from_name(const struct bpf_object* obj, const char* name) {
    struct bpf_map* map;
    bpf_object__for_each_map(map, obj) {
        if (strcmp(name, bpf_map__name(map)) == 0) {
            return map;
        }
    }
    return NULL;
}

int attach_programs(const struct bpf_object* obj) {
    struct bpf_link* link = NULL;
    struct bpf_program* prog;
    bpf_object__for_each_program(prog, obj) {
        enum bpf_prog_type ptype = bpf_program__type(prog);
        DEBUGLOG("Loading program %s, SEC %s, type: %d\n", bpf_program__name(prog),
                 bpf_program__section_name(prog), ptype);
        switch (ptype) {
            case BPF_PROG_TYPE_TRACEPOINT:
                link = bpf_program__attach(prog);
                break;
            case BPF_PROG_TYPE_KPROBE:
                /* k(ret)probe or u(ret)probe*/
                if (strstr(bpf_program__section_name(prog), "uprobe")) {
                    // link = attach_uprobe(prog, 0);
                } else if (strstr(bpf_program__section_name(prog), "uretprobe")) {
                    // link = attach_uprobe(prog, 1);
                } else if (strstr(bpf_program__section_name(prog), "kprobe")) {
                    link = attach_kprobe(prog, 0);
                } else {
                    link = attach_kprobe(prog, 1);
                }
                break;
            default:
                fprintf(stderr, "Dont know what to do for prog_type %d\n", ptype);
                break;
        }
        if (libbpf_get_error(link)) {
            fprintf(stderr, "ERROR: bpf_program__attach failed for prog %s\n",
                    bpf_program__name(prog));
            return -1;
        }
    }
    return 0;
}

int load_bpf_elf_obj(struct bpf_object* obj) {
    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: loading BPF object file failed. Errno: %d\n", errno);
        return 1;
    }
    return 0;
}