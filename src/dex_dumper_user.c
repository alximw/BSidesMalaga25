#define _GNU_SOURCE

#include <bpf/libbpf.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <time.h>

#include "dex_dumper.h"
#include "helper.h"
const char* bpf_path = "/data/local/tmp/dex_dumper.bpf.o";
static uint16_t watched_uids[MAX_UIDS];

void usage(void) {
    printf(": instrument kernel syscalls with our own bpf implant");
    printf("\n");
    printf("-h, --help                 Print program usage.\n");
    printf("-u, --uids                 List (comma separated) of uids to instrument.\n");
    exit(0);
}

static void add_int(char* uid, int current, uint16_t* list_ptr) {
    char* endptr;
    uint32_t token = (uint32_t)strtol(uid, &endptr, 10);
    if (errno != 0) {
        fprintf(stderr, "[ERROR] Error parsing int from %s with base 10.\n", uid);
        exit(-1);
    }
    list_ptr[current] = token;
}

int add_ints_to_map(uint16_t* list, struct bpf_map* map) {
    if (!map) {
        fprintf(stderr, "Error updating map, map ptr is NULL.\n");
        return -1;
    }
    int add_result = 0;
    uint16_t value = 0x1337;
    for (unsigned int i = 0; i < MAX_UIDS - 1; i++) {
        if (list[i] == 0x00) break;
        printf("adding %d:%d to map\n", list[i], value);
        add_result =
            bpf_map__update_elem(map, &list[i], sizeof(__u16), &value, sizeof(value), BPF_ANY);
        if (add_result < 0) {
            printf("Error adding entry k = %d v = %d. error:%s \n", list[i], value, strerror(errno));
            return -1;
        }
    }
    return 0;
}

int parse_list_to_int_array(char* arg, uint16_t* list_ptr) {
    unsigned char current = 0;
    char* token = strtok(arg, ",");
    add_int(token, current, list_ptr);
    current += 1;
    token = strtok(NULL, ",");
    while (token != NULL && current < MAX_UIDS) {
        add_int(token, current, list_ptr);
        current += 1;
        token = strtok(NULL, ",");
    }
    return current;
}

void parseargs(int argc, char** argv) {
    unsigned int error_count = 0;
    int opt = 0;
    int long_index = 0;
    static struct option long_options[] = {{"help", no_argument, NULL, 'h'},
                                           {"uids", required_argument, NULL, 'u'},
                                           {NULL, 0, NULL, 0}};

    while ((opt = getopt_long_only(argc, argv, ":hvu:l:", long_options, &long_index)) != -1) {
        switch (opt) {
            case 'u':
                parse_list_to_int_array(optarg, (uint16_t*)&watched_uids);
                break;
            case ':':
                fprintf(stderr, "[ERROR] Option '-%c' is missing an argument.\n", optopt);
                error_count++;
                break;
            case 'h':
            case '?':
            default:
                usage();
                break;
        }
    }
    if (error_count > 0 || argc == 1) {
        usage();
    }
}

/* called on each new event submited to the ringbuf */
static int rb_callback(void* ctx, void* data, size_t len) {
    struct dexload_event* info = (struct dexload_event*)data;
    if (!info) {
        return -1;
    }
    printf("[+] pid: %d loading dex (%ld bytes) @ %p. Location: %s \n", info->pid, info->size,
           info->begin, info->location);
    struct iovec local[1];
    local[0].iov_base = calloc(info->size, sizeof(char));
    local[0].iov_len = info->size;

    struct iovec remote[1];
    remote[0].iov_base = info->begin;
    remote[0].iov_len = info->size;
    ssize_t nread = process_vm_readv(info->pid, local, 2, remote, 1, 0);
    if (nread < 0) {
        printf("Error reading memory from remote process %d. errno: %s\n", info->pid,
               strerror(errno));
        return 1;
    }
    char filename[MAX_PATH_LEN] = {0};
    snprintf(filename, MAX_PATH_LEN, "/sdcard/%u.dex", (unsigned)time(NULL));
    printf("[+] dumping %ld bytes to %s\n", info->size, filename);
    FILE* f = fopen(filename, "wb");
    fwrite(local[0].iov_base, sizeof(char), info->size, f);
    chmod(filename, S_IRWXU | S_IRWXG | S_IRWXO);
    fclose(f);
    return 0;
}

struct bpf_link* attach_uprobe(const struct bpf_program* prog, bool is_ret) {
    const char* pname = bpf_program__name(prog);
    if (strstr(pname, "libdexfile")) {
        return bpf_program__attach_uprobe(prog, is_ret, -1, LIBDEXFILE, OFFSET);
    }
    return NULL;
}

struct bpf_map* find_map(const struct bpf_object* obj, const char* name) {
    struct bpf_map* map;
    bpf_object__for_each_map(map, obj) {
        if (strcmp(name, bpf_map__name(map)) == 0) {
            return map;
        }
    }
    return NULL;
}

int attach_program(const struct bpf_object* obj) {
    struct bpf_link* link = NULL;
    struct bpf_program* prog;
    bpf_object__for_each_program(prog, obj) {
        enum bpf_prog_type ptype = bpf_program__type(prog);
        DEBUGLOG("Attaching program %s, SEC %s, type: %d\n", bpf_program__name(prog),
                 bpf_program__section_name(prog), ptype);
        switch (ptype) {
            case BPF_PROG_TYPE_KPROBE:
                if (strstr(bpf_program__section_name(prog), "uprobe")) {
                    link = attach_uprobe(prog, 0);
                } else if (strstr(bpf_program__section_name(prog), "uretprobe")) {
                    link = attach_uprobe(prog, 1);
                }
            default:
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

int main(int argc, char** argv) {
    struct bpf_object* elf_obj;
    parseargs(argc, argv);

    elf_obj = bpf_object__open_file(bpf_path, NULL);
    if (!elf_obj) {
        fprintf(stderr, "Error opening %s. Errno: %d\n", bpf_path, errno);
        return 1;
    }

    if (bpf_object__load(elf_obj)) {
        fprintf(stderr, "ERROR: loading BPF object file failed. Errno: %d\n", errno);
        return 1;
    }

    /* add uids to monitor */
    add_ints_to_map((uint16_t*)&watched_uids, find_map_from_name(elf_obj, "uids_to_watch"));
    int rbFd = bpf_object__find_map_fd_by_name(elf_obj, "dexload_events");
    struct ring_buffer* rb = ring_buffer__new(rbFd, rb_callback, NULL, NULL);
    if (attach_program(elf_obj)) {
        fprintf(stderr, "Error attaching programs. Errno: %d\n", errno);
        return 1;
    }
    if (!rb) {
        fprintf(stderr, "Error allocating ring buffer");
        return -1;
    }
    /*poll the buffer*/
    while (1) {
        ring_buffer__consume(rb);
    }

    return 0;
}