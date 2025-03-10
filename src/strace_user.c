#include <bpf/libbpf.h>
#include <errno.h>
#include <getopt.h>
#include <stdlib.h>

#include "helper.h"
#include "strace.h"
const char* bpf_path = "/data/local/tmp/strace.bpf.o";
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
    struct syscall_event* info = (struct syscall_event*)data;
    if (!info) {
        return -1;
    }

    if (info->mode == SYS_ENTER) {
        printf("%s(", info->name);
        for (int i = 0; i < info->num_args; i++) {
            if (is_fs_syscall(info->syscall_nr) && i == 1) {
                printf("%s,", info->path);
            } else if (!is_fs_syscall(info->syscall_nr) && i == 0) {
                printf("%s,", info->path);
            } else {
                printf("%p,", info->args[i]);
            }
        }
        printf("\b)");
    } else {
        if (info->retval < 0) {
            printf("=%ld (%s)\n", info->retval, strerror(abs(info->retval)));
        } else {
            printf("=%ld\n", info->retval);
        }
    }

    return 0;
}

int main(int argc, char** argv) {
    struct bpf_object* elf_obj;
    parseargs(argc, argv);
    elf_obj = bpf_object__open_file(bpf_path, NULL);
    if (!elf_obj) {
        printf("Error opening %s. Errno: %d\n", bpf_path, errno);
        return 1;
    }

    if (load_bpf_elf_obj(elf_obj)) {
        return 1;
    }
    /* add uids to monitor */
    add_ints_to_map((uint16_t*)&watched_uids, find_map_from_name(elf_obj, "uids_to_watch"));

    attach_programs(elf_obj);
    int rbFd = bpf_object__find_map_fd_by_name(elf_obj, "syscall_events");
    struct ring_buffer* rb = ring_buffer__new(rbFd, rb_callback, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Error allocating ring buffer");
        return -1;
    }

    /* poll the buffer */
    while (1) {
        ring_buffer__consume(rb);
    }

    return 0;
}