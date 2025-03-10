

#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <getopt.h>
#include <stdlib.h>

#include "helper.h"
#include "network_monitor.h"

const char* bpf_path = "/data/local/tmp/network_monitor.bpf.o";
static uint16_t watched_uids[MAX_UIDS];
static uint16_t watched_udp_ports[MAX_PORTS];
static uint16_t watched_tcp_ports[MAX_PORTS];
static uint64_t cnt;
#define MAX_CNT 100000ll

void usage(void) {
    printf(": instrument kernel syscalls with our own bpf implant");
    printf("\n");
    printf("-h, --help                 Print program usage.\n");
    printf("-u, --uids                 List (comma separated) of uids to instrument.\n");
    printf("-p, --ports                List (comma separated) of dst TCP ports to watch.\n");
    printf("-d, --dports               List (comma separated) of dst UDP ports to watch.\n");
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

void dump_config() {
    DEBUGLOG("[+] monitored UIDs:\n");
    for (int i = 0; i < MAX_UIDS; i++) {
        int curr = watched_uids[i];
        if (curr == 0x0) break;
        DEBUGLOG("\tmonitoring UID[%d] = %d\n", i, watched_uids[i]);
    }
    DEBUGLOG("[+] monitored TCP:\n");
    for (int i = 0; i < MAX_UIDS; i++) {
        int curr = watched_tcp_ports[i];
        if (curr == 0x0) break;
        DEBUGLOG("\tmonitoring TCP[%d] = %d\n", i, watched_tcp_ports[i]);
    }
    DEBUGLOG("[+] monitored UDP:\n");
    for (int i = 0; i < MAX_UIDS; i++) {
        int curr = watched_udp_ports[i];
        if (curr == 0x0) break;
        DEBUGLOG("\tmonitoring UDP[%d] = %d\n", i, watched_udp_ports[i]);
    }
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

void parseargs(int argc, char** argv) {
    unsigned int error_count = 0;
    int opt = 0;
    int long_index = 0;
    static struct option long_options[] = {{"help", no_argument, NULL, 'h'},
                                           {"uids", required_argument, NULL, 'u'},
                                           {"ports", required_argument, NULL, 'p'},
                                           {"dports", required_argument, NULL, 'd'},
                                           {NULL, 0, NULL, 0}};

    while ((opt = getopt_long_only(argc, argv, ":hvu:l:", long_options, &long_index)) != -1) {
        switch (opt) {
            case 'd':
                parse_list_to_int_array(optarg, (uint16_t*)&watched_udp_ports);
                break;
            case 'p':
                parse_list_to_int_array(optarg, (uint16_t*)&watched_tcp_ports);
                break;
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

static void perf_buff_cb(void* ctx, int cpu, void* data, __u32 size) {
    struct net_event ev = *(struct net_event*)data;
    if (ev.isIPv6) {
    } else {
        struct in_addr ip_addr;
        ip_addr.s_addr = ev.dst_ip4;
        printf("[%s(%d)]  proto: %d  src: localhost:%d-> %s:%d\n", ev.proc_ctx.comm,
               ev.proc_ctx.pid, ev.protocol, ev.src_port, inet_ntoa(ip_addr), ev.dst_port);
    }
}
struct perf_buffer* setup_perf_buf(struct bpf_object* obj) {
    int map_fd = bpf_object__find_map_fd_by_name(obj, "network_events");
    if (map_fd < 0) {
        fprintf(stderr, "ERROR: finding a map in obj file failed\n");
        return NULL;
    }
    return perf_buffer__new(map_fd, 8, perf_buff_cb, NULL, NULL, NULL);
}

int main(int argc, char** argv) {
    memset(&watched_uids, 0x00, sizeof(uint16_t) * MAX_UIDS);
    memset(&watched_tcp_ports, 0x00, sizeof(uint16_t) * MAX_PORTS);
    memset(&watched_udp_ports, 0x00, sizeof(uint16_t) * MAX_PORTS);

    struct bpf_object* elf_obj;
    parseargs(argc, argv);
    dump_config();

    elf_obj = bpf_object__open_file(bpf_path, NULL);
    if (!elf_obj) {
        printf("Error opening %s. Errno: %d\n", bpf_path, errno);
        return 1;
    }

    if (load_bpf_elf_obj(elf_obj)) {
        return 1;
    }

    add_ints_to_map((uint16_t*)&watched_uids, find_map_from_name(elf_obj, "uids_to_watch"));
    add_ints_to_map((uint16_t*)&watched_tcp_ports, find_map_from_name(elf_obj, "tcp_ports"));
    add_ints_to_map((uint16_t*)&watched_udp_ports, find_map_from_name(elf_obj, "udp_ports"));
    attach_programs(elf_obj);
    struct perf_buffer* pb = setup_perf_buf(elf_obj);
    if (!pb) {
        return -1;
    }

    // poll the perfbuff int ret = 0;
    int ret;
    while ((ret = perf_buffer__poll(pb, 1000)) >= 0 && cnt < MAX_CNT) {
    }
    read_from_trace_pipe();
    return 0;
}