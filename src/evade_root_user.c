#include <bpf/libbpf.h>
#include <errno.h>
#include <getopt.h>
#include <stdlib.h>

#include "evade_root.h"
#include "helper.h"

const char* bpf_path = "/data/local/tmp/evade_root.bpf.o";
static struct config config = {0};

void usage(void) {
    printf("evade_root: evade RootBeer root detections");
    printf("\n");
    printf("-h, --help                 Print program usage.\n");
    printf("-u, --uids                 List (comma separated) of uids to instrument.\n");
    printf("-l, --files                List (comma separated) of files to hide.\n");
    printf("-b, --bins                 List (comma separated) of binary files to hide.\n");
    exit(0);
}

static void add_uid(char* uid, int current) {
    char* endptr;
    short int_token = (short)strtol(uid, &endptr, 10);
    if (errno != 0) {
        fprintf(stderr, "[ERROR] Error parsing int from %s with base 10.\n", uid);
        exit(-1);
    }
    config.watched_uids[current] = int_token;
}

void dump_config() {
    DEBUGLOG("[+] monitored UIDs:\n");
    for (int i = 0; i < MAX_UIDS; i++) {
        int curr = config.watched_uids[i];
        if (curr == -1) break;
        DEBUGLOG("\tmonitoring UID[%d] = %d\n", i, config.watched_uids[i]);
    }
    DEBUGLOG("[+] Files to hide:\n");
    for (int i = 0; i < MAX_KEYS; i++) {
        char curr = config.files_to_hide[i][0];
        if (!curr) break;
        DEBUGLOG("\thidding file: %s\n", config.files_to_hide[i]);
    }
    DEBUGLOG("[+] Binaries to hide:\n");
    for (int i = 0; i < MAX_KEYS; i++) {
        char curr = config.bins_to_hide[i][0];
        if (!curr) break;
        DEBUGLOG("\thidding binary: %s\n", config.bins_to_hide[i]);
    }
}

int parse_uid_list(char* arg) {
    unsigned char current = 0;
    char* token = strtok(arg, ",");
    add_uid(token, current);
    current += 1;
    token = strtok(NULL, ",");
    while (token != NULL && current < MAX_UIDS) {
        add_uid(token, current);
        current += 1;
        token = strtok(NULL, ",");
    }
    return current;
}

void watch_uids(struct bpf_map* uids_map) {
    if (!uids_map) {
        fprintf(stderr, "Error updating uids_to_watch, map is NULL.\n");
        return;
    }
    int value = DUMMY; /* dummy value, we dont care about it */
    int add_result = 0;
    for (unsigned int i = 0; i < MAX_UIDS - 1; i++) {
        if (config.watched_uids[i] == -1) break;
        add_result = bpf_map__update_elem(uids_map, &config.watched_uids[i], sizeof(__u32), &value,
                                          sizeof(__u32), BPF_ANY);
        if (add_result < 0) {
            printf("Error adding entry k = %d v = %d. errno:%d error: %s\n", config.watched_uids[i],
                   value, errno, strerror(errno));
        }
    }
}

unsigned int add_entry(char* path, struct bpf_map* map) {
    int add_result = 0;
    struct fs_hide_key key = {0};
    key.inode = 0;
    key.st_dev = 0;
    int value = DUMMY; /* dummy value, we dont care about it */
    memset(&key.path, (char)0x0, MAX_D_NAME_LEN);
    memcpy(&key.path, path, strlen(path));

    add_result =
        bpf_map__update_elem(map, &key, sizeof(struct fs_hide_key), &value, sizeof(value), BPF_ANY);
    if (add_result < 0) {
        printf("Error adding entry %s. error:%s\n", path, strerror(errno));
    }
    return 0;
}

void hide_files(struct bpf_map* hide_map) {
    if (!hide_map) {
        fprintf(stderr, "Error updating files_to_hide_hm, map is NULL.\n");
        return;
    }
    for (unsigned int i = 0; i < MAX_FILES - 1; i++) {
        if (config.files_to_hide[i][0] == 0x00) break;
        add_entry(config.files_to_hide[i], hide_map);
    }
}

void mute_system_bins(struct bpf_map* mute_map) {
    if (!mute_map) {
        fprintf(stderr, "Error updating mute_map, map is NULL.\n");
        return;
    }
    int add_result = 0;
    uint32_t value = DUMMY;
    for (int i = 0; i < MAX_FILES; i++) {
        if (config.bins_to_hide[i][0] == 0x00) {
            break;
        }
        // printf("Adding %s\n", config.bins_to_hide[i]);
        struct task_name task;
        memset(&task.name, 0x00, MAX_COMM_LEN);
        strlcpy((char*)&task.name, config.bins_to_hide[i], strlen(config.bins_to_hide[i]) + 1);
        add_result = bpf_map__update_elem(mute_map, &task, sizeof(struct task_name), &value,
                                          sizeof(value), BPF_ANY);
        if (add_result < 0) {
            printf("Error adding task entry %s. errno: %s \n", config.bins_to_hide[i],
                   strerror(errno));
        }
    }
}

int parse_file_list(char* arg, file_list list) {
    unsigned int tok_len = 0;
    unsigned char current = 0;
    char* token = strtok(arg, ",");
    tok_len = strlen(token);
    size_t size = (tok_len < MAX_D_NAME_LEN) ? tok_len : MAX_D_NAME_LEN;
    printf("writing to %p, token %s\n", &list[current], token);
    memcpy(list[current], token, size);
    current += 1;
    token = strtok(NULL, ",");
    while (token != NULL && current < MAX_FILES) {
        tok_len = strlen(token);
        size = (tok_len < MAX_D_NAME_LEN) ? tok_len : MAX_D_NAME_LEN;
        printf("writing to %p, token %s\n", &list[current], token);
        memcpy(list[current], token, size);
        current += 1;
        token = strtok(NULL, ",");
    }
    return current;
}

void parseargs(int argc, char** argv) {
    unsigned int error_count = 0;
    int opt = 0;
    int long_index = 0;
    // static struct option long_options[] = {};
    static struct option long_options[] = {{"help", no_argument, NULL, 'h'},
                                           {"uids", required_argument, NULL, 'u'},
                                           {"files", required_argument, NULL, 'l'},
                                           {"bins", required_argument, NULL, 'b'},
                                           {NULL, 0, NULL, 0}};

    while ((opt = getopt_long_only(argc, argv, ":hvu:l:b:", long_options, &long_index)) != -1) {
        switch (opt) {
            case 'b':
                parse_file_list(optarg, config.bins_to_hide);
                break;
            case 'l':
                parse_file_list(optarg, config.files_to_hide);
                break;
            case 'u':
                parse_uid_list(optarg);
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

int main(int argc, char** argv) {
    memset(&config.watched_uids, 0xFF, sizeof(unsigned int) * MAX_UIDS);
    memset(&config.files_to_hide, 0x00, sizeof(config.files_to_hide));
    memset(&config.bins_to_hide, 0x00, sizeof(config.bins_to_hide));

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
    watch_uids(find_map_from_name(elf_obj, "uids_to_watch"));
    hide_files(find_map_from_name(elf_obj, "files_to_hide_hm"));
    mute_system_bins(find_map_from_name(elf_obj, "tasks_to_mute"));
    attach_programs(elf_obj);
    read_from_trace_pipe();

    return 0;
}