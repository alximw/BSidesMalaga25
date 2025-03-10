
#define MAX_UIDS 10
#define MAX_PORTS 10
#define MAX_COMM_LEN 128

enum net_function_name {
    TCP_SENDMSG,
    UDP_SENDMSG,
};

struct ctx {
    uint32_t pid;
    uint32_t uid;
    char comm[MAX_COMM_LEN];
};

struct net_event {
    uint8_t isIPv6;
    uint32_t protocol;
    uint32_t src_port;
    uint32_t src_ip4;
    uint32_t dst_port;
    uint32_t dst_ip4;
    uint32_t src_ip6[4];
    uint32_t dst_ip6[4];
    enum net_function_name fname;
    struct ctx proc_ctx;
};

static const char* const syscall_names_str[] = {
    [TCP_SENDMSG] = "tcp_sendmsg", [UDP_SENDMSG] = "udp_sendmsg"};
