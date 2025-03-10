#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <vmlinux.h>

#include "network_monitor.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";
/* we could as well use an array here but
lookups are faster on a hashmap */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u16));
    __uint(value_size, sizeof(__u16));
    __uint(max_entries, MAX_UIDS);
} uids_to_watch SEC(".maps");

/* hashmap for tcp ports */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u16));
    __uint(value_size, sizeof(__u16));
    __uint(max_entries, MAX_PORTS);
} tcp_ports SEC(".maps");

/* hashmap for udp ports */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u16));
    __uint(value_size, sizeof(__u16));
    __uint(max_entries, MAX_PORTS);
} udp_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 2);
} network_events SEC(".maps");

/* decide if we should hook the current process based on its uid */
static bool should_hook() {
    u32 uid = (bpf_get_current_uid_gid() & 0x00000000FFFFFFFF);
    u32* value = bpf_map_lookup_elem(&uids_to_watch, &uid);
    return value != NULL;
}
/* decide if we should hook the current process based on its uid */
static bool is_monitored_port(__u16 port, bool udp) {
    u16* value = NULL;
    if (udp) {
        value = bpf_map_lookup_elem(&udp_ports, &port);
    } else {
        value = bpf_map_lookup_elem(&tcp_ports, &port);
    }
    return value != NULL;
}

static inline __attribute__((always_inline)) void report_net_event(struct pt_regs* ctx,
                                                                   struct net_event* event) {
    int error = bpf_perf_event_output(ctx, &network_events, 0, event, sizeof(struct net_event));
}

static inline __attribute__((always_inline)) void handle_smsg(struct pt_regs* ctx, struct sock* sock,
                                                              enum net_function_name fname,
                                                              bool is_udp) {
    struct net_event event = {0};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 uid = (bpf_get_current_uid_gid() & 0x00000000FFFFFFFF);
    event.fname = fname;
    u16 family, lport, dport;

    bpf_probe_read(&dport, sizeof(dport), &sock->__sk_common.skc_dport);
    dport = bpf_ntohs(dport);
    if (!is_monitored_port(dport, is_udp)) {
        // bpf_printk("ignoring %d", dport);
        return;
    }
    bpf_probe_read(&lport, sizeof(lport), &sock->__sk_common.skc_num);
    bpf_probe_read(&family, sizeof(family), &sock->__sk_common.skc_family);
    if (!is_udp) {
        event.protocol = IPPROTO_TCP;
    } else {
        event.protocol = IPPROTO_UDP;
    }

    event.src_port = bpf_ntohs(lport);
    event.dst_port = dport;
    switch (family) {
        case 0x10:
            // bpf_printk("IPV6");
            event.isIPv6 = 1;
            u32 src_ip6[4], dst_ip6[4];
            bpf_probe_read(&src_ip6, sizeof(src_ip6), &sock->__sk_common.skc_v6_rcv_saddr);
            bpf_probe_read(&dst_ip6, sizeof(dst_ip6), &sock->__sk_common.skc_v6_daddr);
            __builtin_memcpy(event.src_ip6, src_ip6, sizeof(src_ip6));
            __builtin_memcpy(event.dst_ip6, dst_ip6, sizeof(dst_ip6));
            break;
        case 0x2:
            // bpf_printk("IPV4");
            u32 src_ip4, dst_ip4;
            bpf_probe_read(&src_ip4, sizeof(src_ip4), &sock->__sk_common.skc_rcv_saddr);
            bpf_probe_read(&dst_ip4, sizeof(dst_ip4), &sock->__sk_common.skc_daddr);
            event.src_ip4 = src_ip4;
            event.dst_ip4 = dst_ip4;
            break;
        default:
            break;
    }
    struct ctx fctx;
    fctx.pid = pid;
    fctx.uid = uid;
    bpf_get_current_comm(&fctx.comm, sizeof(fctx.comm));
    event.proc_ctx = fctx;

    report_net_event(ctx, &event);
}

SEC("kprobe/tcp_sendmsg") int tcp_sendmsg(struct pt_regs* ctx) {
    if (!should_hook()) return 0;
    bpf_printk("kprobe/tcp_sendmsg");
    struct sock* sk = (struct sock*)PT_REGS_PARM1(ctx);
    if (sk == NULL) {
        return 0;
    }
    handle_smsg(ctx, sk, UDP_SENDMSG, false);
    return 0;
};

SEC("kprobe/udp_sendmsg")
int udp_sendmsg(struct pt_regs* ctx) {
    if (!should_hook()) return 0;
    bpf_printk("kprobe/udp_sendmsg");
    struct sock* sk = (struct sock*)PT_REGS_PARM1(ctx);
    handle_smsg(ctx, sk, UDP_SENDMSG, true);
    return 0;
};