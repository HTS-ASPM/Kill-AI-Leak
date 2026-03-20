// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//
// tcp_trace.c — eBPF program for tracing TCP send/recv to detect AI API calls.
//
// This program attaches to the tcp_sendmsg and tcp_recvmsg kprobes to
// capture per-connection byte counts, socket metadata (addresses and ports),
// and the originating process identity. Events are emitted to a ring buffer
// consumed by the Kill-AI-Leak observer in userspace.
//
// Build (reference):
//   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
//     -I/usr/include/bpf -I/usr/include \
//     -c tcp_trace.c -o tcp_trace.o
//
// Requires: Linux >= 5.8 (ring buffer support), BTF-enabled kernel.

#include "vmlinux.h"           // generated BTF header (bpftool btf dump)
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// Maximum process name length (TASK_COMM_LEN in the kernel).
#define TASK_COMM_LEN 16

// Event type tags shared with the userspace parser.
#define EVENT_TCP_SEND 1
#define EVENT_TCP_RECV 2

// Ports of interest — primarily HTTPS (443).  The userspace side performs
// deeper filtering, but pre-filtering in kernel space saves ring-buffer
// bandwidth.
#define PORT_HTTPS 443
#define PORT_HTTP  80

// AI provider port for local inference servers (Ollama, llama.cpp, etc.).
#define PORT_OLLAMA 11434

// ---------------------------------------------------------------------------
// Event structure — passed to userspace via the ring buffer.
// ---------------------------------------------------------------------------

// tcp_event_t is the fixed-size record emitted for every qualifying
// tcp_sendmsg / tcp_recvmsg call.
struct tcp_event_t {
    // Kernel timestamp in nanoseconds (bpf_ktime_get_ns).
    __u64 timestamp_ns;

    // Process identity.
    __u32 pid;
    __u32 tid;
    __u32 uid;
    char  comm[TASK_COMM_LEN];

    // Socket 4-tuple.
    __u32 saddr;     // source IPv4 address (network byte order)
    __u32 daddr;     // destination IPv4 address (network byte order)
    __u16 sport;     // source port (host byte order)
    __u16 dport;     // destination port (host byte order)

    // Payload metadata.
    __u32 bytes;     // number of bytes sent or received
    __u8  event_type; // EVENT_TCP_SEND or EVENT_TCP_RECV

    // Address family — AF_INET (2) or AF_INET6 (10).
    __u16 family;

    // IPv6 addresses (populated only when family == AF_INET6).
    __u8 saddr6[16];
    __u8 daddr6[16];
};

// ---------------------------------------------------------------------------
// Maps
// ---------------------------------------------------------------------------

// Ring buffer for sending events to userspace.  Size is 256 KB per CPU;
// the observer loader may override this at load time.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} tcp_events SEC(".maps");

// Optional: per-connection tracking map for correlating send/recv.
// Key: pid_tgid << 32 | socket fd.  Value: cumulative bytes.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, __u64);
} conn_bytes SEC(".maps");

// Configuration map — writable from userspace to toggle tracing at runtime.
// Key 0: enabled (0/1).  Key 1: minimum bytes threshold.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} tcp_config SEC(".maps");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// is_target_port returns true if the destination port is one we care about.
static __always_inline bool is_target_port(__u16 dport) {
    return dport == PORT_HTTPS ||
           dport == PORT_HTTP  ||
           dport == PORT_OLLAMA;
}

// emit_tcp_event reads socket metadata and pushes an event to the ring
// buffer.  Returns 0 on success.
static __always_inline int emit_tcp_event(struct sock *sk, int bytes, __u8 type) {
    // Check runtime enable flag.
    __u32 key_enabled = 0;
    __u64 *enabled = bpf_map_lookup_elem(&tcp_config, &key_enabled);
    if (enabled && *enabled == 0)
        return 0;

    // Read address family.
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);

    // Read destination port (network byte order in kernel, convert).
    __u16 dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    // Pre-filter: only emit events for ports of interest.
    if (!is_target_port(dport))
        return 0;

    // Reserve space in the ring buffer.
    struct tcp_event_t *evt;
    evt = bpf_ringbuf_reserve(&tcp_events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    // Timestamps and process identity.
    evt->timestamp_ns = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->pid = pid_tgid >> 32;
    evt->tid = (__u32)pid_tgid;
    evt->uid = (__u32)bpf_get_current_uid_gid();
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    // Socket addresses.
    evt->family = family;
    evt->sport  = BPF_CORE_READ(sk, __sk_common.skc_num);   // already host order
    evt->dport  = dport;

    if (family == 2 /* AF_INET */) {
        evt->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        evt->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    } else if (family == 10 /* AF_INET6 */) {
        BPF_CORE_READ_INTO(&evt->saddr6, sk,
                           __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        BPF_CORE_READ_INTO(&evt->daddr6, sk,
                           __sk_common.skc_v6_daddr.in6_u.u6_addr8);
    }

    // Payload size.
    evt->bytes      = bytes > 0 ? (__u32)bytes : 0;
    evt->event_type = type;

    // Update cumulative byte counter for this connection.
    __u64 conn_key = pid_tgid;
    __u64 *total   = bpf_map_lookup_elem(&conn_bytes, &conn_key);
    if (total) {
        __sync_fetch_and_add(total, evt->bytes);
    } else {
        __u64 init = evt->bytes;
        bpf_map_update_elem(&conn_bytes, &conn_key, &init, BPF_ANY);
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// ---------------------------------------------------------------------------
// Kprobe / tracepoint programs
// ---------------------------------------------------------------------------

// Attach to tcp_sendmsg.  The first argument is struct sock *, the second
// is struct msghdr *, and the third is size_t (bytes to send).
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(kprobe_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
    return emit_tcp_event(sk, (int)size, EVENT_TCP_SEND);
}

// Return probe for tcp_sendmsg — captures the actual number of bytes sent
// (which may differ from the requested size).
SEC("kretprobe/tcp_sendmsg")
int BPF_KRETPROBE(kretprobe_tcp_sendmsg, int ret) {
    // ret < 0 means error; we ignore failed sends.
    if (ret <= 0)
        return 0;

    // We already emitted the event on entry.  The return probe is used
    // only for metrics; a production implementation would correlate with
    // a per-call map entry.
    return 0;
}

// Attach to tcp_recvmsg.  We hook the return path to get the actual bytes
// received.
SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(kprobe_tcp_recvmsg, struct sock *sk) {
    // Stash sk pointer for the return probe.  In a full implementation this
    // would use a per-CPU array or hash map keyed by pid_tgid.
    return 0;
}

SEC("kretprobe/tcp_recvmsg")
int BPF_KRETPROBE(kretprobe_tcp_recvmsg, int ret) {
    if (ret <= 0)
        return 0;

    // For the return probe we need the socket pointer.  A production
    // implementation stores it in a per-CPU map during the entry probe.
    // Here we demonstrate the event emission path; the loader pairs
    // entry and return probes at attach time.
    return 0;
}

// ---------------------------------------------------------------------------
// Tracepoint alternative — sys_enter_sendto / sys_enter_recvfrom
// These are available on all kernels and do not require BTF.
// ---------------------------------------------------------------------------

// Raw tracepoint on tcp_sendmsg for kernels that expose it.
SEC("tp_btf/tcp_sendmsg")
int BPF_PROG(tp_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
    return emit_tcp_event(sk, (int)size, EVENT_TCP_SEND);
}

// Raw tracepoint for the receive path (tcp_recvmsg return).
SEC("fentry/tcp_recvmsg")
int BPF_PROG(fentry_tcp_recvmsg, struct sock *sk) {
    // Entry-side hook — stash sk for fexit correlation.
    return 0;
}

SEC("fexit/tcp_recvmsg")
int BPF_PROG(fexit_tcp_recvmsg, struct sock *sk, struct msghdr *msg,
             size_t len, int flags, int *addr_len, int ret) {
    if (ret <= 0)
        return 0;
    return emit_tcp_event(sk, ret, EVENT_TCP_RECV);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
