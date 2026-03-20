// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//
// ssl_trace.c — eBPF uprobes for intercepting TLS plaintext via OpenSSL.
//
// Attaches to SSL_write and SSL_read in libssl.so to capture data before
// encryption and after decryption.  This gives the Kill-AI-Leak observer
// visibility into HTTPS traffic (AI API calls) without terminating TLS.
//
// Build (reference):
//   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
//     -I/usr/include/bpf -I/usr/include \
//     -c ssl_trace.c -o ssl_trace.o
//
// Attachment (userspace):
//   The loader resolves the symbol offsets for SSL_write / SSL_read in
//   the target process's libssl.so and attaches uprobes + uretprobes.
//
// Requires: Linux >= 5.8, BTF (optional but recommended).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#define TASK_COMM_LEN     16

// Maximum number of plaintext bytes captured per SSL_write / SSL_read.
// Default 4 KB; the userspace loader can override via the config map.
#define MAX_CAPTURE_BYTES 4096

// Chunk size for bpf_probe_read_user — must be a compile-time constant
// to satisfy the verifier's stack-size limits.  We read in 512-byte
// chunks and append to the ring-buffer entry.
#define CHUNK_SIZE        512

// Event type tags.
#define EVENT_SSL_WRITE   3
#define EVENT_SSL_READ    4

// ---------------------------------------------------------------------------
// Event structure
// ---------------------------------------------------------------------------

// ssl_event_t is emitted for every SSL_write / SSL_read that passes
// the userspace-configurable size threshold.
struct ssl_event_t {
    __u64 timestamp_ns;

    __u32 pid;
    __u32 tid;
    __u32 uid;
    char  comm[TASK_COMM_LEN];

    __u8  event_type;   // EVENT_SSL_WRITE or EVENT_SSL_READ

    // Total plaintext length passed to SSL_write / returned by SSL_read.
    __u32 data_len;

    // Number of bytes actually captured (min(data_len, MAX_CAPTURE_BYTES)).
    __u32 captured_len;

    // Captured plaintext bytes.  We store up to MAX_CAPTURE_BYTES so the
    // userspace parser can extract HTTP headers + partial body.
    __u8  data[MAX_CAPTURE_BYTES];
};

// ---------------------------------------------------------------------------
// Maps
// ---------------------------------------------------------------------------

// Ring buffer for SSL events.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);  // 1 MB
} ssl_events SEC(".maps");

// Scratch map for building events — the ssl_event_t struct is too large
// for the BPF stack (512 bytes max).  We use a per-CPU array as scratch.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ssl_event_t);
} ssl_scratch SEC(".maps");

// Stash map: SSL_write / SSL_read entry probes store the buffer pointer
// and length here so the return probe can read the actual data.
// Key: pid_tgid.  Value: struct ssl_args_t.
struct ssl_args_t {
    const void *buf;
    __u32       len;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct ssl_args_t);
} ssl_args_map SEC(".maps");

// Configuration map.
// Key 0: enabled (0 = off, 1 = on).
// Key 1: max capture bytes (overrides MAX_CAPTURE_BYTES at runtime).
// Key 2: minimum data_len threshold — skip small TLS records.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} ssl_config SEC(".maps");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static __always_inline __u32 get_max_capture(void) {
    __u32 key = 1;
    __u64 *val = bpf_map_lookup_elem(&ssl_config, &key);
    if (val && *val > 0 && *val <= MAX_CAPTURE_BYTES)
        return (__u32)*val;
    return MAX_CAPTURE_BYTES;
}

static __always_inline __u32 get_min_threshold(void) {
    __u32 key = 2;
    __u64 *val = bpf_map_lookup_elem(&ssl_config, &key);
    if (val && *val > 0)
        return (__u32)*val;
    return 0;  // capture everything by default
}

// emit_ssl_event reads the plaintext buffer and submits an event.
// Called from the return probe after we know the call succeeded.
static __always_inline int emit_ssl_event(const void *buf, __u32 data_len, __u8 type) {
    // Check enabled flag.
    __u32 key_enabled = 0;
    __u64 *enabled = bpf_map_lookup_elem(&ssl_config, &key_enabled);
    if (enabled && *enabled == 0)
        return 0;

    // Skip tiny records (TLS alerts, etc.).
    __u32 min_threshold = get_min_threshold();
    if (data_len < min_threshold)
        return 0;

    // Use the per-CPU scratch space.
    __u32 zero = 0;
    struct ssl_event_t *evt = bpf_map_lookup_elem(&ssl_scratch, &zero);
    if (!evt)
        return 0;

    // Zero the data area to prevent leaking old data.
    __builtin_memset(evt->data, 0, MAX_CAPTURE_BYTES);

    // Fill process metadata.
    evt->timestamp_ns = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->pid = pid_tgid >> 32;
    evt->tid = (__u32)pid_tgid;
    evt->uid = (__u32)bpf_get_current_uid_gid();
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    evt->event_type = type;
    evt->data_len   = data_len;

    // Determine capture length.
    __u32 max_cap = get_max_capture();
    __u32 to_copy = data_len < max_cap ? data_len : max_cap;
    evt->captured_len = to_copy;

    // Read plaintext from userspace.  The bpf_probe_read_user call must
    // use a constant or bounded size for the verifier.  We read in fixed
    // chunks to stay within limits.
    //
    // Chunk 0: bytes [0, 512).
    if (to_copy > 0) {
        __u32 n = to_copy < CHUNK_SIZE ? to_copy : CHUNK_SIZE;
        bpf_probe_read_user(&evt->data[0], n, buf);
    }
    // Chunk 1: bytes [512, 1024).
    if (to_copy > CHUNK_SIZE) {
        __u32 n = (to_copy - CHUNK_SIZE) < CHUNK_SIZE
                      ? (to_copy - CHUNK_SIZE)
                      : CHUNK_SIZE;
        bpf_probe_read_user(&evt->data[CHUNK_SIZE], n, buf + CHUNK_SIZE);
    }
    // Chunk 2: bytes [1024, 1536).
    if (to_copy > 2 * CHUNK_SIZE) {
        __u32 n = (to_copy - 2 * CHUNK_SIZE) < CHUNK_SIZE
                      ? (to_copy - 2 * CHUNK_SIZE)
                      : CHUNK_SIZE;
        bpf_probe_read_user(&evt->data[2 * CHUNK_SIZE], n,
                            buf + 2 * CHUNK_SIZE);
    }
    // Chunk 3: bytes [1536, 2048).
    if (to_copy > 3 * CHUNK_SIZE) {
        __u32 n = (to_copy - 3 * CHUNK_SIZE) < CHUNK_SIZE
                      ? (to_copy - 3 * CHUNK_SIZE)
                      : CHUNK_SIZE;
        bpf_probe_read_user(&evt->data[3 * CHUNK_SIZE], n,
                            buf + 3 * CHUNK_SIZE);
    }
    // Chunk 4: bytes [2048, 2560).
    if (to_copy > 4 * CHUNK_SIZE) {
        __u32 n = (to_copy - 4 * CHUNK_SIZE) < CHUNK_SIZE
                      ? (to_copy - 4 * CHUNK_SIZE)
                      : CHUNK_SIZE;
        bpf_probe_read_user(&evt->data[4 * CHUNK_SIZE], n,
                            buf + 4 * CHUNK_SIZE);
    }
    // Chunk 5: bytes [2560, 3072).
    if (to_copy > 5 * CHUNK_SIZE) {
        __u32 n = (to_copy - 5 * CHUNK_SIZE) < CHUNK_SIZE
                      ? (to_copy - 5 * CHUNK_SIZE)
                      : CHUNK_SIZE;
        bpf_probe_read_user(&evt->data[5 * CHUNK_SIZE], n,
                            buf + 5 * CHUNK_SIZE);
    }
    // Chunk 6: bytes [3072, 3584).
    if (to_copy > 6 * CHUNK_SIZE) {
        __u32 n = (to_copy - 6 * CHUNK_SIZE) < CHUNK_SIZE
                      ? (to_copy - 6 * CHUNK_SIZE)
                      : CHUNK_SIZE;
        bpf_probe_read_user(&evt->data[6 * CHUNK_SIZE], n,
                            buf + 6 * CHUNK_SIZE);
    }
    // Chunk 7: bytes [3584, 4096).
    if (to_copy > 7 * CHUNK_SIZE) {
        __u32 n = (to_copy - 7 * CHUNK_SIZE) < CHUNK_SIZE
                      ? (to_copy - 7 * CHUNK_SIZE)
                      : CHUNK_SIZE;
        bpf_probe_read_user(&evt->data[7 * CHUNK_SIZE], n,
                            buf + 7 * CHUNK_SIZE);
    }

    // Submit to ring buffer.  We copy only the header + captured bytes
    // to minimise ring-buffer usage.
    __u64 event_size = (__u64)(
        sizeof(struct ssl_event_t) - MAX_CAPTURE_BYTES + to_copy);
    bpf_ringbuf_output(&ssl_events, evt, event_size, 0);

    return 0;
}

// ---------------------------------------------------------------------------
// Uprobe programs — SSL_write
// ---------------------------------------------------------------------------

// SSL_write entry: int SSL_write(SSL *ssl, const void *buf, int num)
// We stash the buffer pointer and length for the return probe.
SEC("uprobe/SSL_write")
int BPF_UPROBE(uprobe_ssl_write, void *ssl, const void *buf, int num) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_args_t args = {
        .buf = buf,
        .len = (__u32)num,
    };
    bpf_map_update_elem(&ssl_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

// SSL_write return: the return value is the number of bytes written.
SEC("uretprobe/SSL_write")
int BPF_URETPROBE(uretprobe_ssl_write, int ret) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_args_t *args = bpf_map_lookup_elem(&ssl_args_map, &pid_tgid);
    if (!args)
        return 0;

    // Capture the stashed values before deleting the map entry.
    const void *buf = args->buf;
    __u32 len       = args->len;
    bpf_map_delete_elem(&ssl_args_map, &pid_tgid);

    if (ret <= 0)
        return 0;

    // Use the actual bytes written if smaller than the requested length.
    __u32 data_len = (__u32)ret < len ? (__u32)ret : len;
    return emit_ssl_event(buf, data_len, EVENT_SSL_WRITE);
}

// ---------------------------------------------------------------------------
// Uprobe programs — SSL_read
// ---------------------------------------------------------------------------

// SSL_read entry: int SSL_read(SSL *ssl, void *buf, int num)
// Stash the output buffer pointer so the return probe can read from it.
SEC("uprobe/SSL_read")
int BPF_UPROBE(uprobe_ssl_read, void *ssl, void *buf, int num) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_args_t args = {
        .buf = buf,
        .len = (__u32)num,
    };
    bpf_map_update_elem(&ssl_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

// SSL_read return: ret is the number of bytes read (decrypted plaintext).
SEC("uretprobe/SSL_read")
int BPF_URETPROBE(uretprobe_ssl_read, int ret) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_args_t *args = bpf_map_lookup_elem(&ssl_args_map, &pid_tgid);
    if (!args)
        return 0;

    const void *buf = args->buf;
    bpf_map_delete_elem(&ssl_args_map, &pid_tgid);

    if (ret <= 0)
        return 0;

    return emit_ssl_event(buf, (__u32)ret, EVENT_SSL_READ);
}

// ---------------------------------------------------------------------------
// GnuTLS support (optional, same pattern)
// ---------------------------------------------------------------------------

// gnutls_record_send entry.
SEC("uprobe/gnutls_record_send")
int BPF_UPROBE(uprobe_gnutls_send, void *session, const void *data, __u32 len) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_args_t args = { .buf = data, .len = len };
    bpf_map_update_elem(&ssl_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/gnutls_record_send")
int BPF_URETPROBE(uretprobe_gnutls_send, int ret) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_args_t *args = bpf_map_lookup_elem(&ssl_args_map, &pid_tgid);
    if (!args) return 0;
    const void *buf = args->buf;
    bpf_map_delete_elem(&ssl_args_map, &pid_tgid);
    if (ret <= 0) return 0;
    return emit_ssl_event(buf, (__u32)ret, EVENT_SSL_WRITE);
}

// gnutls_record_recv entry.
SEC("uprobe/gnutls_record_recv")
int BPF_UPROBE(uprobe_gnutls_recv, void *session, void *data, __u32 len) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_args_t args = { .buf = data, .len = len };
    bpf_map_update_elem(&ssl_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/gnutls_record_recv")
int BPF_URETPROBE(uretprobe_gnutls_recv, int ret) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_args_t *args = bpf_map_lookup_elem(&ssl_args_map, &pid_tgid);
    if (!args) return 0;
    const void *buf = args->buf;
    bpf_map_delete_elem(&ssl_args_map, &pid_tgid);
    if (ret <= 0) return 0;
    return emit_ssl_event(buf, (__u32)ret, EVENT_SSL_READ);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
