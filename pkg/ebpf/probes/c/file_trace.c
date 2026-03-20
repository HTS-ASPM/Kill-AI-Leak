// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//
// file_trace.c — eBPF program for monitoring file access to AI model and
// credential files.
//
// Attaches to the sys_enter_openat tracepoint to capture every openat(2)
// call.  The userspace observer filters for:
//   - AI model files: .gguf, .safetensors, .pt, .pth, .onnx, .bin, .h5,
//     .tflite, .mlmodel, .pb
//   - Credential/config files: .env, credentials, keys, tokens
//
// Kernel-side filtering uses a suffix hash map to reduce ring-buffer traffic.
//
// Build (reference):
//   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
//     -I/usr/include/bpf -I/usr/include \
//     -c file_trace.c -o file_trace.o

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#define TASK_COMM_LEN    16
#define MAX_FILENAME_LEN 256
#define EVENT_FILE_OPEN  7

// File extension hash constants (FNV-1a 32-bit).
#define FNV_OFFSET 2166136261u
#define FNV_PRIME  16777619u

// Maximum suffix length we check.
#define MAX_SUFFIX_LEN 16

// openat flags we care about.
#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR   2

// ---------------------------------------------------------------------------
// Event structure
// ---------------------------------------------------------------------------

struct file_event_t {
    __u64 timestamp_ns;

    __u32 pid;
    __u32 tid;
    __u32 uid;
    char  comm[TASK_COMM_LEN];

    // File being opened.
    char  filename[MAX_FILENAME_LEN];

    // openat flags (O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, etc.).
    __u32 flags;

    // dirfd passed to openat(2).  AT_FDCWD (-100) means current dir.
    __s32 dirfd;

    // Classification determined by kernel-side filtering.
    // 0 = unclassified, 1 = model file, 2 = credential file.
    __u8 file_class;

    __u8 event_type;  // EVENT_FILE_OPEN
};

// ---------------------------------------------------------------------------
// Maps
// ---------------------------------------------------------------------------

// Ring buffer for file events.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} file_events SEC(".maps");

// Per-CPU scratch space.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct file_event_t);
} file_scratch SEC(".maps");

// Configuration map.
// Key 0: enabled (0/1).
// Key 1: filter mode — 0 = capture all openat calls (very noisy),
//         1 = only AI model + credential files (recommended).
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} file_config SEC(".maps");

// Suffix filter set.  The key is a file extension string (e.g. ".gguf"),
// the value encodes the file class (1 = model, 2 = credential).
// Populated by the userspace loader at startup.
#define SUFFIX_KEY_LEN 16

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, char[SUFFIX_KEY_LEN]);
    __type(value, __u8);
} suffix_filter SEC(".maps");

// Full-path substring filter for credential files that don't rely on
// extension (e.g. "credentials", ".env", "authorized_keys").
// Key: substring.  Value: file class.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, char[32]);
    __type(value, __u8);
} path_filter SEC(".maps");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// find_suffix extracts the last '.' delimited suffix from filename into
// out_suffix.  Returns 0 on success, -1 if no suffix found.
//
// Because BPF verifier requires bounded loops, we scan backwards from
// position MAX_FILENAME_LEN-1 with a fixed iteration count.
static __always_inline int find_suffix(const char *filename, char *out_suffix) {
    int dot_pos = -1;
    int len = 0;

    // Find string length (bounded).
    #pragma unroll
    for (int i = 0; i < MAX_FILENAME_LEN; i++) {
        if (filename[i] == '\0') {
            len = i;
            break;
        }
        if (i == MAX_FILENAME_LEN - 1)
            len = MAX_FILENAME_LEN;
    }

    if (len == 0)
        return -1;

    // Scan backwards for the last '.'.
    #pragma unroll
    for (int i = MAX_FILENAME_LEN - 1; i >= 0; i--) {
        if (i >= len)
            continue;
        if (filename[i] == '/') {
            // Reached a directory separator before finding '.'.
            break;
        }
        if (filename[i] == '.') {
            dot_pos = i;
            break;
        }
    }

    if (dot_pos < 0)
        return -1;

    // Copy suffix to output (including the dot).
    int suffix_len = len - dot_pos;
    if (suffix_len > SUFFIX_KEY_LEN - 1)
        suffix_len = SUFFIX_KEY_LEN - 1;

    __builtin_memset(out_suffix, 0, SUFFIX_KEY_LEN);
    #pragma unroll
    for (int i = 0; i < SUFFIX_KEY_LEN - 1; i++) {
        if (i >= suffix_len)
            break;
        int idx = dot_pos + i;
        if (idx < MAX_FILENAME_LEN)
            out_suffix[i] = filename[idx];
    }

    return 0;
}

// check_path_substring checks the filename against known credential path
// patterns.  Returns the file class (2) if matched, 0 otherwise.
//
// The patterns are stored in the path_filter map, populated by userspace.
// Because we cannot iterate BPF maps from a program, we check a fixed set
// of well-known patterns inline.
static __always_inline __u8 check_credential_patterns(const char *filename,
                                                       int len) {
    // We check for well-known filenames.  The path_filter map provides
    // an extensible set managed by userspace; this inline check is a
    // fast-path for the most critical patterns.
    //
    // Due to BPF verifier constraints, we use fixed-position substring
    // checks.  The userspace parser performs definitive matching.

    // Check for ".env" anywhere in the path.
    #pragma unroll
    for (int i = 0; i < MAX_FILENAME_LEN - 4; i++) {
        if (i >= len) break;
        if (filename[i] == '.' && filename[i+1] == 'e' &&
            filename[i+2] == 'n' && filename[i+3] == 'v') {
            // Verify it's a standalone segment (preceded by / or start).
            if (i == 0 || filename[i-1] == '/')
                return 2;
        }
    }

    // Check for "credentials" in the path.
    #pragma unroll
    for (int i = 0; i < MAX_FILENAME_LEN - 11; i++) {
        if (i >= len) break;
        if (filename[i] == 'c' && filename[i+1] == 'r' &&
            filename[i+2] == 'e' && filename[i+3] == 'd' &&
            filename[i+4] == 'e' && filename[i+5] == 'n' &&
            filename[i+6] == 't' && filename[i+7] == 'i' &&
            filename[i+8] == 'a' && filename[i+9] == 'l' &&
            filename[i+10] == 's')
            return 2;
    }

    return 0;
}

// ---------------------------------------------------------------------------
// Tracepoint: sys_enter_openat
// ---------------------------------------------------------------------------
//
// openat(2) signature: int openat(int dirfd, const char *pathname,
//                                 int flags, mode_t mode)
// Tracepoint args: args[0]=dirfd, args[1]=pathname, args[2]=flags

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint_sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    // Check enabled flag.
    __u32 key_enabled = 0;
    __u64 *enabled = bpf_map_lookup_elem(&file_config, &key_enabled);
    if (enabled && *enabled == 0)
        return 0;

    // Use per-CPU scratch.
    __u32 zero = 0;
    struct file_event_t *evt = bpf_map_lookup_elem(&file_scratch, &zero);
    if (!evt)
        return 0;

    __builtin_memset(evt, 0, sizeof(*evt));

    // Read filename from userspace.
    const char *pathname = (const char *)ctx->args[1];
    if (!pathname)
        return 0;

    int ret = bpf_probe_read_user_str(&evt->filename, sizeof(evt->filename),
                                      pathname);
    if (ret <= 0)
        return 0;

    int path_len = ret - 1;  // bpf_probe_read_user_str includes '\0'.

    // Check filter mode.
    __u32 key_mode = 1;
    __u64 *mode = bpf_map_lookup_elem(&file_config, &key_mode);
    bool filter_enabled = (mode && *mode == 1);

    __u8 file_class = 0;

    if (filter_enabled) {
        // Try suffix-based classification.
        char suffix[SUFFIX_KEY_LEN] = {};
        if (find_suffix(evt->filename, suffix) == 0) {
            __u8 *cls = bpf_map_lookup_elem(&suffix_filter, suffix);
            if (cls)
                file_class = *cls;
        }

        // Try credential pattern matching if not already classified.
        if (file_class == 0)
            file_class = check_credential_patterns(evt->filename, path_len);

        // If nothing matched in filter mode, skip this event.
        if (file_class == 0)
            return 0;
    }

    // Fill process metadata.
    evt->timestamp_ns = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->pid = pid_tgid >> 32;
    evt->tid = (__u32)pid_tgid;
    evt->uid = (__u32)bpf_get_current_uid_gid();
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    evt->dirfd  = (__s32)ctx->args[0];
    evt->flags  = (__u32)ctx->args[2];
    evt->file_class = file_class;
    evt->event_type = EVENT_FILE_OPEN;

    bpf_ringbuf_output(&file_events, evt, sizeof(*evt), 0);
    return 0;
}

// ---------------------------------------------------------------------------
// Tracepoint: sys_enter_openat2 (Linux >= 5.6)
// ---------------------------------------------------------------------------
//
// openat2(2) uses struct open_how; we capture it the same way.

SEC("tracepoint/syscalls/sys_enter_openat2")
int tracepoint_sys_enter_openat2(struct trace_event_raw_sys_enter *ctx) {
    // Reuse the openat handler — the filename is still in args[1].
    // args[0] = dirfd, args[1] = pathname, args[2] = &open_how, args[3] = size.

    __u32 key_enabled = 0;
    __u64 *enabled = bpf_map_lookup_elem(&file_config, &key_enabled);
    if (enabled && *enabled == 0)
        return 0;

    __u32 zero = 0;
    struct file_event_t *evt = bpf_map_lookup_elem(&file_scratch, &zero);
    if (!evt)
        return 0;

    __builtin_memset(evt, 0, sizeof(*evt));

    const char *pathname = (const char *)ctx->args[1];
    if (!pathname)
        return 0;

    int ret = bpf_probe_read_user_str(&evt->filename, sizeof(evt->filename),
                                      pathname);
    if (ret <= 0)
        return 0;

    int path_len = ret - 1;

    __u32 key_mode = 1;
    __u64 *mode = bpf_map_lookup_elem(&file_config, &key_mode);
    bool filter_enabled = (mode && *mode == 1);

    __u8 file_class = 0;
    if (filter_enabled) {
        char suffix[SUFFIX_KEY_LEN] = {};
        if (find_suffix(evt->filename, suffix) == 0) {
            __u8 *cls = bpf_map_lookup_elem(&suffix_filter, suffix);
            if (cls)
                file_class = *cls;
        }
        if (file_class == 0)
            file_class = check_credential_patterns(evt->filename, path_len);
        if (file_class == 0)
            return 0;
    }

    evt->timestamp_ns = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->pid = pid_tgid >> 32;
    evt->tid = (__u32)pid_tgid;
    evt->uid = (__u32)bpf_get_current_uid_gid();
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    evt->dirfd  = (__s32)ctx->args[0];
    evt->flags  = 0;  // Flags are in the open_how struct; read separately if needed.
    evt->file_class = file_class;
    evt->event_type = EVENT_FILE_OPEN;

    bpf_ringbuf_output(&file_events, evt, sizeof(*evt), 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
