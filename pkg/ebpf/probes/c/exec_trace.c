// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//
// exec_trace.c — eBPF program for monitoring process execution.
//
// Attaches to the sys_enter_execve tracepoint to capture every new process
// spawned on the node.  The observer userspace component uses these events
// to detect AI-related processes (python running openai SDK, ollama server,
// llama.cpp inference, etc.) and attribute network connections back to the
// originating workload.
//
// Build (reference):
//   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
//     -I/usr/include/bpf -I/usr/include \
//     -c exec_trace.c -o exec_trace.o

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#define TASK_COMM_LEN 16

// Maximum filename length captured.
#define MAX_FILENAME_LEN 256

// Maximum number of argv entries captured (first 6).
#define MAX_ARGS      6

// Maximum length of each argument string.
#define MAX_ARG_LEN   128

// Event type tag.
#define EVENT_EXEC    5

// ---------------------------------------------------------------------------
// Event structure
// ---------------------------------------------------------------------------

struct exec_event_t {
    __u64 timestamp_ns;

    // Process identity.
    __u32 pid;
    __u32 ppid;     // parent PID
    __u32 uid;
    __u32 gid;
    char  comm[TASK_COMM_LEN];

    // Executable path.
    char filename[MAX_FILENAME_LEN];

    // First MAX_ARGS arguments.
    char argv[MAX_ARGS][MAX_ARG_LEN];
    __u8 argc;   // actual number of arguments captured

    __u8 event_type;  // EVENT_EXEC
};

// ---------------------------------------------------------------------------
// Maps
// ---------------------------------------------------------------------------

// Ring buffer for exec events.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} exec_events SEC(".maps");

// Per-CPU scratch for building events (struct is too large for BPF stack).
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct exec_event_t);
} exec_scratch SEC(".maps");

// Configuration map.
// Key 0: enabled (0/1).
// Key 1: filter mode — 0 = capture all, 1 = only AI-related binaries.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} exec_config SEC(".maps");

// AI binary name filter set.  The key is the binary basename (e.g.
// "python3"), value is 1 if it should be captured.  Populated by
// the userspace loader at startup.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, char[TASK_COMM_LEN]);
    __type(value, __u8);
} ai_binary_filter SEC(".maps");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// extract_basename finds the last '/' in the filename and returns a
// pointer past it.  On the BPF stack we cannot do arbitrary string
// manipulation, so we do a bounded reverse scan.
//
// Note: This is a best-effort helper.  The userspace parser also extracts
// the basename for definitive matching.
static __always_inline bool is_filtered_binary(const char *comm) {
    __u32 key_mode = 1;
    __u64 *mode = bpf_map_lookup_elem(&exec_config, &key_mode);
    if (!mode || *mode == 0)
        return true;  // capture-all mode

    // Check if comm is in the AI binary filter set.
    __u8 *found = bpf_map_lookup_elem(&ai_binary_filter, comm);
    return found != NULL;
}

// ---------------------------------------------------------------------------
// Tracepoint program: sys_enter_execve
// ---------------------------------------------------------------------------
//
// The tracepoint context for sys_enter_execve provides:
//   const char *filename     — path to the executable
//   const char *const *argv  — argument vector
//   const char *const *envp  — environment (we skip this)

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint_sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    // Check enabled flag.
    __u32 key_enabled = 0;
    __u64 *enabled = bpf_map_lookup_elem(&exec_config, &key_enabled);
    if (enabled && *enabled == 0)
        return 0;

    // Use per-CPU scratch to build the event.
    __u32 zero = 0;
    struct exec_event_t *evt = bpf_map_lookup_elem(&exec_scratch, &zero);
    if (!evt)
        return 0;

    // Zero the struct.
    __builtin_memset(evt, 0, sizeof(*evt));

    // Process identity.
    evt->timestamp_ns = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->pid = pid_tgid >> 32;
    evt->uid = (__u32)bpf_get_current_uid_gid();
    evt->gid = (__u32)(bpf_get_current_uid_gid() >> 32);
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    evt->event_type = EVENT_EXEC;

    // Parent PID — read from current task_struct.
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    evt->ppid = BPF_CORE_READ(task, real_parent, tgid);

    // Read filename from syscall arguments.
    // args[0] = filename pointer for execve.
    const char *filename_ptr = (const char *)ctx->args[0];
    if (filename_ptr)
        bpf_probe_read_user_str(&evt->filename, sizeof(evt->filename),
                                filename_ptr);

    // Read argv — args[1] is the argv pointer array.
    const char *const *argv = (const char *const *)ctx->args[1];
    if (!argv)
        goto submit;

    // Read up to MAX_ARGS argument strings.
    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        const char *arg_ptr = NULL;
        int ret = bpf_probe_read_user(&arg_ptr, sizeof(arg_ptr),
                                      &argv[i]);
        if (ret != 0 || !arg_ptr)
            break;

        bpf_probe_read_user_str(&evt->argv[i], MAX_ARG_LEN, arg_ptr);
        evt->argc = i + 1;
    }

submit:
    // Apply binary filter.
    if (!is_filtered_binary(evt->comm))
        return 0;

    bpf_ringbuf_output(&exec_events, evt, sizeof(*evt), 0);
    return 0;
}

// ---------------------------------------------------------------------------
// Tracepoint: sched_process_exec (alternative attachment point)
// ---------------------------------------------------------------------------
//
// sched_process_exec fires after the kernel has committed to the new binary.
// At this point task->comm already reflects the new executable name, making
// filtering more reliable.

SEC("tp_btf/sched_process_exec")
int BPF_PROG(sched_process_exec, struct task_struct *task,
             pid_t old_pid, struct linux_binprm *bprm) {
    __u32 key_enabled = 0;
    __u64 *enabled = bpf_map_lookup_elem(&exec_config, &key_enabled);
    if (enabled && *enabled == 0)
        return 0;

    __u32 zero = 0;
    struct exec_event_t *evt = bpf_map_lookup_elem(&exec_scratch, &zero);
    if (!evt)
        return 0;

    __builtin_memset(evt, 0, sizeof(*evt));

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->pid  = BPF_CORE_READ(task, tgid);
    evt->ppid = BPF_CORE_READ(task, real_parent, tgid);
    evt->uid  = BPF_CORE_READ(task, cred, uid.val);
    evt->gid  = BPF_CORE_READ(task, cred, gid.val);
    evt->event_type = EVENT_EXEC;

    // Read comm from the task struct (already updated to new binary).
    BPF_CORE_READ_STR_INTO(&evt->comm, task, comm);

    // Read the full executable path from bprm->filename.
    const char *fname = BPF_CORE_READ(bprm, filename);
    if (fname)
        bpf_probe_read_kernel_str(&evt->filename, sizeof(evt->filename),
                                  fname);

    // Apply binary filter.
    if (!is_filtered_binary(evt->comm))
        return 0;

    bpf_ringbuf_output(&exec_events, evt, sizeof(*evt), 0);
    return 0;
}

// ---------------------------------------------------------------------------
// Tracepoint: sched_process_exit — track AI process termination.
// ---------------------------------------------------------------------------

#define EVENT_EXIT 6

struct exit_event_t {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 ppid;
    __s32 exit_code;
    char  comm[TASK_COMM_LEN];
    __u8  event_type;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} exit_events SEC(".maps");

SEC("tracepoint/sched/sched_process_exit")
int tracepoint_sched_process_exit(struct trace_event_raw_sched_process_template *ctx) {
    __u32 key_enabled = 0;
    __u64 *enabled = bpf_map_lookup_elem(&exec_config, &key_enabled);
    if (enabled && *enabled == 0)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    struct exit_event_t evt = {};
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.pid  = bpf_get_current_pid_tgid() >> 32;
    evt.ppid = BPF_CORE_READ(task, real_parent, tgid);
    evt.exit_code = BPF_CORE_READ(task, exit_code) >> 8;
    evt.event_type = EVENT_EXIT;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    // Only emit for known AI binaries.
    if (!is_filtered_binary(evt.comm))
        return 0;

    bpf_ringbuf_output(&exit_events, &evt, sizeof(evt), 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
