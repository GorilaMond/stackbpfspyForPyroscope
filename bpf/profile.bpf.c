// SPDX-License-Identifier: GPL-2.0-only

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "profile.bpf.h"
#include "pid.h"
#include "ume.h"

#define PF_KTHREAD 0x00200000

SEC("perf_event")
int do_perf_event(struct bpf_perf_event_data *ctx) {
    u32 tgid = 0;
    current_pid(&tgid);

    struct sample_key key = {};
    u32 *val, one = 1;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (tgid == 0 || task == 0) { // 不监测0号进程
        return 0;
    }
    int flags = 0;
    if (pyro_bpf_core_read(&flags, sizeof(flags), &task->flags)) {
        bpf_dbg_printk("failed to read task->flags\n");
        return 0;
    }
    if (flags & PF_KTHREAD) { // 不监测内核线程
        bpf_dbg_printk("skipping kthread %d\n", tgid);
        return 0;
    }

    struct pid_config *config = bpf_map_lookup_elem(&pids, &tgid); // pids 为 保存要监测进程pid的map
    if (config == NULL) { // 如果采样到的pid不在 pids 中，则在pids中存储为未知进程，并向用户态报告
        struct pid_config unknown = {
                .type = PROFILING_TYPE_UNKNOWN,
                .collect_kernel = 0,
                .collect_user = 0,
                .padding_ = 0
        };
        if (bpf_map_update_elem(&pids, &tgid, &unknown, BPF_NOEXIST)) {
            bpf_dbg_printk("failed to update pids map. probably concurrent update\n");
            return 0;
        }
        struct pid_event event = {
                .op  = OP_REQUEST_UNKNOWN_PROCESS_INFO,
                .pid = tgid
        };
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
        return 0;
    }

    if (config->type == PROFILING_TYPE_ERROR || config->type == PROFILING_TYPE_UNKNOWN) { // 为错误进程或未知进程，则直接返回
        return 0;
    }

    // 如果程序类型为python，则尾调用到python调用栈获取函数
    if (config->type == PROFILING_TYPE_PYTHON) {
        bpf_tail_call(ctx, &progs, PROG_IDX_PYTHON);
        return 0;
    }

    // 如果程序中保留栈帧信息，则使用正常的栈解析流程
    if (config->type == PROFILING_TYPE_FRAMEPOINTERS) {
        key.pid = tgid;
        key.kern_stack = -1;
        key.user_stack = -1;

        if (config->collect_kernel) {
            key.kern_stack = bpf_get_stackid(ctx, &stacks, KERN_STACKID_FLAGS); // stacks 为 调用栈存储map
        }
        if (config->collect_user) {
            key.user_stack = bpf_get_stackid(ctx, &stacks, USER_STACKID_FLAGS);
        }

        val = bpf_map_lookup_elem(&counts, &key);
        if (val)
            (*val)++;
        else
            bpf_map_update_elem(&counts, &key, &one, BPF_NOEXIST); // counts 为 计数map，键类型为u32
    }
    return 0;
}

// 进程退出 处理程序，向用户态报告进程退出消息
SEC("kprobe/disassociate_ctty")
int BPF_KPROBE(disassociate_ctty, int on_exit) {
    if (!on_exit) {
        return 0;
    }
    u32 pid = 0;
    current_pid(&pid);
    if (pid == 0) {
        return 0;
    }
    struct pid_event event = {
        .op  = OP_PID_DEAD,
        .pid = pid
    };
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

// 程序加载 处理程序，向用户态报告进程执行消息
// execve/execveat
SEC("kprobe/exec")
int BPF_KPROBE(exec, void *_) {
    u32 pid = 0;
    current_pid(&pid);
    if (pid == 0) {
        return 0;
    }
    struct pid_event event = {
            .op  = OP_REQUEST_EXEC_PROCESS_INFO,
            .pid = pid
    };
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

char _license[] SEC("license") = "GPL";
