#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# execsnoop Trace new processes via exec() syscalls.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: execsnoop [-h] [-T] [-t] [-x] [-q] [-n NAME] [-l LINE]
#                  [--max-args MAX_ARGS]
#
# This currently will print up to a maximum of 19 arguments, plus the process
# name, so 20 fields in total (MAXARG).
#
# This won't catch all new processes: an application may fork() but not exec().
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 07-Feb-2016   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF, DEBUG_PREPROCESSOR
from bcc.containers import filter_by_containers
from bcc.utils import ArgString, printb
import bcc.utils as utils
import argparse
import re
import time
import pwd
from collections import defaultdict
from time import strftime


# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/types.h>

struct data_t {
    u32 pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
    u32 ppid; // Parent PID as in the userspace term (i.e task->real_parent->tgid in kernel)
    u32 uid;
    char comm[TASK_COMM_LEN];

    u64 start;
    u32 len;
    u64 prot;
};

#define READ_KERN(ptr) ({                    \
  typeof(ptr) _val;                          \
  __builtin_memset(&_val, 0, sizeof(_val));  \
  bpf_probe_read(&_val, sizeof(_val), &ptr); \
  _val;                                      \
})
BPF_PERF_OUTPUT(events);

int __do_mprotect_pkey(struct pt_regs *ctx,u64 start, u32 len, u64 prot)
{
    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;

    struct data_t data = { .uid = uid, .start = start };
    struct task_struct *task;

    data.len = READ_KERN(len);
    data.prot = READ_KERN(prot);

    data.pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

"""

# initialize BPF
# if you want to see the c source after preprocess, set 'debug' to DEBUG_PREPROCESSOR
b = BPF(text=bpf_text, debug=DEBUG_PREPROCESSOR)
b.attach_kprobe(event="do_mprotect_pkey", fn_name="__do_mprotect_pkey")


# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(event.pid, event.ppid, event.uid, event.comm.decode(),
          hex(event.start), event.len, event.prot, sep='\t')


# loop with callback to print_event
b["events"].open_perf_buffer(print_event)

print("MProtect bind begins!")

while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
