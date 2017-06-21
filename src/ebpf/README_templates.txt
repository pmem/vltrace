Templates for Kprobes and Tracepoints hooks
-------------------------------------------

In order to get a value of all arguments and the return code of a syscall,
Kprobes and Tracepoints hooks are used. The hooks are generated from templates
by replacing the constant string 'SYSCALL_NAME_filled_for_replace'
with actual syscall name:
- kprobe__SYSCALL_NAME_filled_for_replace - for Kprobes
- kretprobe__SYSCALL_NAME_filled_for_replace - for Kretprobes

There are only two hooks for Tracepoints:
- tracepoint__sys_enter and
- tracepoint__sys_exit.

There are several types of templates depending on:
1) syscall type:
   - template_fork.c:         - for fork(), vfork() and clone() syscalls,
   - template_exit.c:         - for exit() and exit_group() syscalls.
2) number of string arguments:
   - template_0_str.c:        - 0 string arguments,
   - template_1_str-*.c:      - 1 string argument,
   - template_2_str-*.c:      - 2 string arguments,
   - template_3_str-*.c:      - 3 string arguments.
3) mode of reading string arguments:
   - template_?_str-sl.c:     - single packet per each syscall (one packet
                                contains all string arguments),
   - template_?_str-ml.c:     - single packet per each string argument,
   - template_?_str-const.c:  - constant number of packets per each string
                                argument (the number is computed from
                                the maximum length of a string argument
                                and the size of the packet string buffer,
   - template_?_str-full.c:   - variable number of packets per each string
                                argument depending on the length of a string,
                                but not greater than maximum number of packets
                                computed like in the 'constant' case above.
