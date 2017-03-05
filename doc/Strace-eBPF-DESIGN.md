% Strace.eBPF
% **Fast syscall's tracing**
% Vitalii Chernookyi

******

Why we need new tool
---------------------

 - regular system tracing tools are slow
 - regular tools slow down traced application by few orders of magnitude
 - output of regular tools is human-oriented and don't assume automated
   processing
 - overcoming above problems in regular way require:

    - kernel hacking (sysdig)
    - special HW (Lauterbach).

******

Used technologies
------------------

 - eBPF
 - KProbe
 - Perf Event Circular Buffer
 - event-loop

******

System requirements
--------------------

 - libbcc after commit 6c99958e95cfb741575b05bef6b5701e55b3d7c0
 - Linux Kernel 4.4 (for Perf Event Circular Buffer)
 - CAP_SYS_ADMIN capability for bpf() syscall
 - mounted tracefs

******

Pros
-----

 - Used combination of technologies allow tool to be about one order
   of magnitude faster than regular system strace.
 - Consumes much less amount of CPU resources.
 - Output is designed to be suitable for processing with classical tools
   and technologies, like awk.
 - Can trace syscalls system-wide.
 - Can trace init (process with 'pid == 1'). Finally we have a proper
   tool for debugging systemd ;-)

******

Cons
-----

 - Limited functionality.
 - Slow attaching and detaching.
 - Asynchronity. If user does not provide enough system resources, it may
   lose some calls. This tool does not try to work-around it in any way.
 - Depends on modern kernel features.
 - Underlying eBPF technology is still in active development. Hangs and crashes
   may occur more often as for regular strace, especially on low-res systems.
 - Truncating of very long filenames (longer then ~NAME_MAX bytes) to ~NAME_MAX.
   Details:
    + https://github.com/iovisor/bcc/issues/900

******

Data Flow Diagram
-----------------------------

![DSGN_data_flow_dia.png](DSGN_data_flow_dia.png)

******

Behavioral Activity Diagram
----------------------------

![DSGN_beh_act_dia.png](DSGN_beh_act_dia.png)

******

Conclusion
-----------

 - we reached performance more than 1000000 syscalls per second.
 - we introduce about 750 nanosec of penalty in each syscall.
 - there is space for future optimizations.
