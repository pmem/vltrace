/*
 * Copyright 2017, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *
 *     * Neither the name of the copyright holder nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * pid_check_ff_fast_hook.c -- Pid check hook for fast-follow-fork mode.
 */

{
	bool t = false;

	if ((pid_tid >> 32) == TRACED_PID) {
		t |= true;
	} else {
		struct task_struct *task;
		struct task_struct *real_parent_task;
		u64 ppid;

		task = (struct task_struct *)bpf_get_current_task();

		/*
		 * XXX Something wrong is here with real_parent. Probably we
		 *    should use another parent pointer.
		 *
		 * - https://github.com/iovisor/bcc/issues/799
		 * - http://lxr.free-electrons.com/source/kernel/sys.c?v=4.8#L847
		 */
		bpf_probe_read(&real_parent_task,
				sizeof(real_parent_task),
				&task->real_parent);

		bpf_probe_read(&ppid,
			   sizeof(ppid),
			   &real_parent_task->pid);

		if (ppid == TRACED_PID)
			t |= true;
	}

	if (!t) {
		return 0;
	}
}
