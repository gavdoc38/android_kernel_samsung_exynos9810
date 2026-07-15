/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM exynos_dpu

#if !defined(_TRACE_EXYNOS_DPU_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_EXYNOS_DPU_H

#include <linux/tracepoint.h>

TRACE_EVENT(decon_systrace,

	TP_PROTO(int pid, char id, const char *name, int value),

	TP_ARGS(pid, id, name, value),

	TP_STRUCT__entry(
		__field(int, pid)
		__field(char, id)
		__string(name, name)
		__field(int, value)
	),

	TP_fast_assign(
		__entry->pid = pid;
		__entry->id = id;
		__assign_str(name, name);
		__entry->value = value;
	),

	TP_printk("pid=%d id=%c name=%s value=%d",
		  __entry->pid, __entry->id, __get_str(name),
		  __entry->value)
);

#endif /* _TRACE_EXYNOS_DPU_H */

#include <trace/define_trace.h>
