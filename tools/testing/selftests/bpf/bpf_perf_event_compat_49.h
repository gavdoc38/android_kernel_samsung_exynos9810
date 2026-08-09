/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __EXYNOS9810_BPF_PERF_EVENT_COMPAT_49_H
#define __EXYNOS9810_BPF_PERF_EVENT_COMPAT_49_H

/*
 * Userspace view of the BPF perf-event context used by this Exynos9810
 * 4.9-based backport.
 *
 * The kernel's current include/uapi/linux/bpf_perf_event.h embeds the
 * kernel-only struct pt_regs.  Feeding that raw header directly to an
 * Android userspace build is invalid (and collides with Bionic headers).
 * On arm64, struct user_pt_regs is the userspace prefix of struct pt_regs;
 * the 4.9 tree then appends four u64 fields before sample_period.
 *
 * Keep this compatibility declaration local to the selftest harness.  It is
 * deliberately NOT a claim that the kernel already exposes Linux 5.15's
 * bpf_user_pt_regs_t + sample_period + addr UAPI; that ABI difference is a
 * separate backport/audit item.
 */
#include <stddef.h>
#include <asm/ptrace.h>
#include <linux/types.h>

#if !defined(__aarch64__)
#error "Exynos9810 verifier selftest perf-event compatibility is arm64-only"
#endif

struct bpf_perf_event_data {
	struct user_pt_regs regs;
	__u64 __orig_x0;
	__u64 __syscallno;
	__u64 __orig_addr_limit;
	__u64 unused;
	__u64 sample_period;
};

_Static_assert(sizeof(struct user_pt_regs) == 34 * sizeof(__u64),
	       "unexpected arm64 user_pt_regs layout");
_Static_assert(offsetof(struct bpf_perf_event_data, sample_period) ==
	       38 * sizeof(__u64),
	       "unexpected Exynos9810 BPF perf-event context layout");

#endif /* __EXYNOS9810_BPF_PERF_EVENT_COMPAT_49_H */
