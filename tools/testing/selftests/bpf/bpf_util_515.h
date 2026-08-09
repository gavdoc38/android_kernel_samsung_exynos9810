/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __EXYNOS9810_BPF_UTIL_515_H
#define __EXYNOS9810_BPF_UTIL_515_H

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* libbpf_num_possible_cpus() without a libbpf dependency. */
static inline unsigned int bpf_num_possible_cpus(void)
{
	char buf[256], *p, *end;
	unsigned int total = 0;
	FILE *f;

	f = fopen("/sys/devices/system/cpu/possible", "r");
	if (!f)
		goto fallback;
	if (!fgets(buf, sizeof(buf), f)) {
		fclose(f);
		goto fallback;
	}
	fclose(f);

	p = buf;
	while (*p) {
		unsigned long first, last;

		errno = 0;
		first = strtoul(p, &end, 10);
		if (errno || end == p)
			goto fallback;
		p = end;
		last = first;
		if (*p == '-') {
			p++;
			errno = 0;
			last = strtoul(p, &end, 10);
			if (errno || end == p || last < first)
				goto fallback;
			p = end;
		}
		total += (unsigned int)(last - first + 1);
		if (*p == ',') {
			p++;
			continue;
		}
		while (*p == '\n' || *p == '\r' || *p == ' ' || *p == '\t')
			p++;
		if (*p)
			goto fallback;
	}
	if (total)
		return total;

fallback:
	{
		long n = sysconf(_SC_NPROCESSORS_CONF);
		if (n > 0)
			return (unsigned int)n;
	}
	fprintf(stderr, "Failed to determine number of possible CPUs\n");
	exit(1);
}

#define __bpf_percpu_val_align __attribute__((__aligned__(8)))
#define BPF_DECLARE_PERCPU(type, name) \
	struct { type v; } __bpf_percpu_val_align name[bpf_num_possible_cpus()]
#define bpf_percpu(name, cpu) name[(cpu)].v

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif
#ifndef sizeof_field
#define sizeof_field(TYPE, MEMBER) sizeof((((TYPE *)0)->MEMBER))
#endif
#ifndef offsetofend
#define offsetofend(TYPE, MEMBER) \
	(offsetof(TYPE, MEMBER) + sizeof_field(TYPE, MEMBER))
#endif

#endif /* __EXYNOS9810_BPF_UTIL_515_H */
