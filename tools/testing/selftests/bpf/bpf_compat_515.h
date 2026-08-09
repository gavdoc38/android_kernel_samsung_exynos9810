/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __EXYNOS9810_BPF_COMPAT_515_H
#define __EXYNOS9810_BPF_COMPAT_515_H

/*
 * Small userspace compatibility layer for the Linux 5.15.178 standalone
 * test_verifier harness.  Keep this deliberately narrower than libbpf: the
 * verifier selftest only needs raw bpf() syscall helpers and capability
 * toggling, and linking Android's full libbpf/libelf stack here buys us
 * nothing.
 */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <linux/capability.h>

#ifndef CAP_PERFMON
#define CAP_PERFMON 38
#endif
#ifndef CAP_BPF
#define CAP_BPF 39
#endif

#ifndef BPF_OBJ_NAME_LEN
#define BPF_OBJ_NAME_LEN 16U
#endif

typedef __u32 u32;
typedef __u64 u64;

struct bpf_create_map_attr {
	const char *name;
	enum bpf_map_type map_type;
	__u32 map_flags;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 numa_node;
	__u32 btf_fd;
	__u32 btf_key_type_id;
	__u32 btf_value_type_id;
	__u32 map_ifindex;
	__u32 inner_map_fd;
};

struct bpf_load_program_attr {
	enum bpf_prog_type prog_type;
	enum bpf_attach_type expected_attach_type;
	const char *name;
	const struct bpf_insn *insns;
	size_t insns_cnt;
	const char *license;
	__u32 kern_version;
	__u32 prog_flags;
	__u32 prog_ifindex;
	__u32 log_level;
	__u32 attach_btf_id;
	__u32 attach_prog_fd;
};

static inline __u64 bpf515_ptr_to_u64(const void *ptr)
{
	return (__u64)(uintptr_t)ptr;
}

static inline int bpf515_syscall(enum bpf_cmd cmd, union bpf_attr *attr)
{
#ifdef __NR_bpf
	return (int)syscall(__NR_bpf, cmd, attr, sizeof(*attr));
#else
	errno = ENOSYS;
	return -1;
#endif
}

static inline void bpf515_set_obj_name(char dst[BPF_OBJ_NAME_LEN],
				       const char *src)
{
	if (!src || !src[0])
		return;
	strncpy(dst, src, BPF_OBJ_NAME_LEN - 1);
	dst[BPF_OBJ_NAME_LEN - 1] = '\0';
}

static inline int bpf_create_map(enum bpf_map_type type, int key_size,
				 int value_size, int max_entries,
				 __u32 map_flags)
{
	union bpf_attr attr = {};

	attr.map_type = type;
	attr.key_size = key_size;
	attr.value_size = value_size;
	attr.max_entries = max_entries;
	attr.map_flags = map_flags;
	return bpf515_syscall(BPF_MAP_CREATE, &attr);
}

static inline int bpf_create_map_in_map(enum bpf_map_type type,
					const char *name, int key_size,
					int inner_map_fd, int max_entries,
					__u32 map_flags)
{
	union bpf_attr attr = {};

	attr.map_type = type;
	attr.key_size = key_size;
	attr.value_size = sizeof(__u32);
	attr.max_entries = max_entries;
	attr.map_flags = map_flags;
	attr.inner_map_fd = inner_map_fd;
	bpf515_set_obj_name(attr.map_name, name);
	return bpf515_syscall(BPF_MAP_CREATE, &attr);
}

static inline int bpf_create_map_xattr(const struct bpf_create_map_attr *a)
{
	union bpf_attr attr = {};

	attr.map_type = a->map_type;
	attr.key_size = a->key_size;
	attr.value_size = a->value_size;
	attr.max_entries = a->max_entries;
	attr.map_flags = a->map_flags;
	attr.numa_node = a->numa_node;
	attr.btf_fd = a->btf_fd;
	attr.btf_key_type_id = a->btf_key_type_id;
	attr.btf_value_type_id = a->btf_value_type_id;
	attr.map_ifindex = a->map_ifindex;
	attr.inner_map_fd = a->inner_map_fd;
	bpf515_set_obj_name(attr.map_name, a->name);
	return bpf515_syscall(BPF_MAP_CREATE, &attr);
}

static inline int bpf_map_update_elem(int fd, const void *key,
				      const void *value, __u64 flags)
{
	union bpf_attr attr = {};

	attr.map_fd = fd;
	attr.key = bpf515_ptr_to_u64(key);
	attr.value = bpf515_ptr_to_u64(value);
	attr.flags = flags;
	return bpf515_syscall(BPF_MAP_UPDATE_ELEM, &attr);
}

static inline int bpf_load_program(enum bpf_prog_type type,
				   const struct bpf_insn *insns,
				   size_t insns_cnt, const char *license,
				   __u32 kern_version, char *log_buf,
				   size_t log_buf_sz)
{
	union bpf_attr attr = {};

	attr.prog_type = type;
	attr.insn_cnt = insns_cnt;
	attr.insns = bpf515_ptr_to_u64(insns);
	attr.license = bpf515_ptr_to_u64(license);
	attr.kern_version = kern_version;
	if (log_buf && log_buf_sz) {
		attr.log_buf = bpf515_ptr_to_u64(log_buf);
		attr.log_size = log_buf_sz;
		attr.log_level = 1;
		log_buf[0] = '\0';
	}
	return bpf515_syscall(BPF_PROG_LOAD, &attr);
}

static inline int bpf_load_program_xattr(const struct bpf_load_program_attr *a,
					 char *log_buf, size_t log_buf_sz)
{
	union bpf_attr attr = {};

	attr.prog_type = a->prog_type;
	attr.insn_cnt = a->insns_cnt;
	attr.insns = bpf515_ptr_to_u64(a->insns);
	attr.license = bpf515_ptr_to_u64(a->license);
	attr.kern_version = a->kern_version;
	attr.prog_flags = a->prog_flags;
	attr.prog_ifindex = a->prog_ifindex;
	attr.expected_attach_type = a->expected_attach_type;
	attr.attach_btf_id = a->attach_btf_id;
	attr.attach_prog_fd = a->attach_prog_fd;
	bpf515_set_obj_name(attr.prog_name, a->name);
	if (log_buf && log_buf_sz) {
		attr.log_buf = bpf515_ptr_to_u64(log_buf);
		attr.log_size = log_buf_sz;
		attr.log_level = a->log_level;
		log_buf[0] = '\0';
	}
	return bpf515_syscall(BPF_PROG_LOAD, &attr);
}

static inline int bpf_load_btf(const void *btf, __u32 btf_size,
			       char *log_buf, __u32 log_buf_size,
			       bool do_log)
{
	union bpf_attr attr = {};

	attr.btf = bpf515_ptr_to_u64(btf);
	attr.btf_size = btf_size;
	if (log_buf && log_buf_size) {
		attr.btf_log_buf = bpf515_ptr_to_u64(log_buf);
		attr.btf_log_size = log_buf_size;
		attr.btf_log_level = do_log ? 1 : 0;
	}
	return bpf515_syscall(BPF_BTF_LOAD, &attr);
}

static inline int bpf515_prog_test_run(int prog_fd, int repeat,
				       void *data_in, __u32 data_size_in,
				       void *data_out, __u32 *data_size_out,
				       __u32 *retval, __u32 *duration)
{
	union bpf_attr attr = {};
	int ret;

	attr.test.prog_fd = prog_fd;
	attr.test.repeat = repeat;
	attr.test.data_in = bpf515_ptr_to_u64(data_in);
	attr.test.data_size_in = data_size_in;
	attr.test.data_out = bpf515_ptr_to_u64(data_out);
	if (data_size_out)
		attr.test.data_size_out = *data_size_out;

	ret = bpf515_syscall(BPF_PROG_TEST_RUN, &attr);
	if (data_size_out)
		*data_size_out = attr.test.data_size_out;
	if (retval)
		*retval = attr.test.retval;
	if (duration)
		*duration = attr.test.duration;
	return ret;
}

/*
 * These probes are only consulted after the actual test setup failed.  Keep
 * them intentionally small: for a supported type, a minimal map/program
 * should succeed.  EPERM is treated as "supported" so policy/capability bugs
 * do not get hidden as feature skips.
 */
static inline int bpf_probe_map_type(enum bpf_map_type type, __u32 ifindex)
{
	int fd = -1, inner = -1;
	union bpf_attr attr = {};
	int saved_errno;

	if (type == BPF_MAP_TYPE_SK_STORAGE)
		return 1; /* real selftest setup supplies required BTF */

	attr.map_type = type;
	attr.key_size = sizeof(__u32);
	attr.value_size = sizeof(__u64);
	attr.max_entries = 1;
	attr.map_ifindex = ifindex;

	switch (type) {
	case BPF_MAP_TYPE_RINGBUF:
		attr.key_size = 0;
		attr.value_size = 0;
		attr.max_entries = 4096;
		break;
	case BPF_MAP_TYPE_QUEUE:
	case BPF_MAP_TYPE_STACK:
		attr.key_size = 0;
		attr.value_size = sizeof(__u64);
		break;
	case BPF_MAP_TYPE_LPM_TRIE:
		attr.key_size = sizeof(__u64);
		attr.map_flags = BPF_F_NO_PREALLOC;
		break;
	case BPF_MAP_TYPE_CGROUP_STORAGE:
	case BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE:
		attr.key_size = sizeof(struct bpf_cgroup_storage_key);
		attr.value_size = 8;
		attr.max_entries = 0;
		break;
	case BPF_MAP_TYPE_ARRAY_OF_MAPS:
	case BPF_MAP_TYPE_HASH_OF_MAPS:
		inner = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(__u32),
				       sizeof(__u64), 1, 0);
		if (inner < 0)
			return errno == EPERM ? 1 : 0;
		attr.value_size = sizeof(__u32);
		attr.inner_map_fd = inner;
		break;
	default:
		break;
	}

	fd = bpf515_syscall(BPF_MAP_CREATE, &attr);
	saved_errno = errno;
	if (fd >= 0)
		close(fd);
	if (inner >= 0)
		close(inner);
	if (fd >= 0)
		return 1;
	return saved_errno == EPERM || saved_errno == EACCES;
}

static inline int bpf_probe_prog_type(enum bpf_prog_type type, __u32 ifindex)
{
	struct bpf_insn insns[] = {
		{
			.code = BPF_ALU64 | BPF_MOV | BPF_K,
			.dst_reg = BPF_REG_0,
			.imm = 0,
		},
		{
			.code = BPF_JMP | BPF_EXIT,
		},
	};
	union bpf_attr attr = {};
	static const char license[] = "GPL";
	int fd, saved_errno;

	/* These require an attach-BTF target and are handled by explicit skips. */
	if (type == BPF_PROG_TYPE_TRACING || type == BPF_PROG_TYPE_EXT)
		return 0;

	attr.prog_type = type;
	attr.insn_cnt = sizeof(insns) / sizeof(insns[0]);
	attr.insns = bpf515_ptr_to_u64(insns);
	attr.license = bpf515_ptr_to_u64(license);
	attr.prog_ifindex = ifindex;
	fd = bpf515_syscall(BPF_PROG_LOAD, &attr);
	saved_errno = errno;
	if (fd >= 0)
		close(fd);
	if (fd >= 0)
		return 1;
	return saved_errno == EPERM || saved_errno == EACCES;
}

static inline int bpf515_capget(struct __user_cap_data_struct data[2])
{
	struct __user_cap_header_struct hdr = {
		.version = _LINUX_CAPABILITY_VERSION_3,
		.pid = 0,
	};
#ifdef __NR_capget
	return (int)syscall(__NR_capget, &hdr, data);
#else
	errno = ENOSYS;
	return -1;
#endif
}

static inline int bpf515_capset(const struct __user_cap_data_struct data[2])
{
	struct __user_cap_header_struct hdr = {
		.version = _LINUX_CAPABILITY_VERSION_3,
		.pid = 0,
	};
#ifdef __NR_capset
	return (int)syscall(__NR_capset, &hdr, data);
#else
	errno = ENOSYS;
	return -1;
#endif
}

static inline bool bpf515_cap_is_set(const struct __user_cap_data_struct data[2],
				     unsigned int cap, bool permitted)
{
	const __u32 word = cap / 32;
	const __u32 bit = 1U << (cap % 32);

	if (word >= 2)
		return false;
	return permitted ? !!(data[word].permitted & bit) :
			   !!(data[word].effective & bit);
}

static inline void bpf515_cap_toggle(struct __user_cap_data_struct data[2],
				     unsigned int cap, bool enable)
{
	const __u32 word = cap / 32;
	const __u32 bit = 1U << (cap % 32);

	if (word >= 2)
		return;
	if (enable && (data[word].permitted & bit))
		data[word].effective |= bit;
	else
		data[word].effective &= ~bit;
}

static inline int bpf515_set_admin(bool admin)
{
	struct __user_cap_data_struct data[2] = {};

	if (bpf515_capget(data))
		return -1;

	/*
	 * Linux 5.15's selftest drops CAP_SYS_ADMIN and relies on CAP_BPF plus
	 * CAP_PERFMON.  This Exynos 4.9 backport intentionally retains legacy
	 * CAP_SYS_ADMIN gates in parts of BPF, so privileged test loads need it.
	 */
	bpf515_cap_toggle(data, CAP_SYS_ADMIN, admin);
	bpf515_cap_toggle(data, CAP_NET_ADMIN, admin);
	bpf515_cap_toggle(data, CAP_PERFMON, admin);
	bpf515_cap_toggle(data, CAP_BPF, admin);
	return bpf515_capset(data);
}

static inline bool bpf515_is_admin(void)
{
	struct __user_cap_data_struct data[2] = {};
	bool modern;

	if (bpf515_capget(data))
		return false;
	if (bpf515_cap_is_set(data, CAP_SYS_ADMIN, false))
		return true;

	modern = bpf515_cap_is_set(data, CAP_NET_ADMIN, false) &&
		 bpf515_cap_is_set(data, CAP_PERFMON, false) &&
		 bpf515_cap_is_set(data, CAP_BPF, false);
	return modern;
}

#endif /* __EXYNOS9810_BPF_COMPAT_515_H */
