/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __EXYNOS9810_BPF_BTF_COMPAT_515_H
#define __EXYNOS9810_BPF_BTF_COMPAT_515_H

/*
 * Minimal vmlinux-BTF lookup helper for the Android-built Linux 5.15.178
 * standalone verifier selftest.
 *
 * The upstream harness gets this functionality from libbpf.  Pulling full
 * libbpf/libelf into this small Android test binary is unnecessary, so parse
 * /sys/kernel/btf/vmlinux directly instead.
 *
 * Keep the prefix/kind rules in sync with Linux 5.15 libbpf's
 * btf_get_kernel_prefix_kind().
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <linux/btf.h>

#define BPF515_VMLINUX_BTF_PATH "/sys/kernel/btf/vmlinux"
#define BPF515_BTF_MAX_FILE_SIZE (64U * 1024U * 1024U)
#define BPF515_BTF_MAX_NAME_SIZE 128

#define BPF515_BTF_TRACE_PREFIX "btf_trace_"
#define BPF515_BTF_LSM_PREFIX   "bpf_lsm_"
#define BPF515_BTF_ITER_PREFIX  "bpf_iter_"

static unsigned char *bpf515_vmlinux_btf_data;
static size_t bpf515_vmlinux_btf_size;
static const unsigned char *bpf515_vmlinux_btf_types;
static size_t bpf515_vmlinux_btf_type_len;
static const char *bpf515_vmlinux_btf_strs;
static size_t bpf515_vmlinux_btf_str_len;
static bool bpf515_vmlinux_btf_tried;
static int bpf515_vmlinux_btf_status;

static inline int
bpf515_read_file(const char *path, unsigned char **data, size_t *size)
{
	unsigned char *buf = NULL;
	size_t len = 0;
	size_t cap = 1024U * 1024U;
	ssize_t n;
	int fd;
	int err = 0;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	buf = malloc(cap);
	if (!buf) {
		err = -ENOMEM;
		goto out;
	}

	for (;;) {
		if (len == cap) {
			unsigned char *tmp;
			size_t new_cap;

			if (cap >= BPF515_BTF_MAX_FILE_SIZE) {
				err = -E2BIG;
				goto out;
			}

			new_cap = cap * 2;
			if (new_cap > BPF515_BTF_MAX_FILE_SIZE)
				new_cap = BPF515_BTF_MAX_FILE_SIZE;

			tmp = realloc(buf, new_cap);
			if (!tmp) {
				err = -ENOMEM;
				goto out;
			}

			buf = tmp;
			cap = new_cap;
		}

		n = read(fd, buf + len, cap - len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			err = -errno;
			goto out;
		}

		if (!n)
			break;

		len += (size_t)n;
	}

	if (!len) {
		err = -EINVAL;
		goto out;
	}

	*data = buf;
	*size = len;
	buf = NULL;

out:
	free(buf);
	close(fd);
	return err;
}

static inline int bpf515_vmlinux_btf_init(void)
{
	const struct btf_header *hdr;
	const unsigned char *base;
	size_t payload_len;
	int err;

	if (bpf515_vmlinux_btf_tried)
		return bpf515_vmlinux_btf_status;

	bpf515_vmlinux_btf_tried = true;

	err = bpf515_read_file(BPF515_VMLINUX_BTF_PATH,
			       &bpf515_vmlinux_btf_data,
			       &bpf515_vmlinux_btf_size);
	if (err)
		goto fail;

	if (bpf515_vmlinux_btf_size < sizeof(*hdr)) {
		err = -EINVAL;
		goto fail;
	}

	hdr = (const struct btf_header *)bpf515_vmlinux_btf_data;

	if (hdr->magic != BTF_MAGIC ||
	    hdr->version != BTF_VERSION ||
	    hdr->hdr_len < sizeof(*hdr) ||
	    hdr->hdr_len > bpf515_vmlinux_btf_size) {
		err = -EINVAL;
		goto fail;
	}

	base = bpf515_vmlinux_btf_data + hdr->hdr_len;
	payload_len = bpf515_vmlinux_btf_size - hdr->hdr_len;

	if (hdr->type_off > payload_len ||
	    hdr->type_len > payload_len - hdr->type_off ||
	    hdr->str_off > payload_len ||
	    hdr->str_len > payload_len - hdr->str_off) {
		err = -EINVAL;
		goto fail;
	}

	bpf515_vmlinux_btf_types = base + hdr->type_off;
	bpf515_vmlinux_btf_type_len = hdr->type_len;
	bpf515_vmlinux_btf_strs = (const char *)base + hdr->str_off;
	bpf515_vmlinux_btf_str_len = hdr->str_len;

	bpf515_vmlinux_btf_status = 0;
	return 0;

fail:
	free(bpf515_vmlinux_btf_data);
	bpf515_vmlinux_btf_data = NULL;
	bpf515_vmlinux_btf_size = 0;
	bpf515_vmlinux_btf_status = err;
	return err;
}

static inline int
bpf515_btf_type_record_size(const struct btf_type *type, size_t remaining,
			    size_t *record_size)
{
	__u32 kind = BTF_INFO_KIND(type->info);
	__u32 vlen = BTF_INFO_VLEN(type->info);
	size_t unit = 0;
	size_t extra = 0;

	switch (kind) {
	case BTF_KIND_UNKN:
	case BTF_KIND_PTR:
	case BTF_KIND_FWD:
	case BTF_KIND_TYPEDEF:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_CONST:
	case BTF_KIND_RESTRICT:
	case BTF_KIND_FUNC:
	case BTF_KIND_FLOAT:
		break;

	case BTF_KIND_INT:
		extra = sizeof(__u32);
		break;

	case BTF_KIND_ARRAY:
		extra = sizeof(struct btf_array);
		break;

	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
		unit = sizeof(struct btf_member);
		break;

	case BTF_KIND_ENUM:
		unit = sizeof(struct btf_enum);
		break;

	case BTF_KIND_FUNC_PROTO:
		unit = sizeof(struct btf_param);
		break;

	case BTF_KIND_VAR:
		extra = sizeof(struct btf_var);
		break;

	case BTF_KIND_DATASEC:
		unit = sizeof(struct btf_var_secinfo);
		break;

	default:
		return -EOPNOTSUPP;
	}

	if (unit) {
		if (vlen > (SIZE_MAX - sizeof(*type)) / unit)
			return -EOVERFLOW;
		extra = (size_t)vlen * unit;
	}

	if (sizeof(*type) > remaining ||
	    extra > remaining - sizeof(*type))
		return -EINVAL;

	*record_size = sizeof(*type) + extra;
	return 0;
}

static inline int
bpf515_find_vmlinux_btf_name_kind(const char *name, int kind)
{
	const unsigned char *pos;
	const unsigned char *end;
	__u32 id = 1;
	int err;

	err = bpf515_vmlinux_btf_init();
	if (err)
		return err;

	pos = bpf515_vmlinux_btf_types;
	end = pos + bpf515_vmlinux_btf_type_len;

	while (pos < end) {
		const struct btf_type *type;
		size_t remaining = (size_t)(end - pos);
		size_t record_size;
		__u32 type_kind;

		if (remaining < sizeof(struct btf_type))
			return -EINVAL;

		type = (const struct btf_type *)pos;
		type_kind = BTF_INFO_KIND(type->info);

		if ((int)type_kind == kind &&
		    type->name_off < bpf515_vmlinux_btf_str_len) {
			const char *type_name =
				bpf515_vmlinux_btf_strs + type->name_off;
			size_t max_len =
				bpf515_vmlinux_btf_str_len - type->name_off;

			if (memchr(type_name, '\0', max_len) &&
			    strcmp(type_name, name) == 0)
				return (int)id;
		}

		err = bpf515_btf_type_record_size(type, remaining,
						  &record_size);
		if (err)
			return err;

		pos += record_size;

		if (id == BTF_MAX_TYPE)
			return -E2BIG;

		id++;
	}

	if (pos != end)
		return -EINVAL;

	return -ENOENT;
}

/*
 * Match Linux 5.15 libbpf's btf_get_kernel_prefix_kind().
 *
 * Normal fentry/fexit/fmod_ret targets are plain BTF_KIND_FUNC names.
 * Iterator attach targets use the "bpf_iter_" prefix, so "task" resolves
 * to the BTF function named "bpf_iter_task".
 */
static inline int
bpf515_find_vmlinux_attach_btf_id(const char *name,
				  enum bpf_attach_type attach_type)
{
	const char *prefix = "";
	int kind = BTF_KIND_FUNC;
	size_t prefix_len;
	size_t name_len;
	char full_name[BPF515_BTF_MAX_NAME_SIZE];

	switch (attach_type) {
	case BPF_TRACE_RAW_TP:
		prefix = BPF515_BTF_TRACE_PREFIX;
		kind = BTF_KIND_TYPEDEF;
		break;
	case BPF_LSM_MAC:
		prefix = BPF515_BTF_LSM_PREFIX;
		kind = BTF_KIND_FUNC;
		break;
	case BPF_TRACE_ITER:
		prefix = BPF515_BTF_ITER_PREFIX;
		kind = BTF_KIND_FUNC;
		break;
	default:
		break;
	}

	prefix_len = strlen(prefix);
	name_len = strlen(name);

	if (prefix_len >= sizeof(full_name) ||
	    name_len >= sizeof(full_name) - prefix_len)
		return -ENAMETOOLONG;

	memcpy(full_name, prefix, prefix_len);
	memcpy(full_name + prefix_len, name, name_len + 1);

	return bpf515_find_vmlinux_btf_name_kind(full_name, kind);
}

#endif /* __EXYNOS9810_BPF_BTF_COMPAT_515_H */
