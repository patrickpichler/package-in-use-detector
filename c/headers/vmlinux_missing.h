#ifndef __VMLINUX_MISSING_H__
#define __VMLINUX_MISSING_H__

#include "vmlinux.h"

struct btf_ptr {
	void *ptr;
	__u32 type_id;
	__u32 flags;		/* BTF ptr flags; unused at present. */
};

#endif // __VMLINUX_MISSING_H__
