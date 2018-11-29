/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2019 Oracle and/or its affiliates. All rights reserved. */
#include <linux/linkage.h>
#include <asm/asm.h>
#include <asm/frame.h>
#include <asm/page_types.h>
#include <asm/unwind_hints.h>
#include <xen/interface/xen.h>
#include <xen/interface/xen-mca.h>
#include <asm/xen/interface.h>

	.balign PAGE_SIZE
ENTRY(kvm_xen_hypercall_page)
	hcall=0
	.rept (PAGE_SIZE / 32)
		FRAME_BEGIN
		push %rcx	/* Push call clobbered registers */
		push %r9
		push %r11
		mov $hcall, %rax

		call kvm_xen_host_hcall
		pop %r11
		pop %r9
		pop %rcx

		FRAME_END
		ret
		.balign 32
		hcall = hcall + 1
	.endr
/*
 * Hypercall symbols are used for unwinding the stack, so we give them names
 * prefixed with kvm_xen_ (Xen hypercalls have symbols prefixed with xen_.)
 */
#define HYPERCALL(n) \
  .equ kvm_xen_hypercall_##n, kvm_xen_hypercall_page + __HYPERVISOR_##n * 32; \
  .type kvm_xen_hypercall_##n, @function;				      \
  .size kvm_xen_hypercall_##n, 32
#include <asm/xen-hypercalls.h>
#undef HYPERCALL
END(kvm_xen_hypercall_page)

/*
 * Some call stubs generated above do not have associated symbols. Generate
 * bogus symbols for those hypercall blocks to stop objtool from complaining
 * about unreachable code.
 */
.altmacro
.macro hypercall_missing N
       .equ kvm_xen_hypercall_missing_\N, kvm_xen_hypercall_page + \N * 32;
       .type kvm_xen_hypercall_missing_\N, @function;
       .size kvm_xen_hypercall_missing_\N, 32;
.endm

.macro hypercalls_missing N count=1
       .set n,\N
       .rept \count
               hypercall_missing %n
               .set n,n+1
       .endr
.endm

hypercalls_missing 11 1
hypercalls_missing 42 6
hypercalls_missing 56 72
