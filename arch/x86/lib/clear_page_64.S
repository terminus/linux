/* SPDX-License-Identifier: GPL-2.0-only */
#include <linux/linkage.h>
#include <asm/export.h>
#include <asm/page_types.h>

/*
 * Most CPUs support enhanced REP MOVSB/STOSB instructions. It is
 * recommended to use this when possible and we do use them by default.
 * If enhanced REP MOVSB/STOSB is not available, try to use fast string.
 * Otherwise, use original.
 */

/*
 * Zero pages.
 * %rdi	- base page
 * %rsi	- number of pages
 *
 * Note: clear_pages_*() have differing alignments restrictions
 * but callers are always expected to page align.
 */
SYM_FUNC_START(clear_pages_rep)
	movq %rsi,%rcx
	shlq $(PAGE_SHIFT - 3),%rcx
	xorl %eax,%eax
	rep stosq
	RET
SYM_FUNC_END(clear_pages_rep)
EXPORT_SYMBOL_GPL(clear_pages_rep)

SYM_FUNC_START(clear_pages_orig)
	xorl   %eax,%eax
	movq   %rsi,%rcx
	shlq   $(PAGE_SHIFT - 6),%rcx
	.p2align 4
.Lloop:
	decq	%rcx
#define PUT(x) movq %rax,x*8(%rdi)
	movq %rax,(%rdi)
	PUT(1)
	PUT(2)
	PUT(3)
	PUT(4)
	PUT(5)
	PUT(6)
	PUT(7)
	leaq	64(%rdi),%rdi
	jnz	.Lloop
	nop
	RET
SYM_FUNC_END(clear_pages_orig)
EXPORT_SYMBOL_GPL(clear_pages_orig)

SYM_FUNC_START(clear_pages_erms)
	movq %rsi,%rcx
	shlq $PAGE_SHIFT, %rcx
	xorl %eax,%eax
	rep stosb
	RET
SYM_FUNC_END(clear_pages_erms)
EXPORT_SYMBOL_GPL(clear_pages_erms)
