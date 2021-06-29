/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_PAGE_64_H
#define _ASM_X86_PAGE_64_H

#include <asm/page_64_types.h>

#ifndef __ASSEMBLY__
#include <asm/cpufeatures.h>
#include <asm/alternative.h>

/* duplicated to the one in bootmem.h */
extern unsigned long max_pfn;
extern unsigned long phys_base;

extern unsigned long page_offset_base;
extern unsigned long vmalloc_base;
extern unsigned long vmemmap_base;

static __always_inline unsigned long __phys_addr_nodebug(unsigned long x)
{
	unsigned long y = x - __START_KERNEL_map;

	/* use the carry flag to determine if x was < __START_KERNEL_map */
	x = y + ((x > y) ? phys_base : (__START_KERNEL_map - PAGE_OFFSET));

	return x;
}

#ifdef CONFIG_DEBUG_VIRTUAL
extern unsigned long __phys_addr(unsigned long);
extern unsigned long __phys_addr_symbol(unsigned long);
#else
#define __phys_addr(x)		__phys_addr_nodebug(x)
#define __phys_addr_symbol(x) \
	((unsigned long)(x) - __START_KERNEL_map + phys_base)
#endif

#define __phys_reloc_hide(x)	(x)

#ifdef CONFIG_FLATMEM
#define pfn_valid(pfn)          ((pfn) < max_pfn)
#endif

/*
 * Clear in chunks of 256 pages/1024KB.
 *
 * Assuming a clearing BW of 3b/cyc (recent generation processors have
 * more), this amounts to around 400K cycles for each chunk.
 *
 * With a cpufreq of ~2.5GHz, this amounts to ~160us for each chunk
 * (which would also be the interval between calls to cond_resched().)
 */
#define ARCH_MAX_CLEAR_PAGES_ORDER	8

void clear_pages_orig(void *page, unsigned long npages);
void clear_pages_rep(void *page, unsigned long npages);
void clear_pages_erms(void *page, unsigned long npages);
void clear_pages_movnt(void *page, unsigned long npages);
void clear_pages_clzero(void *page, unsigned long npages);

#define __HAVE_ARCH_CLEAR_USER_PAGES
static inline void clear_pages(void *page, unsigned int npages)
{
	alternative_call_2(clear_pages_orig,
			   clear_pages_rep, X86_FEATURE_REP_GOOD,
			   clear_pages_erms, X86_FEATURE_ERMS,
			   "=D" (page), "S" ((unsigned long) npages),
			   "0" (page)
			   : "cc", "memory", "rax", "rcx");
}

void copy_page(void *to, void *from);

#ifdef CONFIG_X86_5LEVEL
/*
 * User space process size.  This is the first address outside the user range.
 * There are a few constraints that determine this:
 *
 * On Intel CPUs, if a SYSCALL instruction is at the highest canonical
 * address, then that syscall will enter the kernel with a
 * non-canonical return address, and SYSRET will explode dangerously.
 * We avoid this particular problem by preventing anything
 * from being mapped at the maximum canonical address.
 *
 * On AMD CPUs in the Ryzen family, there's a nasty bug in which the
 * CPUs malfunction if they execute code from the highest canonical page.
 * They'll speculate right off the end of the canonical space, and
 * bad things happen.  This is worked around in the same way as the
 * Intel problem.
 *
 * With page table isolation enabled, we map the LDT in ... [stay tuned]
 */
static __always_inline unsigned long task_size_max(void)
{
	unsigned long ret;

	alternative_io("movq %[small],%0","movq %[large],%0",
			X86_FEATURE_LA57,
			"=r" (ret),
			[small] "i" ((1ul << 47)-PAGE_SIZE),
			[large] "i" ((1ul << 56)-PAGE_SIZE));

	return ret;
}
#endif	/* CONFIG_X86_5LEVEL */

#endif	/* !__ASSEMBLY__ */

#ifdef CONFIG_X86_VSYSCALL_EMULATION
# define __HAVE_ARCH_GATE_AREA 1
#endif

#endif /* _ASM_X86_PAGE_64_H */
