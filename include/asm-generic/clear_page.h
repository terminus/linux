/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_GENERIC_CLEAR_PAGE_H
#define __ASM_GENERIC_CLEAR_PAGE_H

/*
 * clear_user_pages() operates on contiguous pages and does the clearing
 * operation in a single arch defined primitive.
 *
 * To do this, arch code defines clear_user_pages() and the max granularity
 * it can handle via ARCH_MAX_CLEAR_PAGES_ORDER.
 *
 * Note that given the need for contiguity, __HAVE_ARCH_CLEAR_USER_PAGES
 * and CONFIG_HIGHMEM are mutually exclusive.
 */

#if defined(CONFIG_HIGHMEM) && defined(__HAVE_ARCH_CLEAR_USER_PAGES)
#error CONFIG_HIGHMEM is incompatible with __HAVE_ARCH_CLEAR_USER_PAGES
#endif
#if defined(CONFIG_HIGHMEM) && defined(__HAVE_ARCH_CLEAR_USER_PAGES_INCOHERENT)
#error CONFIG_HIGHMEM is incompatible with __HAVE_ARCH_CLEAR_USER_PAGES_INCOHERENT
#endif

#ifndef __HAVE_ARCH_CLEAR_USER_PAGES

/*
 * For architectures that do not expose __HAVE_ARCH_CLEAR_USER_PAGES, set
 * the granularity to be identical to clear_user_page().
 */
#define ARCH_MAX_CLEAR_PAGES_ORDER	0

#ifndef __ASSEMBLY__

/*
 * With ARCH_MAX_CLEAR_PAGES_ORDER == 0, all callers should be specifying
 * npages == 1 and so we just fallback to clear_user_page().
 */
static inline void clear_user_pages(void *page, unsigned long vaddr,
			       struct page *start_page, unsigned int npages)
{
	clear_user_page(page, vaddr, start_page);
}
#endif /* __ASSEMBLY__ */
#endif /* __HAVE_ARCH_CLEAR_USER_PAGES */

#define ARCH_MAX_CLEAR_PAGES	(1 << ARCH_MAX_CLEAR_PAGES_ORDER)

#ifndef __HAVE_ARCH_CLEAR_USER_PAGES_INCOHERENT
#ifndef __ASSEMBLY__
/*
 * Fallback path (via clear_user_pages()) if the architecture does not
 * support incoherent clearing.
 */
static inline void clear_user_pages_incoherent(__incoherent void *page,
					       unsigned long vaddr,
					       struct page *pg,
					       unsigned int npages)
{
	clear_user_pages((__force void *)page, vaddr, pg, npages);
}

static inline void clear_page_make_coherent(void) { }
#endif /* __ASSEMBLY__ */
#endif /* __HAVE_ARCH_CLEAR_USER_PAGES_INCOHERENT */

#ifndef __ASSEMBLY__
extern unsigned long __init arch_clear_page_non_caching_threshold(void);
#endif

#endif /* __ASM_GENERIC_CLEAR_PAGE_H */
