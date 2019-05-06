/******************************************************************************
 * grant_table.c
 *
 * Granting foreign access to our memory reservation.
 *
 * Copyright (c) 2005-2006, Christopher Clark
 * Copyright (c) 2004-2005, K A Fraser
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#define pr_fmt(fmt) "xen:" KBUILD_MODNAME ": " fmt

#include <linux/memblock.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/io.h>
#include <linux/delay.h>
#include <linux/hardirq.h>
#include <linux/workqueue.h>
#include <linux/ratelimit.h>
#include <linux/moduleparam.h>
#ifdef CONFIG_XEN_GRANT_DMA_ALLOC
#include <linux/dma-mapping.h>
#endif

#include <xen/xen.h>
#include <xen/xenhost.h>
#include <xen/interface/xen.h>
#include <xen/page.h>
#include <xen/grant_table.h>
#include <xen/interface/memory.h>
#include <xen/hvc-console.h>
#include <xen/swiotlb-xen.h>
#include <xen/balloon.h>
#ifdef CONFIG_X86
#include <asm/xen/cpuid.h>
#endif
#include <xen/mem-reservation.h>
#include <asm/xen/hypercall.h>
#include <asm/xen/interface.h>

#include <asm/pgtable.h>
#include <asm/sync_bitops.h>

/* External tools reserve first few grant table entries. */
#define NR_RESERVED_ENTRIES 8
#define GNTTAB_LIST_END 0xffffffff

static DEFINE_SPINLOCK(gnttab_list_lock);
static unsigned int xen_gnttab_version;
module_param_named(version, xen_gnttab_version, uint, 0);

/*This is a structure of function pointers for grant table*/
struct gnttab_ops {
	/*
	 * Version of the grant interface.
	 */
	unsigned int version;
	/*
	 * Grant refs per grant frame.
	 */
	unsigned int grefs_per_grant_frame;
	/*
	 * Mapping a list of frames for storing grant entries. Frames parameter
	 * is used to store grant table address when grant table being setup,
	 * nr_gframes is the number of frames to map grant table. Returning
	 * GNTST_okay means success and negative value means failure.
	 */
	int (*map_frames)(xenhost_t *xh, xen_pfn_t *frames, unsigned int nr_gframes);
	/*
	 * Release a list of frames which are mapped in map_frames for grant
	 * entry status.
	 */
	void (*unmap_frames)(xenhost_t *xh);
	/*
	 * Introducing a valid entry into the grant table, granting the frame of
	 * this grant entry to domain for accessing or transfering. Ref
	 * parameter is reference of this introduced grant entry, domid is id of
	 * granted domain, frame is the page frame to be granted, and flags is
	 * status of the grant entry to be updated.
	 */
	void (*update_entry)(xenhost_t *xh, grant_ref_t ref, domid_t domid,
			     unsigned long frame, unsigned flags);
	/*
	 * Stop granting a grant entry to domain for accessing. Ref parameter is
	 * reference of a grant entry whose grant access will be stopped,
	 * readonly is not in use in this function. If the grant entry is
	 * currently mapped for reading or writing, just return failure(==0)
	 * directly and don't tear down the grant access. Otherwise, stop grant
	 * access for this entry and return success(==1).
	 */
	int (*end_foreign_access_ref)(xenhost_t *xh, grant_ref_t ref, int readonly);
	/*
	 * Stop granting a grant entry to domain for transfer. Ref parameter is
	 * reference of a grant entry whose grant transfer will be stopped. If
	 * tranfer has not started, just reclaim the grant entry and return
	 * failure(==0). Otherwise, wait for the transfer to complete and then
	 * return the frame.
	 */
	unsigned long (*end_foreign_transfer_ref)(xenhost_t *xh, grant_ref_t ref);
	/*
	 * Query the status of a grant entry. Ref parameter is reference of
	 * queried grant entry, return value is the status of queried entry.
	 * Detailed status(writing/reading) can be gotten from the return value
	 * by bit operations.
	 */
	int (*query_foreign_access)(xenhost_t *xh, grant_ref_t ref);
};

struct unmap_refs_callback_data {
	struct completion completion;
	int result;
};

struct gnttab_private {
	const struct gnttab_ops *gnttab_interface;
	grant_status_t *grstatus;
	grant_ref_t gnttab_free_head;
	unsigned int nr_grant_frames;
	int gnttab_free_count;
	struct gnttab_free_callback *gnttab_free_callback_list;
	struct grant_frames auto_xlat_grant_frames;
	grant_ref_t **gnttab_list;

	union {
		struct grant_entry_v1 *v1;
		union grant_entry_v2 *v2;
		void *addr;
	} gnttab_shared;
};

#define gt_priv(xh) ((struct gnttab_private *) (xh)->gnttab_private)

static int gnttab_expand(xenhost_t *xh, unsigned int req_entries);

#define RPP (PAGE_SIZE / sizeof(grant_ref_t))
#define SPP (PAGE_SIZE / sizeof(grant_status_t))

static inline grant_ref_t *__gnttab_entry(xenhost_t *xh, grant_ref_t entry)
{
	struct gnttab_private *gt = gt_priv(xh);

	return &gt->gnttab_list[(entry) / RPP][(entry) % RPP];
}
/* This can be used as an l-value */
#define gnttab_entry(xh, entry) (*__gnttab_entry(xh, entry))

static int get_free_entries(xenhost_t *xh, unsigned count)
{
	unsigned long flags;
	int ref, rc = 0;
	grant_ref_t head;
	struct gnttab_private *gt = gt_priv(xh);

	spin_lock_irqsave(&gnttab_list_lock, flags);

	if ((gt->gnttab_free_count < count) &&
	    ((rc = gnttab_expand(xh, count - gt->gnttab_free_count)) < 0)) {
		spin_unlock_irqrestore(&gnttab_list_lock, flags);
		return rc;
	}

	ref = head = gt->gnttab_free_head;
	gt->gnttab_free_count -= count;
	while (count-- > 1)
		head = gnttab_entry(xh, head);
	gt->gnttab_free_head = gnttab_entry(xh, head);
	gnttab_entry(xh, head) = GNTTAB_LIST_END;

	spin_unlock_irqrestore(&gnttab_list_lock, flags);

	return ref;
}

static void do_free_callbacks(xenhost_t *xh)
{
	struct gnttab_free_callback *callback, *next;
	struct gnttab_private *gt = gt_priv(xh);

	callback = gt->gnttab_free_callback_list;
	gt->gnttab_free_callback_list = NULL;

	while (callback != NULL) {
		next = callback->next;
		if (gt->gnttab_free_count >= callback->count) {
			callback->next = NULL;
			callback->fn(callback->arg);
		} else {
			callback->next = gt->gnttab_free_callback_list;
			gt->gnttab_free_callback_list = callback;
		}
		callback = next;
	}
}

static inline void check_free_callbacks(xenhost_t *xh)
{
	struct gnttab_private *gt = gt_priv(xh);

	if (unlikely(gt->gnttab_free_callback_list))
		do_free_callbacks(xh);
}

static void put_free_entry(xenhost_t *xh, grant_ref_t ref)
{
	unsigned long flags;
	struct gnttab_private *gt = gt_priv(xh);

	spin_lock_irqsave(&gnttab_list_lock, flags);
	gnttab_entry(xh, ref) = gt->gnttab_free_head;
	gt->gnttab_free_head = ref;
	gt->gnttab_free_count++;
	check_free_callbacks(xh);
	spin_unlock_irqrestore(&gnttab_list_lock, flags);
}

/*
 * Following applies to gnttab_update_entry_v1 and gnttab_update_entry_v2.
 * Introducing a valid entry into the grant table:
 *  1. Write ent->domid.
 *  2. Write ent->frame:
 *      GTF_permit_access:   Frame to which access is permitted.
 *      GTF_accept_transfer: Pseudo-phys frame slot being filled by new
 *                           frame, or zero if none.
 *  3. Write memory barrier (WMB).
 *  4. Write ent->flags, inc. valid type.
 */
static void gnttab_update_entry_v1(xenhost_t *xh, grant_ref_t ref, domid_t domid,
				   unsigned long frame, unsigned flags)
{
	struct gnttab_private *gt = gt_priv(xh);

	gt->gnttab_shared.v1[ref].domid = domid;
	gt->gnttab_shared.v1[ref].frame = frame;
	wmb();
	gt->gnttab_shared.v1[ref].flags = flags;
}

static void gnttab_update_entry_v2(xenhost_t *xh, grant_ref_t ref, domid_t domid,
				   unsigned long frame, unsigned int flags)
{
	struct gnttab_private *gt = gt_priv(xh);

	gt->gnttab_shared.v2[ref].hdr.domid = domid;
	gt->gnttab_shared.v2[ref].full_page.frame = frame;
	wmb();	/* Hypervisor concurrent accesses. */
	gt->gnttab_shared.v2[ref].hdr.flags = GTF_permit_access | flags;
}

/*
 * Public grant-issuing interface functions
 */
void gnttab_grant_foreign_access_ref(xenhost_t *xh, grant_ref_t ref, domid_t domid,
				     unsigned long frame, int readonly)
{
	struct gnttab_private *gt = gt_priv(xh);

	gt->gnttab_interface->update_entry(xh, ref, domid, frame,
			   GTF_permit_access | (readonly ? GTF_readonly : 0));
}
EXPORT_SYMBOL_GPL(gnttab_grant_foreign_access_ref);

int gnttab_grant_foreign_access(xenhost_t *xh, domid_t domid, unsigned long frame,
				int readonly)
{
	int ref;

	ref = get_free_entries(xh, 1);
	if (unlikely(ref < 0))
		return -ENOSPC;

	gnttab_grant_foreign_access_ref(xh, ref, domid, frame, readonly);

	return ref;
}
EXPORT_SYMBOL_GPL(gnttab_grant_foreign_access);

static int gnttab_query_foreign_access_v1(xenhost_t *xh, grant_ref_t ref)
{
	struct gnttab_private *gt = gt_priv(xh);

	return gt->gnttab_shared.v1[ref].flags & (GTF_reading|GTF_writing);
}

static int gnttab_query_foreign_access_v2(xenhost_t *xh, grant_ref_t ref)
{
	struct gnttab_private *gt = gt_priv(xh);

	return gt->grstatus[ref] & (GTF_reading|GTF_writing);
}

int gnttab_query_foreign_access(xenhost_t *xh, grant_ref_t ref)
{
	struct gnttab_private *gt = gt_priv(xh);

	return gt->gnttab_interface->query_foreign_access(xh, ref);
}
EXPORT_SYMBOL_GPL(gnttab_query_foreign_access);

static int gnttab_end_foreign_access_ref_v1(xenhost_t *xh, grant_ref_t ref, int readonly)
{
	struct gnttab_private *gt = gt_priv(xh);
	u16 flags, nflags;
	u16 *pflags;

	pflags = &gt->gnttab_shared.v1[ref].flags;
	nflags = *pflags;
	do {
		flags = nflags;
		if (flags & (GTF_reading|GTF_writing))
			return 0;
	} while ((nflags = sync_cmpxchg(pflags, flags, 0)) != flags);

	return 1;
}

static int gnttab_end_foreign_access_ref_v2(xenhost_t *xh, grant_ref_t ref, int readonly)
{
	struct gnttab_private *gt = gt_priv(xh);

	gt->gnttab_shared.v2[ref].hdr.flags = 0;
	mb();	/* Concurrent access by hypervisor. */
	if (gt->grstatus[ref] & (GTF_reading|GTF_writing)) {
		return 0;
	} else {
		/*
		 * The read of grstatus needs to have acquire semantics.
		 *  On x86, reads already have that, and we just need to
		 * protect against compiler reorderings.
		 * On other architectures we may need a full barrier.
		 */
#ifdef CONFIG_X86
		barrier();
#else
		mb();
#endif
	}

	return 1;
}

static inline int _gnttab_end_foreign_access_ref(xenhost_t *xh, grant_ref_t ref, int readonly)
{
	struct gnttab_private *gt = gt_priv(xh);

	return gt->gnttab_interface->end_foreign_access_ref(xh, ref, readonly);
}

int gnttab_end_foreign_access_ref(xenhost_t *xh, grant_ref_t ref, int readonly)
{
	if (_gnttab_end_foreign_access_ref(xh, ref, readonly))
		return 1;
	pr_warn("WARNING: g.e. %#x still in use!\n", ref);
	return 0;
}
EXPORT_SYMBOL_GPL(gnttab_end_foreign_access_ref);

struct deferred_entry {
	struct list_head list;
	grant_ref_t ref;
	bool ro;
	uint16_t warn_delay;
	struct page *page;
	xenhost_t *xh;
};
static LIST_HEAD(deferred_list);
static void gnttab_handle_deferred(struct timer_list *);
static DEFINE_TIMER(deferred_timer, gnttab_handle_deferred);

static void gnttab_handle_deferred(struct timer_list *unused)
{
	unsigned int nr = 10;
	struct deferred_entry *first = NULL;
	unsigned long flags;

	spin_lock_irqsave(&gnttab_list_lock, flags);
	while (nr--) {
		struct deferred_entry *entry
			= list_first_entry(&deferred_list,
					   struct deferred_entry, list);

		if (entry == first)
			break;
		list_del(&entry->list);
		spin_unlock_irqrestore(&gnttab_list_lock, flags);
		if (_gnttab_end_foreign_access_ref(entry->xh, entry->ref, entry->ro)) {
			put_free_entry(entry->xh, entry->ref);
			if (entry->page) {
				pr_debug("freeing g.e. %#x (pfn %#lx)\n",
					 entry->ref, page_to_pfn(entry->page));
				put_page(entry->page);
			} else
				pr_info("freeing g.e. %#x\n", entry->ref);
			kfree(entry);
			entry = NULL;
		} else {
			if (!--entry->warn_delay)
				pr_info("g.e. %#x still pending\n", entry->ref);
			if (!first)
				first = entry;
		}
		spin_lock_irqsave(&gnttab_list_lock, flags);
		if (entry)
			list_add_tail(&entry->list, &deferred_list);
		else if (list_empty(&deferred_list))
			break;
	}
	if (!list_empty(&deferred_list) && !timer_pending(&deferred_timer)) {
		deferred_timer.expires = jiffies + HZ;
		add_timer(&deferred_timer);
	}
	spin_unlock_irqrestore(&gnttab_list_lock, flags);
}

static void gnttab_add_deferred(xenhost_t *xh, grant_ref_t ref, bool readonly,
				struct page *page)
{
	struct deferred_entry *entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
	const char *what = KERN_WARNING "leaking";

	if (entry) {
		unsigned long flags;

		entry->ref = ref;
		entry->ro = readonly;
		entry->page = page;
		entry->xh = xh;
		entry->warn_delay = 60;
		spin_lock_irqsave(&gnttab_list_lock, flags);
		list_add_tail(&entry->list, &deferred_list);
		if (!timer_pending(&deferred_timer)) {
			deferred_timer.expires = jiffies + HZ;
			add_timer(&deferred_timer);
		}
		spin_unlock_irqrestore(&gnttab_list_lock, flags);
		what = KERN_DEBUG "deferring";
	}
	printk("%s g.e. %#x (pfn %#lx)\n",
	       what, ref, page ? page_to_pfn(page) : -1);
}

void gnttab_end_foreign_access(xenhost_t *xh, grant_ref_t ref, int readonly,
			       unsigned long page)
{
	if (gnttab_end_foreign_access_ref(xh, ref, readonly)) {
		put_free_entry(xh, ref);
		if (page != 0)
			put_page(virt_to_page(page));
	} else
		gnttab_add_deferred(xh, ref, readonly,
				    page ? virt_to_page(page) : NULL);
}
EXPORT_SYMBOL_GPL(gnttab_end_foreign_access);

int gnttab_grant_foreign_transfer(xenhost_t *xh, domid_t domid, unsigned long pfn)
{
	int ref;

	ref = get_free_entries(xh, 1);
	if (unlikely(ref < 0))
		return -ENOSPC;
	gnttab_grant_foreign_transfer_ref(xh, ref, domid, pfn);

	return ref;
}
EXPORT_SYMBOL_GPL(gnttab_grant_foreign_transfer);

void gnttab_grant_foreign_transfer_ref(xenhost_t *xh, grant_ref_t ref, domid_t domid,
				       unsigned long pfn)
{
	struct gnttab_private *gt = gt_priv(xh);

	gt->gnttab_interface->update_entry(xh, ref, domid, pfn, GTF_accept_transfer);
}
EXPORT_SYMBOL_GPL(gnttab_grant_foreign_transfer_ref);

static unsigned long gnttab_end_foreign_transfer_ref_v1(xenhost_t *xh, grant_ref_t ref)
{
	struct gnttab_private *gt = gt_priv(xh);
	unsigned long frame;
	u16           flags;
	u16          *pflags;

	pflags = &gt->gnttab_shared.v1[ref].flags;

	/*
	 * If a transfer is not even yet started, try to reclaim the grant
	 * reference and return failure (== 0).
	 */
	while (!((flags = *pflags) & GTF_transfer_committed)) {
		if (sync_cmpxchg(pflags, flags, 0) == flags)
			return 0;
		cpu_relax();
	}

	/* If a transfer is in progress then wait until it is completed. */
	while (!(flags & GTF_transfer_completed)) {
		flags = *pflags;
		cpu_relax();
	}

	rmb();	/* Read the frame number /after/ reading completion status. */
	frame = gt->gnttab_shared.v1[ref].frame;
	BUG_ON(frame == 0);

	return frame;
}

static unsigned long gnttab_end_foreign_transfer_ref_v2(xenhost_t *xh, grant_ref_t ref)
{
	unsigned long frame;
	u16           flags;
	u16          *pflags;
	struct gnttab_private *gt = gt_priv(xh);

	pflags = &gt->gnttab_shared.v2[ref].hdr.flags;

	/*
	 * If a transfer is not even yet started, try to reclaim the grant
	 * reference and return failure (== 0).
	 */
	while (!((flags = *pflags) & GTF_transfer_committed)) {
		if (sync_cmpxchg(pflags, flags, 0) == flags)
			return 0;
		cpu_relax();
	}

	/* If a transfer is in progress then wait until it is completed. */
	while (!(flags & GTF_transfer_completed)) {
		flags = *pflags;
		cpu_relax();
	}

	rmb();  /* Read the frame number /after/ reading completion status. */
	frame = gt->gnttab_shared.v2[ref].full_page.frame;
	BUG_ON(frame == 0);

	return frame;
}

unsigned long gnttab_end_foreign_transfer_ref(xenhost_t *xh, grant_ref_t ref)
{
	struct gnttab_private *gt = gt_priv(xh);

	return gt->gnttab_interface->end_foreign_transfer_ref(xh, ref);
}
EXPORT_SYMBOL_GPL(gnttab_end_foreign_transfer_ref);

unsigned long gnttab_end_foreign_transfer(xenhost_t *xh, grant_ref_t ref)
{
	unsigned long frame = gnttab_end_foreign_transfer_ref(xh, ref);

	put_free_entry(xh, ref);

	return frame;
}
EXPORT_SYMBOL_GPL(gnttab_end_foreign_transfer);

void gnttab_free_grant_reference(xenhost_t *xh, grant_ref_t ref)
{
	put_free_entry(xh, ref);
}
EXPORT_SYMBOL_GPL(gnttab_free_grant_reference);

void gnttab_free_grant_references(xenhost_t *xh, grant_ref_t head)
{
	struct gnttab_private *gt = gt_priv(xh);
	grant_ref_t ref;
	unsigned long flags;
	int count = 1;
	if (head == GNTTAB_LIST_END)
		return;
	spin_lock_irqsave(&gnttab_list_lock, flags);
	ref = head;
	while (gnttab_entry(xh, ref) != GNTTAB_LIST_END) {
		ref = gnttab_entry(xh, ref);
		count++;
	}
	gnttab_entry(xh, ref) = gt->gnttab_free_head;
	gt->gnttab_free_head = head;
	gt->gnttab_free_count += count;
	check_free_callbacks(xh);
	spin_unlock_irqrestore(&gnttab_list_lock, flags);
}
EXPORT_SYMBOL_GPL(gnttab_free_grant_references);

int gnttab_alloc_grant_references(xenhost_t *xh, u16 count, grant_ref_t *head)
{
	int h = get_free_entries(xh, count);

	if (h < 0)
		return -ENOSPC;

	*head = h;

	return 0;
}
EXPORT_SYMBOL_GPL(gnttab_alloc_grant_references);

int gnttab_empty_grant_references(xenhost_t *xh, const grant_ref_t *private_head)
{
	return (*private_head == GNTTAB_LIST_END);
}
EXPORT_SYMBOL_GPL(gnttab_empty_grant_references);

int gnttab_claim_grant_reference(xenhost_t *xh, grant_ref_t *private_head)
{
	grant_ref_t g = *private_head;
	if (unlikely(g == GNTTAB_LIST_END))
		return -ENOSPC;
	*private_head = gnttab_entry(xh, g);
	return g;
}
EXPORT_SYMBOL_GPL(gnttab_claim_grant_reference);

void gnttab_release_grant_reference(xenhost_t *xh, grant_ref_t *private_head,
				    grant_ref_t release)
{
	gnttab_entry(xh, release) = *private_head;
	*private_head = release;
}
EXPORT_SYMBOL_GPL(gnttab_release_grant_reference);

void gnttab_request_free_callback(xenhost_t *xh, struct gnttab_free_callback *callback,
				  void (*fn)(void *), void *arg, u16 count)
{
	unsigned long flags;
	struct gnttab_free_callback *cb;
	struct gnttab_private *gt = gt_priv(xh);

	spin_lock_irqsave(&gnttab_list_lock, flags);

	/* Check if the callback is already on the list */
	cb = gt->gnttab_free_callback_list;
	while (cb) {
		if (cb == callback)
			goto out;
		cb = cb->next;
	}

	callback->fn = fn;
	callback->arg = arg;
	callback->count = count;
	callback->next = gt->gnttab_free_callback_list;
	gt->gnttab_free_callback_list = callback;
	check_free_callbacks(xh);
out:
	spin_unlock_irqrestore(&gnttab_list_lock, flags);
}
EXPORT_SYMBOL_GPL(gnttab_request_free_callback);

void gnttab_cancel_free_callback(xenhost_t *xh, struct gnttab_free_callback *callback)
{
	struct gnttab_free_callback **pcb;
	unsigned long flags;
	struct gnttab_private *gt = gt_priv(xh);


	spin_lock_irqsave(&gnttab_list_lock, flags);
	for (pcb = &gt->gnttab_free_callback_list; *pcb; pcb = &(*pcb)->next) {
		if (*pcb == callback) {
			*pcb = callback->next;
			break;
		}
	}
	spin_unlock_irqrestore(&gnttab_list_lock, flags);
}
EXPORT_SYMBOL_GPL(gnttab_cancel_free_callback);

static unsigned int gnttab_frames(xenhost_t *xh, unsigned int frames, unsigned int align)
{
	struct gnttab_private *gt = gt_priv(xh);

	return (frames * gt->gnttab_interface->grefs_per_grant_frame + align - 1) /
	       align;
}

static int grow_gnttab_list(xenhost_t *xh, unsigned int more_frames)
{
	unsigned int new_nr_grant_frames, extra_entries, i;
	unsigned int nr_glist_frames, new_nr_glist_frames;
	unsigned int grefs_per_frame;
	struct gnttab_private *gt = gt_priv(xh);

	BUG_ON(gt->gnttab_interface == NULL);
	grefs_per_frame = gt->gnttab_interface->grefs_per_grant_frame;

	new_nr_grant_frames = gt->nr_grant_frames + more_frames;
	extra_entries = more_frames * grefs_per_frame;

	nr_glist_frames = gnttab_frames(xh, gt->nr_grant_frames, RPP);
	new_nr_glist_frames = gnttab_frames(xh, new_nr_grant_frames, RPP);
	for (i = nr_glist_frames; i < new_nr_glist_frames; i++) {
		gt->gnttab_list[i] = (grant_ref_t *)__get_free_page(GFP_ATOMIC);
		if (!gt->gnttab_list[i])
			goto grow_nomem;
	}


	for (i = grefs_per_frame * gt->nr_grant_frames;
	     i < grefs_per_frame * new_nr_grant_frames - 1; i++)
		gnttab_entry(xh, i) = i + 1;

	gnttab_entry(xh, i) = gt->gnttab_free_head;
	gt->gnttab_free_head = grefs_per_frame * gt->nr_grant_frames;
	gt->gnttab_free_count += extra_entries;

	gt->nr_grant_frames = new_nr_grant_frames;

	check_free_callbacks(xh);

	return 0;

grow_nomem:
	while (i-- > nr_glist_frames)
		free_page((unsigned long) gt->gnttab_list[i]);
	return -ENOMEM;
}

static unsigned int __max_nr_grant_frames(xenhost_t *xh)
{
	struct gnttab_query_size query;
	int rc;

	query.dom = DOMID_SELF;

	rc = hypervisor_grant_table_op(xh, GNTTABOP_query_size, &query, 1);
	if ((rc < 0) || (query.status != GNTST_okay))
		return 4; /* Legacy max supported number of frames */

	return query.max_nr_frames;
}

unsigned int gnttab_max_grant_frames(xenhost_t *xh)
{
	unsigned int xen_max = __max_nr_grant_frames(xh);
	static unsigned int boot_max_nr_grant_frames;

	/* First time, initialize it properly. */
	if (!boot_max_nr_grant_frames)
		boot_max_nr_grant_frames = __max_nr_grant_frames(xh);

	if (xen_max > boot_max_nr_grant_frames)
		return boot_max_nr_grant_frames;
	return xen_max;
}
EXPORT_SYMBOL_GPL(gnttab_max_grant_frames);

int gnttab_setup_auto_xlat_frames(xenhost_t *xh, phys_addr_t addr)
{
	struct gnttab_private *gt = gt_priv(xh);
	xen_pfn_t *pfn;
	unsigned int max_nr_gframes = __max_nr_grant_frames(xh);
	unsigned int i;
	void *vaddr;

	if (gt->auto_xlat_grant_frames.count)
		return -EINVAL;

	vaddr = xen_remap(addr, XEN_PAGE_SIZE * max_nr_gframes);
	if (vaddr == NULL) {
		pr_warn("Failed to ioremap gnttab share frames (addr=%pa)!\n",
			&addr);
		return -ENOMEM;
	}
	pfn = kcalloc(max_nr_gframes, sizeof(pfn[0]), GFP_KERNEL);
	if (!pfn) {
		xen_unmap(vaddr);
		return -ENOMEM;
	}
	for (i = 0; i < max_nr_gframes; i++)
		pfn[i] = XEN_PFN_DOWN(addr) + i;

	gt->auto_xlat_grant_frames.vaddr = vaddr;
	gt->auto_xlat_grant_frames.pfn = pfn;
	gt->auto_xlat_grant_frames.count = max_nr_gframes;

	return 0;
}
EXPORT_SYMBOL_GPL(gnttab_setup_auto_xlat_frames);

void gnttab_free_auto_xlat_frames(xenhost_t *xh)
{
	struct gnttab_private *gt = gt_priv(xh);

	if (!gt->auto_xlat_grant_frames.count)
		return;
	kfree(gt->auto_xlat_grant_frames.pfn);
	xen_unmap(gt->auto_xlat_grant_frames.vaddr);

	gt->auto_xlat_grant_frames.pfn = NULL;
	gt->auto_xlat_grant_frames.count = 0;
	gt->auto_xlat_grant_frames.vaddr = NULL;
}
EXPORT_SYMBOL_GPL(gnttab_free_auto_xlat_frames);

int gnttab_pages_set_private(int nr_pages, struct page **pages)
{
	int i;

	for (i = 0; i < nr_pages; i++) {
#if BITS_PER_LONG < 64
		struct xen_page_foreign *foreign;

		foreign = kzalloc(sizeof(*foreign), GFP_KERNEL);
		if (!foreign)
			return -ENOMEM;

		set_page_private(pages[i], (unsigned long)foreign);
#endif
		SetPagePrivate(pages[i]);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(gnttab_pages_set_private);

/**
 * gnttab_alloc_pages - alloc pages suitable for grant mapping into
 * @nr_pages: number of pages to alloc
 * @pages: returns the pages
 */
int gnttab_alloc_pages(xenhost_t *xh, int nr_pages, struct page **pages)
{
	int ret;

	ret = alloc_xenballooned_pages(xh, nr_pages, pages);
	if (ret < 0)
		return ret;

	ret = gnttab_pages_set_private(nr_pages, pages);
	if (ret < 0)
		gnttab_free_pages(xh, nr_pages, pages);

	return ret;
}
EXPORT_SYMBOL_GPL(gnttab_alloc_pages);

void gnttab_pages_clear_private(int nr_pages, struct page **pages)
{
	int i;

	for (i = 0; i < nr_pages; i++) {
		if (PagePrivate(pages[i])) {
#if BITS_PER_LONG < 64
			kfree((void *)page_private(pages[i]));
#endif
			ClearPagePrivate(pages[i]);
		}
	}
}
EXPORT_SYMBOL_GPL(gnttab_pages_clear_private);

/**
 * gnttab_free_pages - free pages allocated by gnttab_alloc_pages()
 * @nr_pages; number of pages to free
 * @pages: the pages
 */
void gnttab_free_pages(xenhost_t *xh, int nr_pages, struct page **pages)
{
	gnttab_pages_clear_private(nr_pages, pages);
	free_xenballooned_pages(xh, nr_pages, pages);
}
EXPORT_SYMBOL_GPL(gnttab_free_pages);

#ifdef CONFIG_XEN_GRANT_DMA_ALLOC
/**
 * gnttab_dma_alloc_pages - alloc DMAable pages suitable for grant mapping into
 * @args: arguments to the function
 */
int gnttab_dma_alloc_pages(xenhost_t *xh, struct gnttab_dma_alloc_args *args)
{
	unsigned long pfn, start_pfn;
	size_t size;
	int i, ret;

	if (xh->type != xenhost_r1)
		return -EINVAL;

	size = args->nr_pages << PAGE_SHIFT;
	if (args->coherent)
		args->vaddr = dma_alloc_coherent(args->dev, size,
						 &args->dev_bus_addr,
						 GFP_KERNEL | __GFP_NOWARN);
	else
		args->vaddr = dma_alloc_wc(args->dev, size,
					   &args->dev_bus_addr,
					   GFP_KERNEL | __GFP_NOWARN);
	if (!args->vaddr) {
		pr_debug("Failed to allocate DMA buffer of size %zu\n", size);
		return -ENOMEM;
	}

	start_pfn = __phys_to_pfn(args->dev_bus_addr);
	for (pfn = start_pfn, i = 0; pfn < start_pfn + args->nr_pages;
			pfn++, i++) {
		struct page *page = pfn_to_page(pfn);

		args->pages[i] = page;
		args->frames[i] = xen_page_to_gfn(page);
		xenmem_reservation_scrub_page(page);
	}

	xenmem_reservation_va_mapping_reset(args->nr_pages, args->pages);

	ret = xenmem_reservation_decrease(args->nr_pages, args->frames);
	if (ret != args->nr_pages) {
		pr_debug("Failed to decrease reservation for DMA buffer\n");
		ret = -EFAULT;
		goto fail;
	}

	ret = gnttab_pages_set_private(args->nr_pages, args->pages);
	if (ret < 0)
		goto fail;

	return 0;

fail:
	gnttab_dma_free_pages(args);
	return ret;
}
EXPORT_SYMBOL_GPL(gnttab_dma_alloc_pages);

/**
 * gnttab_dma_free_pages - free DMAable pages
 * @args: arguments to the function
 */
int gnttab_dma_free_pages(xenhost_t *xh, struct gnttab_dma_alloc_args *args)
{
	size_t size;
	int i, ret;

	if (xh->type != xenhost_r1)
		return -EINVAL;

	gnttab_pages_clear_private(args->nr_pages, args->pages);

	for (i = 0; i < args->nr_pages; i++)
		args->frames[i] = page_to_xen_pfn(args->pages[i]);

	ret = xenmem_reservation_increase(args->nr_pages, args->frames);
	if (ret != args->nr_pages) {
		pr_debug("Failed to increase reservation for DMA buffer\n");
		ret = -EFAULT;
	} else {
		ret = 0;
	}

	xenmem_reservation_va_mapping_update(args->nr_pages, args->pages,
					     args->frames);

	size = args->nr_pages << PAGE_SHIFT;
	if (args->coherent)
		dma_free_coherent(args->dev, size,
				  args->vaddr, args->dev_bus_addr);
	else
		dma_free_wc(args->dev, size,
			    args->vaddr, args->dev_bus_addr);
	return ret;
}
EXPORT_SYMBOL_GPL(gnttab_dma_free_pages);
#endif

/* Handling of paged out grant targets (GNTST_eagain) */
#define MAX_DELAY 256
static inline void
gnttab_retry_eagain_gop(xenhost_t *xh, unsigned int cmd, void *gop, int16_t *status,
						const char *func)
{
	unsigned delay = 1;

	do {
		BUG_ON(hypervisor_grant_table_op(xh, cmd, gop, 1));
		if (*status == GNTST_eagain)
			msleep(delay++);
	} while ((*status == GNTST_eagain) && (delay < MAX_DELAY));

	if (delay >= MAX_DELAY) {
		pr_err("%s: %s eagain grant\n", func, current->comm);
		*status = GNTST_bad_page;
	}
}

void gnttab_batch_map(xenhost_t *xh, struct gnttab_map_grant_ref *batch, unsigned count)
{
	struct gnttab_map_grant_ref *op;

	if (hypervisor_grant_table_op(xh, GNTTABOP_map_grant_ref, batch, count))
		BUG();
	for (op = batch; op < batch + count; op++)
		if (op->status == GNTST_eagain)
			gnttab_retry_eagain_gop(xh, GNTTABOP_map_grant_ref, op,
						&op->status, __func__);
}
EXPORT_SYMBOL_GPL(gnttab_batch_map);

void gnttab_batch_copy(xenhost_t *xh, struct gnttab_copy *batch, unsigned count)
{
	struct gnttab_copy *op;

	if (hypervisor_grant_table_op(xh, GNTTABOP_copy, batch, count))
		BUG();
	for (op = batch; op < batch + count; op++)
		if (op->status == GNTST_eagain)
			gnttab_retry_eagain_gop(xh, GNTTABOP_copy, op,
						&op->status, __func__);
}
EXPORT_SYMBOL_GPL(gnttab_batch_copy);

void gnttab_foreach_grant_in_range(struct page *page,
				   unsigned int offset,
				   unsigned int len,
				   xen_grant_fn_t fn,
				   void *data)
{
	unsigned int goffset;
	unsigned int glen;
	unsigned long xen_pfn;

	len = min_t(unsigned int, PAGE_SIZE - offset, len);
	goffset = xen_offset_in_page(offset);

	xen_pfn = page_to_xen_pfn(page) + XEN_PFN_DOWN(offset);

	while (len) {
		glen = min_t(unsigned int, XEN_PAGE_SIZE - goffset, len);
		fn(pfn_to_gfn(xen_pfn), goffset, glen, data);

		goffset = 0;
		xen_pfn++;
		len -= glen;
	}
}
EXPORT_SYMBOL_GPL(gnttab_foreach_grant_in_range);

void gnttab_foreach_grant(struct page **pages,
			  unsigned int nr_grefs,
			  xen_grant_fn_t fn,
			  void *data)
{
	unsigned int goffset = 0;
	unsigned long xen_pfn = 0;
	unsigned int i;

	for (i = 0; i < nr_grefs; i++) {
		if ((i % XEN_PFN_PER_PAGE) == 0) {
			xen_pfn = page_to_xen_pfn(pages[i / XEN_PFN_PER_PAGE]);
			goffset = 0;
		}

		fn(pfn_to_gfn(xen_pfn), goffset, XEN_PAGE_SIZE, data);

		goffset += XEN_PAGE_SIZE;
		xen_pfn++;
	}
}

int gnttab_map_refs(xenhost_t *xh, struct gnttab_map_grant_ref *map_ops,
		    struct gnttab_map_grant_ref *kmap_ops,
		    struct page **pages, unsigned int count)
{
	int i, ret;

	ret = hypervisor_grant_table_op(xh, GNTTABOP_map_grant_ref, map_ops, count);
	if (ret)
		return ret;

	for (i = 0; i < count; i++) {
		switch (map_ops[i].status) {
		case GNTST_okay:
		{
			struct xen_page_foreign *foreign;

			SetPageForeign(pages[i]);
			foreign = xen_page_foreign(pages[i]);
			foreign->domid = map_ops[i].dom;
			foreign->gref = map_ops[i].ref;
			break;
		}

		case GNTST_no_device_space:
			pr_warn_ratelimited("maptrack limit reached, can't map all guest pages\n");
			break;

		case GNTST_eagain:
			/* Retry eagain maps */
			gnttab_retry_eagain_gop(xh, GNTTABOP_map_grant_ref,
						map_ops + i,
						&map_ops[i].status, __func__);
			/* Test status in next loop iteration. */
			i--;
			break;

		default:
			break;
		}
	}

	return set_foreign_p2m_mapping(map_ops, kmap_ops, pages, count);
}
EXPORT_SYMBOL_GPL(gnttab_map_refs);

int gnttab_unmap_refs(xenhost_t *xh, struct gnttab_unmap_grant_ref *unmap_ops,
		      struct gnttab_unmap_grant_ref *kunmap_ops,
		      struct page **pages, unsigned int count)
{
	unsigned int i;
	int ret;

	ret = hypervisor_grant_table_op(xh, GNTTABOP_unmap_grant_ref, unmap_ops, count);
	if (ret)
		return ret;

	for (i = 0; i < count; i++)
		ClearPageForeign(pages[i]);

	return clear_foreign_p2m_mapping(unmap_ops, kunmap_ops, pages, count);
}
EXPORT_SYMBOL_GPL(gnttab_unmap_refs);

#define GNTTAB_UNMAP_REFS_DELAY 5

static void __gnttab_unmap_refs_async(struct gntab_unmap_queue_data* item);

static void gnttab_unmap_work(struct work_struct *work)
{
	struct gntab_unmap_queue_data
		*unmap_data = container_of(work, 
					   struct gntab_unmap_queue_data,
					   gnttab_work.work);
	if (unmap_data->age != UINT_MAX)
		unmap_data->age++;
	__gnttab_unmap_refs_async(unmap_data);
}

static void __gnttab_unmap_refs_async(struct gntab_unmap_queue_data* item)
{
	int ret;
	int pc;

	for (pc = 0; pc < item->count; pc++) {
		if (page_count(item->pages[pc]) > 1) {
			unsigned long delay = GNTTAB_UNMAP_REFS_DELAY * (item->age + 1);
			schedule_delayed_work(&item->gnttab_work,
					      msecs_to_jiffies(delay));
			return;
		}
	}

	ret = gnttab_unmap_refs(item->xh, item->unmap_ops, item->kunmap_ops,
				item->pages, item->count);
	item->done(ret, item);
}

void gnttab_unmap_refs_async(struct gntab_unmap_queue_data* item)
{
	INIT_DELAYED_WORK(&item->gnttab_work, gnttab_unmap_work);
	item->age = 0;

	__gnttab_unmap_refs_async(item);
}
EXPORT_SYMBOL_GPL(gnttab_unmap_refs_async);

static void unmap_refs_callback(int result,
		struct gntab_unmap_queue_data *data)
{
	struct unmap_refs_callback_data *d = data->data;

	d->result = result;
	complete(&d->completion);
}

int gnttab_unmap_refs_sync(struct gntab_unmap_queue_data *item)
{
	struct unmap_refs_callback_data data;

	init_completion(&data.completion);
	item->data = &data;
	item->done = &unmap_refs_callback;
	gnttab_unmap_refs_async(item);
	wait_for_completion(&data.completion);

	return data.result;
}
EXPORT_SYMBOL_GPL(gnttab_unmap_refs_sync);

static unsigned int nr_status_frames(xenhost_t *xh, unsigned int nr_grant_frames)
{
	struct gnttab_private *gt = gt_priv(xh);

	BUG_ON(gt->gnttab_interface == NULL);
	return gnttab_frames(xh, nr_grant_frames, SPP);
}

static int gnttab_map_frames_v1(xenhost_t *xh, xen_pfn_t *frames, unsigned int nr_gframes)
{
	int rc;
	struct gnttab_private *gt = gt_priv(xh);

	rc = arch_gnttab_map_shared(xh, frames, nr_gframes,
				    gnttab_max_grant_frames(xh),
				    &gt->gnttab_shared.addr);
	BUG_ON(rc);

	return 0;
}

static void gnttab_unmap_frames_v1(xenhost_t *xh)
{
	struct gnttab_private *gt = gt_priv(xh);

	arch_gnttab_unmap(xh, gt->gnttab_shared.addr, gt->nr_grant_frames);
}

static int gnttab_map_frames_v2(xenhost_t *xh, xen_pfn_t *frames, unsigned int nr_gframes)
{
	uint64_t *sframes;
	unsigned int nr_sframes;
	struct gnttab_get_status_frames getframes;
	int rc;
	struct gnttab_private *gt = gt_priv(xh);

	nr_sframes = nr_status_frames(xh, nr_gframes);

	/* No need for kzalloc as it is initialized in following hypercall
	 * GNTTABOP_get_status_frames.
	 */
	sframes = kmalloc_array(nr_sframes, sizeof(uint64_t), GFP_ATOMIC);
	if (!sframes)
		return -ENOMEM;

	getframes.dom        = DOMID_SELF;
	getframes.nr_frames  = nr_sframes;
	set_xen_guest_handle(getframes.frame_list, sframes);

	rc = hypervisor_grant_table_op(xh, GNTTABOP_get_status_frames,
				       &getframes, 1);
	if (rc == -ENOSYS) {
		kfree(sframes);
		return -ENOSYS;
	}

	BUG_ON(rc || getframes.status);

	rc = arch_gnttab_map_status(xh, sframes, nr_sframes,
				    nr_status_frames(xh, gnttab_max_grant_frames(xh)),
				    &gt->grstatus);
	BUG_ON(rc);
	kfree(sframes);

	rc = arch_gnttab_map_shared(xh, frames, nr_gframes,
				    gnttab_max_grant_frames(xh),
				    &gt->gnttab_shared.addr);
	BUG_ON(rc);

	return 0;
}

static void gnttab_unmap_frames_v2(xenhost_t *xh)
{
	struct gnttab_private *gt = gt_priv(xh);

	arch_gnttab_unmap(xh, gt->gnttab_shared.addr, gt->nr_grant_frames);
	arch_gnttab_unmap(xh, gt->grstatus, nr_status_frames(xh, gt->nr_grant_frames));
}

static int gnttab_map(xenhost_t *xh, unsigned int start_idx, unsigned int end_idx)
{
	struct gnttab_setup_table setup;
	xen_pfn_t *frames;
	unsigned int nr_gframes = end_idx + 1;
	struct gnttab_private *gt = gt_priv(xh);
	int rc;

	if (__xen_feature(xh, XENFEAT_auto_translated_physmap)) {
		struct xen_add_to_physmap xatp;
		unsigned int i = end_idx;
		rc = 0;
		BUG_ON(gt->auto_xlat_grant_frames.count < nr_gframes);
		/*
		 * Loop backwards, so that the first hypercall has the largest
		 * index, ensuring that the table will grow only once.
		 */
		do {
			xatp.domid = DOMID_SELF;
			xatp.idx = i;
			xatp.space = XENMAPSPACE_grant_table;
			xatp.gpfn = gt->auto_xlat_grant_frames.pfn[i];
			rc = hypervisor_memory_op(xh, XENMEM_add_to_physmap, &xatp);
			if (rc != 0) {
				pr_warn("grant table add_to_physmap failed, err=%d\n",
					rc);
				break;
			}
		} while (i-- > start_idx);

		return rc;
	}

	/* No need for kzalloc as it is initialized in following hypercall
	 * GNTTABOP_setup_table.
	 */
	frames = kmalloc_array(nr_gframes, sizeof(unsigned long), GFP_ATOMIC);
	if (!frames)
		return -ENOMEM;

	setup.dom        = DOMID_SELF;
	setup.nr_frames  = nr_gframes;
	set_xen_guest_handle(setup.frame_list, frames);

	rc = hypervisor_grant_table_op(xh, GNTTABOP_setup_table, &setup, 1);
	if (rc == -ENOSYS) {
		kfree(frames);
		return -ENOSYS;
	}

	BUG_ON(rc || setup.status);

	rc = gt->gnttab_interface->map_frames(xh, frames, nr_gframes);

	kfree(frames);

	return rc;
}

static const struct gnttab_ops gnttab_v1_ops = {
	.version			= 1,
	.grefs_per_grant_frame		= XEN_PAGE_SIZE /
					  sizeof(struct grant_entry_v1),
	.map_frames			= gnttab_map_frames_v1,
	.unmap_frames			= gnttab_unmap_frames_v1,
	.update_entry			= gnttab_update_entry_v1,
	.end_foreign_access_ref		= gnttab_end_foreign_access_ref_v1,
	.end_foreign_transfer_ref	= gnttab_end_foreign_transfer_ref_v1,
	.query_foreign_access		= gnttab_query_foreign_access_v1,
};

static const struct gnttab_ops gnttab_v2_ops = {
	.version			= 2,
	.grefs_per_grant_frame		= XEN_PAGE_SIZE /
					  sizeof(union grant_entry_v2),
	.map_frames			= gnttab_map_frames_v2,
	.unmap_frames			= gnttab_unmap_frames_v2,
	.update_entry			= gnttab_update_entry_v2,
	.end_foreign_access_ref		= gnttab_end_foreign_access_ref_v2,
	.end_foreign_transfer_ref	= gnttab_end_foreign_transfer_ref_v2,
	.query_foreign_access		= gnttab_query_foreign_access_v2,
};

static bool gnttab_need_v2(xenhost_t *xh)
{
#ifdef CONFIG_X86
	uint32_t base, width;

	if (xen_pv_domain()) {
		base = xenhost_cpuid_base(xh);
		if (cpuid_eax(base) < 5)
			return false;	/* Information not available, use V1. */
		width = cpuid_ebx(base + 5) &
			XEN_CPUID_MACHINE_ADDRESS_WIDTH_MASK;
		return width > 32 + PAGE_SHIFT;
	}
#endif
	return !!(max_possible_pfn >> 32);
}

static void gnttab_request_version(xenhost_t *xh)
{
	long rc;
	struct gnttab_set_version gsv;
	struct gnttab_private *gt = gt_priv(xh);

	if (gnttab_need_v2(xh))
		gsv.version = 2;
	else
		gsv.version = 1;

	/* Boot parameter overrides automatic selection. */
	if (xen_gnttab_version >= 1 && xen_gnttab_version <= 2)
		gsv.version = xen_gnttab_version;

	rc = hypervisor_grant_table_op(xh, GNTTABOP_set_version, &gsv, 1);
	if (rc == 0 && gsv.version == 2)
		gt->gnttab_interface = &gnttab_v2_ops;
	else
		gt->gnttab_interface = &gnttab_v1_ops;

	pr_info("Grant tables using version %d layout\n",
		gt->gnttab_interface->version);
}

static int gnttab_setup(xenhost_t *xh)
{
	unsigned int max_nr_gframes;
	struct gnttab_private *gt = gt_priv(xh);

	max_nr_gframes = gnttab_max_grant_frames(xh);
	if (max_nr_gframes < gt->nr_grant_frames)
		return -ENOSYS;

	if (__xen_feature(xh, XENFEAT_auto_translated_physmap) && gt->gnttab_shared.addr == NULL) {
		gt->gnttab_shared.addr = gt->auto_xlat_grant_frames.vaddr;
		if (gt->gnttab_shared.addr == NULL) {
			pr_warn("gnttab share frames (addr=0x%08lx) is not mapped!\n",
				(unsigned long)gt->auto_xlat_grant_frames.vaddr);
			return -ENOMEM;
		}
	}
	return gnttab_map(xh, 0, gt->nr_grant_frames - 1);
}

int gnttab_resume(void)
{
	xenhost_t **xh;
	for_each_xenhost(xh) {
		int err;

		gnttab_request_version(*xh);
		err = gnttab_setup(*xh);
		if (err)
			return err;
	}
	return 0;
}

int gnttab_suspend(void)
{
	xenhost_t **xh;
	struct gnttab_private *gt;
	
	for_each_xenhost(xh) {
		gt = gt_priv(*xh);

		if (!__xen_feature((*xh), XENFEAT_auto_translated_physmap))
			gt->gnttab_interface->unmap_frames(*xh);
		return 0;
	}
	return 0;
}

static int gnttab_expand(xenhost_t *xh, unsigned int req_entries)
{
	int rc;
	unsigned int cur, extra;
	struct gnttab_private *gt = gt_priv(xh);

	BUG_ON(gt->gnttab_interface == NULL);
	cur = gt->nr_grant_frames;
	extra = ((req_entries + gt->gnttab_interface->grefs_per_grant_frame - 1) /
		 gt->gnttab_interface->grefs_per_grant_frame);
	if (cur + extra > gnttab_max_grant_frames(xh)) {
		pr_warn_ratelimited("xen/grant-table: max_grant_frames reached"
				    " cur=%u extra=%u limit=%u"
				    " gnttab_free_count=%u req_entries=%u\n",
				    cur, extra, gnttab_max_grant_frames(xh),
				    gt->gnttab_free_count, req_entries);
		return -ENOSPC;
	}

	rc = gnttab_map(xh, cur, cur + extra - 1);
	if (rc == 0)
		rc = grow_gnttab_list(xh, extra);

	return rc;
}

int gnttab_init(xenhost_t *xh)
{
	int i;
	unsigned long max_nr_grant_frames;
	unsigned int max_nr_glist_frames, nr_glist_frames;
	unsigned int nr_init_grefs;
	int ret;
	struct gnttab_private *gt = gt_priv(xh);

	gnttab_request_version(xh);
	max_nr_grant_frames = gnttab_max_grant_frames(xh);
	gt->nr_grant_frames = 1;

	/* Determine the maximum number of frames required for the
	 * grant reference free list on the current hypervisor.
	 */
	BUG_ON(gt->gnttab_interface == NULL);
	max_nr_glist_frames = (max_nr_grant_frames *
			       gt->gnttab_interface->grefs_per_grant_frame / RPP);

	gt->gnttab_list = kmalloc_array(max_nr_glist_frames,
				    sizeof(grant_ref_t *),
				    GFP_KERNEL);
	if (gt->gnttab_list == NULL)
		return -ENOMEM;

	nr_glist_frames = gnttab_frames(xh, gt->nr_grant_frames, RPP);
	for (i = 0; i < nr_glist_frames; i++) {
		gt->gnttab_list[i] = (grant_ref_t *)__get_free_page(GFP_KERNEL);
		if (gt->gnttab_list[i] == NULL) {
			ret = -ENOMEM;
			goto ini_nomem;
		}
	}

	ret = arch_gnttab_init(xh, max_nr_grant_frames,
			       nr_status_frames(xh, max_nr_grant_frames));
	if (ret < 0)
		goto ini_nomem;

	if (gnttab_setup(xh) < 0) {
		ret = -ENODEV;
		goto ini_nomem;
	}

	nr_init_grefs = gt->nr_grant_frames *
			gt->gnttab_interface->grefs_per_grant_frame;

	for (i = NR_RESERVED_ENTRIES; i < nr_init_grefs - 1; i++)
		gnttab_entry(xh, i) = i + 1;

	gnttab_entry(xh, nr_init_grefs - 1) = GNTTAB_LIST_END;
	gt->gnttab_free_count = nr_init_grefs - NR_RESERVED_ENTRIES;
	gt->gnttab_free_head  = NR_RESERVED_ENTRIES;

	printk("Grant table initialized\n");
	return 0;

 ini_nomem:
	for (i--; i >= 0; i--)
		free_page((unsigned long)gt->gnttab_list[i]);
	kfree(gt->gnttab_list);
	return ret;
}
EXPORT_SYMBOL_GPL(gnttab_init);

static int __gnttab_init(void)
{
	xenhost_t **xh;
	int err;

	if (!xen_domain())
		return -ENODEV;

	/* Delay grant-table initialization in the PV on HVM case */
	if (xen_hvm_domain() && !xen_pvh_domain())
		return 0;

	for_each_xenhost(xh) {
		err = gnttab_init(*xh);
		if (err)
			return err;
	}
	
	return 0;
}
/* Starts after core_initcall so that xen_pvh_gnttab_setup can be called
 * beforehand to initialize auto_xlat_grant_frames. */
core_initcall_sync(__gnttab_init);
