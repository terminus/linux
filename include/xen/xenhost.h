#ifndef __XENHOST_H
#define __XENHOST_H

#include <xen/interface/features.h>
#include <xen/interface/xen.h>
#include <asm/xen/hypervisor.h>

/*
 * Xenhost abstracts out the Xen interface. It co-exists with the PV/HVM/PVH
 * abstractions (x86_init, hypervisor_x86, pv_ops etc) and is meant to
 * expose ops for communication between the guest and Xen (hypercall, cpuid,
 * shared_info/vcpu_info, evtchn, grant-table and on top of those, xenbus, ballooning),
 * so these could differ based on the kind of underlying Xen: regular, local,
 * and nested.
 *
 * Any call-sites which initiate communication with the hypervisor take
 * xenhost_t * as a parameter and use the appropriate xenhost interface.
 *
 * Note, that the init for the nested xenhost (in the nested dom0 case,
 * there are two) happens for each operation alongside the default xenhost
 * (which remains similar to the one now) and is not deferred for later.
 * This allows us to piggy-back on the non-trivial sequencing, inter-locking
 * logic in the init of the default xenhost.
 */

/*
 * xenhost_type: specifies the controlling Xen interface. The notation,
 * xenhost_r0, xenhost_r1, xenhost_r2 is meant to invoke hypervisor distance
 * from the guest.
 *
 * Note that the distance is relative, and so does not identify a specific
 * hypervisor, just the role played by the interface: so, instance for L0-guest
 * xenhost_r1 would be L0-Xen and for an L1-guest, L1-Xen.
 */
enum xenhost_type {
	xenhost_invalid = 0,
	/*
	 * xenhost_r1: the guest's frontend or backend drivers talking
	 * to a hypervisor one level removed.
	 * This is the ordinary, non-nested configuration as well as for the
	 * typical nested frontends and backends.
	 *
	 * The corresponding xenhost_t would continue to use the current
	 * interfaces, via a redirection layer.
	 */
	xenhost_r1,

	/*
	 * xenhost_r2: frontend drivers communicating with a hypervisor two
	 * levels removed: so L1-dom0-frontends communicating with L0-Xen.
	 *
	 * This is the nested-Xen configuration: L1-dom0-frontend drivers can
	 * now talk to L0-dom0-backend drivers via a separate xenhost_t.
	 */
	xenhost_r2,

	/*
	 * Local/Co-located case: backend drivers now run in the same address
	 * space as the hypervisor. The driver model remains same as
	 * xenhost_r1, but with slightly different interfaces.
	 *
	 * Any frontend guests of this hypervisor will continue to be
	 * xenhost_r1.
	 */
	xenhost_r0,
};

struct xenhost_ops;

typedef struct {
	enum xenhost_type type;

	struct xenhost_ops *ops;

	struct hypercall_entry *hypercall_page;

	/*
	 * Not clear if we need to draw features from two different
	 * hypervisors. There is one feature that seems might be necessary:
	 * XENFEAT_hvm_callback_vector.
	 * Ensuring support in both L1-Xen and L0-Xen means that L0-Xen can
	 * bounce callbacks via L1-Xen.
	 */
	u8 features[XENFEAT_NR_SUBMAPS * 32];

	/*
	 * shared-info to communicate with this xenhost instance.
	 */
	struct {
		struct shared_info *HYPERVISOR_shared_info;
		unsigned long shared_info_pfn;
	};
} xenhost_t;

typedef struct xenhost_ops {
	/*
	 * xen_cpuid is used to probe features early.
	 * xenhost_r0:
	 *   Implementation could not use cpuid at all: it's difficult to
	 *   intercept cpuid instruction locally.
	 * xenhost_r1:
	 * xenhost_r2:
	 *   Separate cpuid-leafs?
	 */
	uint32_t (*cpuid_base)(xenhost_t *xenhost);

	/*
	 * Hypercall page is setup as the first thing once the PV/PVH/PVHVM
	 * code detects that it is selected. The first use is in
	 * xen_setup_features().
	 *
	 * PV/PVH/PVHVM set this up in different ways: hypervisor takes
	 * care of this for PV, PVH and PVHVM use xen_cpuid.
	 *
	 *  xenhost_r0: point hypercall_page to external hypercall_page.
	 *  xenhost_r1: what we do now.
	 *  xenhost_r2: hypercall interface that bypasses L1-Xen to go from
	 *    L1-guest to L0-Xen. The interface would allow L0-Xen to be able
	 *    to decide which particular L1-guest was the caller.
	 */
	void (*setup_hypercall_page)(xenhost_t *xenhost);

	/*
	 * shared_info: needed before vcpu-info setup.
	 *
	 * Needed early because Xen needs it for irq_disable() and such.
	 * On PV first a dummy_shared_info is setup which eventually gets
	 * switched to the real one so this needs to support switching
	 * xenhost.
	 *
	 * Reset for PV is done differently from HVM, so provide a
	 * separate interface.
	 *
	 *  xenhost_r0: point xenhost->HYPERVISOR_shared_info to a
	 *    newly allocated shared_info page.
	 *  xenhost_r1: similar to what we do now.
	 *  xenhost_r2: new remote hypercall to setup a shared_info page.
	 *    This is where we would now handle L0-Xen irq/evtchns.
	 */
	void (*setup_shared_info)(xenhost_t *xenhost);
	void (*reset_shared_info)(xenhost_t *xenhost);
} xenhost_ops_t;

extern xenhost_t *xh_default, *xh_remote;
extern xenhost_t xenhosts[2];

/*
 * xenhost_register(): is called early in the guest's xen-init, after it detects
 * in some implementation defined manner what kind of underlying xenhost or
 * xenhosts exist.
 * Specifies the type of xenhost being registered and the ops for that.
 */
void xenhost_register(enum xenhost_type type, xenhost_ops_t *ops);
void __xenhost_unregister(enum xenhost_type type);


/*
 * Convoluted interface so we can do this without adding a loop counter.
 */
#define for_each_xenhost(xh) \
	for ((xh) = (xenhost_t **) &xenhosts[0];	\
		(((xh) - (xenhost_t **)&xenhosts) < 2) && (*xh)->type != xenhost_invalid; (xh)++)

static inline uint32_t xenhost_cpuid_base(xenhost_t *xh)
{
	if (xh)
		return (xh->ops->cpuid_base)(xh);
	else
		return xen_cpuid_base();
}

static inline void xenhost_setup_hypercall_page(xenhost_t *xh)
{
	(xh->ops->setup_hypercall_page)(xh);
}


static inline void xenhost_setup_shared_info(xenhost_t *xh)
{
	(xh->ops->setup_shared_info)(xh);
}

static inline void xenhost_reset_shared_info(xenhost_t *xh)
{
	(xh->ops->reset_shared_info)(xh);
}

#endif /* __XENHOST_H */
