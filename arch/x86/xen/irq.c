// SPDX-License-Identifier: GPL-2.0
#include <linux/hardirq.h>

#include <asm/x86_init.h>

#include <xen/interface/xen.h>
#include <xen/interface/sched.h>
#include <xen/interface/vcpu.h>
#include <xen/features.h>
#include <xen/events.h>

#include <asm/xen/hypercall.h>
#include <asm/xen/hypervisor.h>

#include "xen-ops.h"

/*
 * Force a proper event-channel callback from Xen after clearing the
 * callback mask. We do this in a very simple manner, by making a call
 * down into Xen. The pending flag will be checked by Xen on return.
 */
void xen_force_evtchn_callback(xenhost_t *xh)
{
	(void)hypervisor_xen_version(xh, 0, NULL);
}

asmlinkage __visible unsigned long xen_save_fl(void)
{
	struct vcpu_info *vcpu;
	unsigned long flags;

	/*
	 * In scenarios with more than one xenhost, the primary xenhost
	 * is responsible for all the upcalls, with the remote xenhost
	 * bouncing its upcalls through it (see comment in
	 * cpu_initialize_context().)
	 *
	 * To minimize unnecessary upcalls, the remote xenhost still looks at
	 * the value of vcpu_info->evtchn_upcall_mask, so we still set and reset
	 * that.
	 *
	 * The fact that the upcall itself is gated by the default xenhost,
	 * also helps in simplifying the logic here because we don't have to
	 * worry about guaranteeing atomicity with updates to
	 * xh_remote->vcpu_info->evtchn_upcall_mask.
	 */
	vcpu = xh_default->xen_vcpu[smp_processor_id()];

	/* flag has opposite sense of mask */
	flags = !vcpu->evtchn_upcall_mask;

	/* convert to IF type flag
	   -0 -> 0x00000000
	   -1 -> 0xffffffff
	*/
	return ((-flags) & X86_EFLAGS_IF);
}
PV_CALLEE_SAVE_REGS_THUNK(xen_save_fl);

__visible void xen_restore_fl(unsigned long flags)
{
	struct vcpu_info *vcpu;
	xenhost_t **xh;

	/* convert from IF type flag */
	flags = !(flags & X86_EFLAGS_IF);

	/* See xen_irq_enable() for why preemption must be disabled. */
	preempt_disable();
	for_each_xenhost(xh) {
		vcpu = (*xh)->xen_vcpu[smp_processor_id()];
		vcpu->evtchn_upcall_mask = flags;
	}

	if (flags == 0) {
		barrier(); /* unmask then check (avoid races) */
		for_each_xenhost(xh) {
			/* Preemption is disabled so we should not have
			 * gotten moved to a different VCPU. */
			vcpu = (*xh)->xen_vcpu[smp_processor_id()];
			if (unlikely(vcpu->evtchn_upcall_pending))
				xen_force_evtchn_callback(*xh);
		}
		preempt_enable();
	} else
		preempt_enable_no_resched();
}
PV_CALLEE_SAVE_REGS_THUNK(xen_restore_fl);

asmlinkage __visible void xen_irq_disable(void)
{
	xenhost_t **xh;

	/* There's a one instruction preempt window here.  We need to
	   make sure we're don't switch CPUs between getting the vcpu
	   pointer and updating the mask. */
	preempt_disable();
	for_each_xenhost(xh)
		/*
		 * Mask events on this CPU for both the xenhosts.  As the
		 * comment above mentions, disabling preemption means we
		 * can safely do that.
		 */
		(*xh)->xen_vcpu[smp_processor_id()]->evtchn_upcall_mask = 1;
	preempt_enable_no_resched();
}
PV_CALLEE_SAVE_REGS_THUNK(xen_irq_disable);

asmlinkage __visible void xen_irq_enable(void)
{
	struct vcpu_info *vcpu;
	xenhost_t **xh;

	/*
	 * We may be preempted as soon as vcpu->evtchn_upcall_mask is
	 * cleared, so disable preemption to ensure we check for
	 * events on the VCPU we are still running on.
	 */
	preempt_disable();

	/* Given that the interrupts are generated from the default xenhost,
	 * we should do this in reverse order.
	 */
	for_each_xenhost(xh) {
		vcpu = (*xh)->xen_vcpu[smp_processor_id()];
		vcpu->evtchn_upcall_mask = 0;

		/* We could get preempted by an incoming interrupt here with a
		 * half enabled irq (for the first xenhost.)
		 */
	}

	barrier(); /* unmask then check (avoid races) */

	for_each_xenhost(xh) {
		vcpu = (*xh)->xen_vcpu[smp_processor_id()];
		if (unlikely(vcpu->evtchn_upcall_pending))
			xen_force_evtchn_callback(*xh);
	}
	preempt_enable();
}
PV_CALLEE_SAVE_REGS_THUNK(xen_irq_enable);

static void xen_safe_halt(void)
{
	/* Blocking includes an implicit local_irq_enable(). */
	if (HYPERVISOR_sched_op(SCHEDOP_block, NULL) != 0)
		BUG();
}

static void xen_halt(void)
{
	if (irqs_disabled())
		HYPERVISOR_vcpu_op(VCPUOP_down,
				   xen_vcpu_nr(xh_default, smp_processor_id()), NULL);
	else
		xen_safe_halt();
}

static const struct pv_irq_ops xen_irq_ops __initconst = {
	.save_fl = PV_CALLEE_SAVE(xen_save_fl),
	.restore_fl = PV_CALLEE_SAVE(xen_restore_fl),
	.irq_disable = PV_CALLEE_SAVE(xen_irq_disable),
	.irq_enable = PV_CALLEE_SAVE(xen_irq_enable),

	.safe_halt = xen_safe_halt,
	.halt = xen_halt,
};

void __init xen_init_irq_ops(void)
{
	pv_ops.irq = xen_irq_ops;
	x86_init.irqs.intr_init = xen_init_IRQ;
}
