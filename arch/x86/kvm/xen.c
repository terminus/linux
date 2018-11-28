// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019 Oracle and/or its affiliates. All rights reserved.
 *
 * KVM Xen emulation
 */

#include "x86.h"
#include "xen.h"
#include "ioapic.h"

#include <linux/mman.h>
#include <linux/highmem.h>
#include <linux/kvm_host.h>
#include <linux/eventfd.h>
#include <linux/sched/stat.h>
#include <linux/linkage.h>

#include <trace/events/kvm.h>
#include <xen/interface/xen.h>
#include <xen/interface/vcpu.h>
#include <xen/interface/event_channel.h>
#include <xen/interface/grant_table.h>
#include <xen/interface/sched.h>
#include <xen/interface/version.h>
#include <xen/xen.h>
#include <xen/features.h>
#include <asm/xen/hypercall.h>

#include <xen/xen.h>
#include <xen/events.h>
#include <xen/xen-ops.h>

#include "trace.h"

/* Grant v1 references per 4K page */
#define GPP_V1 (PAGE_SIZE / sizeof(struct grant_entry_v1))
#define shared_entry(gt, ref)	(&((gt)[(ref) / GPP_V1][(ref) % GPP_V1]))

/* Grant mappings per 4K page */
#define MPP    (PAGE_SIZE / sizeof(struct kvm_grant_map))
#define maptrack_entry(mt, hdl)	(&((mt)[(hdl) / MPP][(hdl) % MPP]))

struct evtchnfd {
	struct eventfd_ctx *ctx;
	u32 vcpu;
	u32 port;
	u32 type;
	union {
		struct {
			u8 type;
		} virq;
		struct {
			domid_t dom;
			struct kvm *vm;
			u32 port;
		} remote;
	};
};

static int kvm_xen_evtchn_send(struct kvm_vcpu *vcpu, int port);
static void *vcpu_to_xen_vcpu_info(struct kvm_vcpu *v);
static void kvm_xen_gnttab_free(struct kvm_xen *xen);
static int kvm_xen_evtchn_send_shim(struct kvm_xen *shim, struct evtchnfd *evt);
static int shim_hypercall(u64 code, u64 a0, u64 a1, u64 a2, u64 a3, u64 a4);

#define XEN_DOMID_MIN	1
#define XEN_DOMID_MAX	(DOMID_FIRST_RESERVED - 1)

static rwlock_t domid_lock;
static struct idr domid_to_kvm;

static struct hypercall_entry *hypercall_page_save;
static struct kvm_xen *xen_shim __read_mostly;

static int kvm_xen_domid_init(struct kvm *kvm, bool any, domid_t domid)
{
	u16 min = XEN_DOMID_MIN, max = XEN_DOMID_MAX;
	struct kvm_xen *xen = &kvm->arch.xen;
	int ret;

	if (!any) {
		min = domid;
		max = domid + 1;
	}

	write_lock_bh(&domid_lock);
	ret = idr_alloc(&domid_to_kvm, kvm, min, max, GFP_ATOMIC);
	write_unlock_bh(&domid_lock);

	if (ret < 0)
		return ret;

	xen->domid = ret;
	return 0;
}

static struct kvm *kvm_xen_find_vm(domid_t domid)
{
	unsigned long flags;
	struct kvm *vm;

	read_lock_irqsave(&domid_lock, flags);
	vm = idr_find(&domid_to_kvm, domid);
	read_unlock_irqrestore(&domid_lock, flags);

	return vm;
}

int kvm_xen_free_domid(struct kvm *kvm)
{
	struct kvm_xen *xen = &kvm->arch.xen;
	struct kvm *vm;

	write_lock_bh(&domid_lock);
	vm = idr_remove(&domid_to_kvm, xen->domid);
	write_unlock_bh(&domid_lock);

	synchronize_srcu(&kvm->srcu);

	return vm == kvm;
}

int kvm_xen_has_interrupt(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_xen *vcpu_xen = vcpu_to_xen_vcpu(vcpu);
	struct vcpu_info *vcpu_info = vcpu_to_xen_vcpu_info(vcpu);

	if (!!atomic_read(&vcpu_xen->cb.queued) || (vcpu_info &&
	    test_bit(0, (unsigned long *) &vcpu_info->evtchn_upcall_pending)))
		return 1;

	return -1;
}

int kvm_xen_get_interrupt(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_xen *vcpu_xen = vcpu_to_xen_vcpu(vcpu);
	u32 vector = vcpu_xen->cb.vector;

	if (kvm_xen_has_interrupt(vcpu) == -1)
		return 0;

	atomic_set(&vcpu_xen->cb.queued, 0);
	return vector;
}

static int kvm_xen_do_upcall(struct kvm *kvm, u32 dest_vcpu,
			     u32 via, u32 vector, int level)
{
	struct kvm_vcpu_xen *vcpu_xen;
	struct kvm_lapic_irq irq;
	struct kvm_vcpu *vcpu;

	if (vector > 0xff || vector < 0x10 || dest_vcpu >= KVM_MAX_VCPUS)
		return -EINVAL;

	vcpu = kvm_get_vcpu(kvm, dest_vcpu);
	if (!vcpu)
		return -EINVAL;

	memset(&irq, 0, sizeof(irq));
	if (via == KVM_XEN_CALLBACK_VIA_VECTOR) {
		vcpu_xen = vcpu_to_xen_vcpu(vcpu);
		atomic_set(&vcpu_xen->cb.queued, 1);
		kvm_make_request(KVM_REQ_EVENT, vcpu);
		kvm_vcpu_kick(vcpu);
	} else if (via == KVM_XEN_CALLBACK_VIA_EVTCHN) {
		irq.shorthand = APIC_DEST_SELF;
		irq.dest_mode = APIC_DEST_PHYSICAL;
		irq.delivery_mode = APIC_DM_FIXED;
		irq.vector = vector;
		irq.level = level;

		/* Deliver upcall to a vector on the destination vcpu */
		kvm_irq_delivery_to_apic(kvm, vcpu->arch.apic, &irq, NULL);
	} else {
		return -EINVAL;
	}

	return 0;
}

static void kvm_xen_evtchnfd_upcall(struct kvm_vcpu *vcpu, struct evtchnfd *e)
{
	struct kvm_vcpu_xen *vx = vcpu_to_xen_vcpu(vcpu);

	kvm_xen_do_upcall(vcpu->kvm, e->vcpu, vx->cb.via, vx->cb.vector, 0);
}

int kvm_xen_has_pending_timer(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_xen *vcpu_xen = vcpu_to_xen_vcpu(vcpu);

	if (kvm_xen_hypercall_enabled(vcpu->kvm) && kvm_xen_timer_enabled(vcpu))
		return atomic_read(&vcpu_xen->timer_pending);

	return 0;
}

void kvm_xen_inject_timer_irqs(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_xen *vcpu_xen = vcpu_to_xen_vcpu(vcpu);

	if (atomic_read(&vcpu_xen->timer_pending) > 0) {
		kvm_xen_evtchn_send(vcpu, vcpu_xen->virq_to_port[VIRQ_TIMER]);

		atomic_set(&vcpu_xen->timer_pending, 0);
	}
}

static enum hrtimer_restart xen_timer_callback(struct hrtimer *timer)
{
	struct kvm_vcpu_xen *vcpu_xen =
		container_of(timer, struct kvm_vcpu_xen, timer);
	struct kvm_vcpu *vcpu = xen_vcpu_to_vcpu(vcpu_xen);
	struct swait_queue_head *wq = &vcpu->wq;

	if (atomic_read(&vcpu_xen->timer_pending))
		return HRTIMER_NORESTART;

	atomic_inc(&vcpu_xen->timer_pending);
	kvm_set_pending_timer(vcpu);

	if (swait_active(wq))
		swake_up_one(wq);

	return HRTIMER_NORESTART;
}

void __kvm_migrate_xen_timer(struct kvm_vcpu *vcpu)
{
	struct hrtimer *timer;

	if (!kvm_xen_timer_enabled(vcpu))
		return;

	timer = &vcpu->arch.xen.timer;
	if (hrtimer_cancel(timer))
		hrtimer_start_expires(timer, HRTIMER_MODE_ABS_PINNED);
}

static void kvm_xen_start_timer(struct kvm_vcpu *vcpu, u64 delta_ns)
{
	struct kvm_vcpu_xen *vcpu_xen = vcpu_to_xen_vcpu(vcpu);
	struct hrtimer *timer = &vcpu_xen->timer;
	ktime_t ktime_now;

	atomic_set(&vcpu_xen->timer_pending, 0);
	ktime_now = ktime_get();
	hrtimer_start(timer, ktime_add_ns(ktime_now, delta_ns),
		      HRTIMER_MODE_ABS_PINNED);
}

static void kvm_xen_stop_timer(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_xen *vcpu_xen = vcpu_to_xen_vcpu(vcpu);

	hrtimer_cancel(&vcpu_xen->timer);
}

void kvm_xen_init_timer(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_xen *vcpu_xen = vcpu_to_xen_vcpu(vcpu);

	hrtimer_init(&vcpu_xen->timer, CLOCK_MONOTONIC,
		     HRTIMER_MODE_ABS_PINNED);
	vcpu_xen->timer.function = xen_timer_callback;
}

bool kvm_xen_timer_enabled(struct kvm_vcpu *vcpu)
{
	return !!vcpu->arch.xen.virq_to_port[VIRQ_TIMER];
}

void kvm_xen_set_virq(struct kvm *kvm, struct evtchnfd *evt)
{
	int virq = evt->virq.type;
	struct kvm_vcpu_xen *vcpu_xen;
	struct kvm_vcpu *vcpu;

	vcpu = kvm_get_vcpu(kvm, evt->vcpu);
	if (!vcpu)
		return;

	if (virq == VIRQ_TIMER)
		kvm_xen_init_timer(vcpu);

	vcpu_xen = vcpu_to_xen_vcpu(vcpu);
	vcpu_xen->virq_to_port[virq] = evt->port;
}

int kvm_xen_set_evtchn(struct kvm_kernel_irq_routing_entry *e,
		   struct kvm *kvm, int irq_source_id, int level,
		   bool line_status)
{
	/*
	 * The routing information for the kirq specifies the vector
	 * on the destination vcpu.
	 */
	return kvm_xen_do_upcall(kvm, e->evtchn.vcpu, e->evtchn.via,
				 e->evtchn.vector, level);
}

int kvm_xen_setup_evtchn(struct kvm *kvm,
			 struct kvm_kernel_irq_routing_entry *e)
{
	struct kvm_vcpu_xen *vcpu_xen;
	struct kvm_vcpu *vcpu = NULL;

	if (e->evtchn.vector > 0xff || e->evtchn.vector < 0x10)
		return -EINVAL;

	/* Expect vcpu to be sane */
	if (e->evtchn.vcpu >= KVM_MAX_VCPUS)
		return -EINVAL;

	vcpu = kvm_get_vcpu(kvm, e->evtchn.vcpu);
	if (!vcpu)
		return -EINVAL;

	vcpu_xen = vcpu_to_xen_vcpu(vcpu);
	if (e->evtchn.via == KVM_XEN_CALLBACK_VIA_VECTOR) {
		vcpu_xen->cb.via = KVM_XEN_CALLBACK_VIA_VECTOR;
		vcpu_xen->cb.vector = e->evtchn.vector;
	} else if (e->evtchn.via == KVM_XEN_CALLBACK_VIA_EVTCHN) {
		vcpu_xen->cb.via = KVM_XEN_CALLBACK_VIA_EVTCHN;
		vcpu_xen->cb.vector = e->evtchn.vector;
	} else {
		return -EINVAL;
	}

	return 0;
}

static void set_vcpu_attr(struct kvm_vcpu *v, u16 type, gpa_t gpa, void *addr)
{
	struct kvm_vcpu_xen *vcpu_xen = vcpu_to_xen_vcpu(v);

	switch (type) {
	case KVM_XEN_ATTR_TYPE_VCPU_INFO:
		vcpu_xen->vcpu_info_addr = gpa;
		vcpu_xen->vcpu_info = addr;
		kvm_xen_setup_pvclock_page(v);
		break;
	case KVM_XEN_ATTR_TYPE_VCPU_TIME_INFO:
		vcpu_xen->pv_time_addr = gpa;
		vcpu_xen->pv_time = addr;
		kvm_xen_setup_pvclock_page(v);
		break;
	case KVM_XEN_ATTR_TYPE_VCPU_RUNSTATE:
		vcpu_xen->steal_time_addr = gpa;
		vcpu_xen->steal_time = addr;
		kvm_xen_setup_runstate_page(v);
		break;
	default:
		break;
	}
}

static gpa_t get_vcpu_attr(struct kvm_vcpu *v, u16 type)
{
	struct kvm_vcpu_xen *vcpu_xen = vcpu_to_xen_vcpu(v);

	switch (type) {
	case KVM_XEN_ATTR_TYPE_VCPU_INFO:
		return vcpu_xen->vcpu_info_addr;
	case KVM_XEN_ATTR_TYPE_VCPU_TIME_INFO:
		return vcpu_xen->pv_time_addr;
	case KVM_XEN_ATTR_TYPE_VCPU_RUNSTATE:
		return vcpu_xen->steal_time_addr;
	default:
		return 0;
	}
}

static int kvm_xen_shared_info_init(struct kvm *kvm, gfn_t gfn)
{
	struct shared_info *shared_info;
	struct page *page;
	gpa_t gpa = gfn_to_gpa(gfn);

	page = gfn_to_page(kvm, gfn);
	if (is_error_page(page))
		return -EINVAL;

	kvm->arch.xen.shinfo_addr = gfn;

	shared_info = page_to_virt(page);
	memset(shared_info, 0, sizeof(struct shared_info));
	kvm->arch.xen.shinfo = shared_info;

	kvm_write_wall_clock(kvm, gpa + offsetof(struct shared_info, wc));

	kvm_make_all_cpus_request(kvm, KVM_REQ_MASTERCLOCK_UPDATE);
	return 0;
}

static void *vcpu_to_xen_vcpu_info(struct kvm_vcpu *v)
{
	struct kvm_vcpu_xen *vcpu_xen = vcpu_to_xen_vcpu(v);
	struct kvm_xen *kvm = &v->kvm->arch.xen;
	unsigned int offset = 0;
	void *hva = NULL;

	if (vcpu_xen->vcpu_info_addr)
		return vcpu_xen->vcpu_info;

	if (kvm->shinfo_addr && v->vcpu_id < MAX_VIRT_CPUS) {
		hva = kvm->shinfo;
		offset += offsetof(struct shared_info, vcpu_info);
		offset += v->vcpu_id * sizeof(struct vcpu_info);
	}

	return hva + offset;
}

static void kvm_xen_update_vcpu_time(struct kvm_vcpu *v,
				 struct pvclock_vcpu_time_info *guest_hv_clock)
{
	struct kvm_vcpu_arch *vcpu = &v->arch;

	BUILD_BUG_ON(offsetof(struct pvclock_vcpu_time_info, version) != 0);

	if (guest_hv_clock->version & 1)
		++guest_hv_clock->version;

	vcpu->hv_clock.version = guest_hv_clock->version + 1;
	guest_hv_clock->version = vcpu->hv_clock.version;

	smp_wmb();

	/* retain PVCLOCK_GUEST_STOPPED if set in guest copy */
	vcpu->hv_clock.flags |= (guest_hv_clock->flags & PVCLOCK_GUEST_STOPPED);

	if (vcpu->pvclock_set_guest_stopped_request) {
		vcpu->hv_clock.flags |= PVCLOCK_GUEST_STOPPED;
		vcpu->pvclock_set_guest_stopped_request = false;
	}

	trace_kvm_pvclock_update(v->vcpu_id, &vcpu->hv_clock);

	*guest_hv_clock = vcpu->hv_clock;

	smp_wmb();

	vcpu->hv_clock.version++;

	guest_hv_clock->version = vcpu->hv_clock.version;
}

void kvm_xen_runstate_set_preempted(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_xen *vcpu_xen = vcpu_to_xen_vcpu(vcpu);
	int state = RUNSTATE_runnable;

	vcpu->arch.st.steal.preempted = KVM_VCPU_PREEMPTED;

	vcpu_xen->steal_time->state = state;
}

void kvm_xen_setup_runstate_page(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_xen *vcpu_xen = vcpu_to_xen_vcpu(vcpu);
	struct vcpu_runstate_info runstate;

	runstate = *vcpu_xen->steal_time;

	runstate.state_entry_time += 1;
	runstate.state_entry_time |= XEN_RUNSTATE_UPDATE;
	vcpu_xen->steal_time->state_entry_time = runstate.state_entry_time;
	smp_wmb();

	vcpu->arch.st.steal.steal += current->sched_info.run_delay -
		vcpu->arch.st.last_steal;
	vcpu->arch.st.last_steal = current->sched_info.run_delay;

	runstate.state = RUNSTATE_running;
	runstate.time[RUNSTATE_runnable] = vcpu->arch.st.steal.steal;
	*vcpu_xen->steal_time = runstate;

	runstate.state_entry_time &= ~XEN_RUNSTATE_UPDATE;
	vcpu_xen->steal_time->state_entry_time = runstate.state_entry_time;
	smp_wmb();
}

void kvm_xen_setup_pvclock_page(struct kvm_vcpu *v)
{
	struct kvm_vcpu_xen *vcpu_xen = vcpu_to_xen_vcpu(v);
	struct pvclock_vcpu_time_info *guest_hv_clock;
	void *hva = vcpu_to_xen_vcpu_info(v);
	unsigned int offset;

	offset = offsetof(struct vcpu_info, time);
	guest_hv_clock = (struct pvclock_vcpu_time_info *) (hva + offset);

	if (likely(hva))
		kvm_xen_update_vcpu_time(v, guest_hv_clock);

	/* Update secondary pvclock region if registered */
	if (vcpu_xen->pv_time_addr) {
		guest_hv_clock = vcpu_xen->pv_time;
		kvm_xen_update_vcpu_time(v, guest_hv_clock);
	}
}

int kvm_xen_hvm_set_attr(struct kvm *kvm, struct kvm_xen_hvm_attr *data)
{
	int r = -ENOENT;

	switch (data->type) {
	case KVM_XEN_ATTR_TYPE_SHARED_INFO: {
		gfn_t gfn = data->u.shared_info.gfn;

		r = kvm_xen_shared_info_init(kvm, gfn);
		break;
	}
	case KVM_XEN_ATTR_TYPE_VCPU_RUNSTATE:
		if (unlikely(!sched_info_on()))
			return -ENOTSUPP;
	/* fallthrough */
	case KVM_XEN_ATTR_TYPE_VCPU_TIME_INFO:
	case KVM_XEN_ATTR_TYPE_VCPU_INFO: {
		gpa_t gpa = data->u.vcpu_attr.gpa;
		struct kvm_vcpu *v;
		struct page *page;
		void *addr;

		v = kvm_get_vcpu(kvm, data->u.vcpu_attr.vcpu);
		if (!v)
			return -EINVAL;

		page = gfn_to_page(v->kvm, gpa_to_gfn(gpa));
		if (is_error_page(page))
			return -EFAULT;

		addr = page_to_virt(page) + offset_in_page(gpa);
		set_vcpu_attr(v, data->type, gpa, addr);
		r = 0;
		break;
	}
	case KVM_XEN_ATTR_TYPE_EVTCHN: {
		struct kvm_xen_eventfd xevfd = data->u.evtchn;

		r = kvm_vm_ioctl_xen_eventfd(kvm, &xevfd);
		break;
	}
	case KVM_XEN_ATTR_TYPE_DOMID: {
		domid_t domid = (u16) data->u.dom.domid;
		bool any = (data->u.dom.domid < 0);

		/* Domain ID 0 or >= 0x7ff0 are reserved */
		if (!any && (!domid || (domid >= XEN_DOMID_MAX)))
			return -EINVAL;

		r = kvm_xen_domid_init(kvm, any, domid);
		break;
	}
	case KVM_XEN_ATTR_TYPE_GNTTAB: {
		struct kvm_xen_gnttab xevfd = data->u.gnttab;

		r = kvm_vm_ioctl_xen_gnttab(kvm, &xevfd);
		break;
	}
	default:
		break;
	}

	return r;
}

int kvm_xen_hvm_get_attr(struct kvm *kvm, struct kvm_xen_hvm_attr *data)
{
	int r = -ENOENT;

	switch (data->type) {
	case KVM_XEN_ATTR_TYPE_SHARED_INFO: {
		data->u.shared_info.gfn = kvm->arch.xen.shinfo_addr;
		break;
	}
	case KVM_XEN_ATTR_TYPE_VCPU_RUNSTATE:
	case KVM_XEN_ATTR_TYPE_VCPU_TIME_INFO:
	case KVM_XEN_ATTR_TYPE_VCPU_INFO: {
		struct kvm_vcpu *v;

		v = kvm_get_vcpu(kvm, data->u.vcpu_attr.vcpu);
		if (!v)
			return -EINVAL;

		data->u.vcpu_attr.gpa = get_vcpu_attr(v, data->type);
		r = 0;
		break;
	}
	case KVM_XEN_ATTR_TYPE_DOMID: {
		data->u.dom.domid = kvm->arch.xen.domid;
		r = 0;
		break;
	}
	default:
		break;
	}

	return r;
}

bool kvm_xen_hypercall_enabled(struct kvm *kvm)
{
	return READ_ONCE(kvm->arch.xen.xen_hypercall);
}

bool kvm_xen_hypercall_set(struct kvm *kvm)
{
	return WRITE_ONCE(kvm->arch.xen.xen_hypercall, 1);
}

static void kvm_xen_hypercall_set_result(struct kvm_vcpu *vcpu, u64 result)
{
	kvm_register_write(vcpu, VCPU_REGS_RAX, result);
}

static int kvm_xen_hypercall_complete_userspace(struct kvm_vcpu *vcpu)
{
	struct kvm_run *run = vcpu->run;

	kvm_xen_hypercall_set_result(vcpu, run->xen.u.hcall.result);
	return kvm_skip_emulated_instruction(vcpu);
}

static int kvm_xen_evtchn_2l_vcpu_set_pending(struct vcpu_info *v)
{
	return test_and_set_bit(0, (unsigned long *) &v->evtchn_upcall_pending);
}

#define BITS_PER_EVTCHN_WORD (sizeof(xen_ulong_t)*8)

static int kvm_xen_evtchn_2l_set_pending(struct shared_info *shared_info,
					 struct vcpu_info *vcpu_info,
					 int p)
{
	if (test_and_set_bit(p, (unsigned long *) shared_info->evtchn_pending))
		return 1;

	if (!test_bit(p, (unsigned long *) shared_info->evtchn_mask) &&
	    !test_and_set_bit(p / BITS_PER_EVTCHN_WORD,
			      (unsigned long *) &vcpu_info->evtchn_pending_sel))
		return kvm_xen_evtchn_2l_vcpu_set_pending(vcpu_info);

	return 1;
}

static int kvm_xen_evtchn_set_pending(struct kvm_vcpu *svcpu,
				      struct evtchnfd *evfd)
{
	struct kvm_vcpu_xen *vcpu_xen;
	struct vcpu_info *vcpu_info;
	struct shared_info *shared_info;
	struct kvm_vcpu *vcpu;

	vcpu = kvm_get_vcpu(svcpu->kvm, evfd->vcpu);
	if (!vcpu)
		return -ENOENT;

	vcpu_xen = vcpu_to_xen_vcpu(vcpu);
	shared_info = (struct shared_info *) vcpu->kvm->arch.xen.shinfo;
	vcpu_info = (struct vcpu_info *) vcpu_xen->vcpu_info;

	return kvm_xen_evtchn_2l_set_pending(shared_info, vcpu_info,
					     evfd->port);
}

static void kvm_xen_check_poller(struct kvm_vcpu *vcpu, int port)
{
	struct kvm_vcpu_xen *vcpu_xen = vcpu_to_xen_vcpu(vcpu);

	if ((vcpu_xen->poll_evtchn == port ||
	     vcpu_xen->poll_evtchn == -1) &&
	    test_and_clear_bit(vcpu->vcpu_id, vcpu->kvm->arch.xen.poll_mask))
		wake_up(&vcpu_xen->sched_waitq);
}

static void kvm_xen_evtchn_2l_reset_port(struct shared_info *shared_info,
					 int port)
{
	clear_bit(port, (unsigned long *) shared_info->evtchn_pending);
	clear_bit(port, (unsigned long *) shared_info->evtchn_mask);
}

static inline struct evtchnfd *port_to_evtchn(struct kvm *kvm, int port)
{
	struct kvm_xen *xen = kvm ? &kvm->arch.xen : xen_shim;

	return idr_find(&xen->port_to_evt, port);
}

static struct kvm_vcpu *get_remote_vcpu(struct evtchnfd *source)
{
	struct kvm *rkvm = source->remote.vm;
	int rport = source->remote.port;
	struct evtchnfd *dest = NULL;
	struct kvm_vcpu *vcpu = NULL;

	WARN_ON(source->type <= XEN_EVTCHN_TYPE_IPI);

	if (!rkvm)
		return NULL;

	/* conn_to_evt is protected by vcpu->kvm->srcu */
	dest = port_to_evtchn(rkvm, rport);
	if (!dest)
		return NULL;

	vcpu = kvm_get_vcpu(rkvm, dest->vcpu);
	return vcpu;
}

static int kvm_xen_evtchn_send(struct kvm_vcpu *vcpu, int port)
{
	struct kvm_vcpu *target = vcpu;
	struct eventfd_ctx *eventfd;
	struct evtchnfd *evtchnfd;

	/* conn_to_evt is protected by vcpu->kvm->srcu */
	evtchnfd = idr_find(&vcpu->kvm->arch.xen.port_to_evt, port);
	if (!evtchnfd)
		return -ENOENT;

	if (evtchnfd->type == XEN_EVTCHN_TYPE_INTERDOM ||
	    evtchnfd->type == XEN_EVTCHN_TYPE_UNBOUND) {
		target = get_remote_vcpu(evtchnfd);
		port = evtchnfd->remote.port;

		if (!target && !evtchnfd->remote.dom)
			return kvm_xen_evtchn_send_shim(xen_shim, evtchnfd);
	}

	eventfd = evtchnfd->ctx;
	if (!kvm_xen_evtchn_set_pending(target, evtchnfd)) {
		if (!eventfd)
			kvm_xen_evtchnfd_upcall(target, evtchnfd);
		else
			eventfd_signal(eventfd, 1);
	}

	kvm_xen_check_poller(kvm_get_vcpu(vcpu->kvm, evtchnfd->vcpu), port);

	return 0;
}

static int kvm_xen_hcall_evtchn_send(struct kvm_vcpu *vcpu, int cmd, u64 param)
{
	struct evtchn_send send;
	gpa_t gpa;
	int idx;

	/* Port management is done in userspace */
	if (cmd != EVTCHNOP_send)
		return -EINVAL;

	idx = srcu_read_lock(&vcpu->kvm->srcu);
	gpa = kvm_mmu_gva_to_gpa_system(vcpu, param, NULL);
	srcu_read_unlock(&vcpu->kvm->srcu, idx);

	if (!gpa || kvm_vcpu_read_guest(vcpu, gpa, &send, sizeof(send)))
		return -EFAULT;

	return kvm_xen_evtchn_send(vcpu, send.port);
}

static int kvm_xen_hcall_vcpu_op(struct kvm_vcpu *vcpu, int cmd, int vcpu_id,
				 u64 param)
{
	struct vcpu_set_singleshot_timer oneshot;
	int ret = -EINVAL;
	long delta;
	gpa_t gpa;
	int idx;

	/* Only process timer ops with commands 6 to 9 */
	if (cmd < VCPUOP_set_periodic_timer ||
	    cmd > VCPUOP_stop_singleshot_timer)
		return ret;

	if (!kvm_xen_timer_enabled(vcpu))
		return ret;

	idx = srcu_read_lock(&vcpu->kvm->srcu);
	gpa = kvm_mmu_gva_to_gpa_system(vcpu, param, NULL);
	srcu_read_unlock(&vcpu->kvm->srcu, idx);

	if (!gpa)
		return ret;

	switch (cmd) {
	case VCPUOP_set_singleshot_timer:
		if (kvm_vcpu_read_guest(vcpu, gpa, &oneshot,
					sizeof(oneshot)))
			return -EFAULT;

		delta = oneshot.timeout_abs_ns - get_kvmclock_ns(vcpu->kvm);
		kvm_xen_start_timer(vcpu, delta);
		ret = 0;
		break;
	case VCPUOP_stop_singleshot_timer:
		kvm_xen_stop_timer(vcpu);
		ret = 0;
		break;
	default:
		break;
	}

	return ret;
}

static int kvm_xen_hcall_set_timer_op(struct kvm_vcpu *vcpu, uint64_t timeout)
{
	ktime_t ktime_now = ktime_get();
	long delta = timeout - get_kvmclock_ns(vcpu->kvm);

	if (!kvm_xen_timer_enabled(vcpu))
		return -EINVAL;

	if (timeout == 0) {
		kvm_xen_stop_timer(vcpu);
	} else if (unlikely(timeout < ktime_now) ||
		   ((uint32_t) (delta >> 50) != 0)) {
		kvm_xen_start_timer(vcpu, 50000000);
	} else {
		kvm_xen_start_timer(vcpu, delta);
	}

	return 0;
}

static bool wait_pending_event(struct kvm_vcpu *vcpu, int nr_ports,
			       evtchn_port_t *ports)
{
	int i;
	struct shared_info *shared_info =
		(struct shared_info *)vcpu->kvm->arch.xen.shinfo;

	for (i = 0; i < nr_ports; i++)
		if (test_bit(ports[i],
			     (unsigned long *)shared_info->evtchn_pending))
			return true;

	return false;
}

static int kvm_xen_schedop_poll(struct kvm_vcpu *vcpu, gpa_t gpa)
{
	struct kvm_vcpu_xen *vcpu_xen = vcpu_to_xen_vcpu(vcpu);
	int idx, i;
	struct sched_poll sched_poll;
	evtchn_port_t port, *ports;
	struct shared_info *shared_info;
	struct evtchnfd *evtchnfd;
	int ret = 0;

	if (kvm_vcpu_read_guest(vcpu, gpa,
				&sched_poll, sizeof(sched_poll)))
		return -EFAULT;

	shared_info = (struct shared_info *)vcpu->kvm->arch.xen.shinfo;

	if (unlikely(sched_poll.nr_ports > 1)) {
		/* Xen (unofficially) limits number of pollers to 128 */
		if (sched_poll.nr_ports > 128)
			return -EINVAL;

		ports = kmalloc_array(sched_poll.nr_ports,
				      sizeof(*ports), GFP_KERNEL);
		if (!ports)
			return -ENOMEM;
	} else
		ports = &port;

	set_bit(vcpu->vcpu_id, vcpu->kvm->arch.xen.poll_mask);

	for (i = 0; i < sched_poll.nr_ports; i++) {
		idx = srcu_read_lock(&vcpu->kvm->srcu);
		gpa = kvm_mmu_gva_to_gpa_system(vcpu,
						(gva_t)(sched_poll.ports + i),
						NULL);
		srcu_read_unlock(&vcpu->kvm->srcu, idx);

		if (!gpa || kvm_vcpu_read_guest(vcpu, gpa,
						&ports[i], sizeof(port))) {
			ret = -EFAULT;
			goto out;
		}

		evtchnfd = idr_find(&vcpu->kvm->arch.xen.port_to_evt,
				    ports[i]);
		if (!evtchnfd) {
			ret = -ENOENT;
			goto out;
		}
	}

	if (sched_poll.nr_ports == 1)
		vcpu_xen->poll_evtchn = port;
	else
		vcpu_xen->poll_evtchn = -1;

	if (!wait_pending_event(vcpu, sched_poll.nr_ports, ports))
		wait_event_interruptible_timeout(
			 vcpu_xen->sched_waitq,
			 wait_pending_event(vcpu, sched_poll.nr_ports, ports),
			 sched_poll.timeout ?: KTIME_MAX);

	vcpu_xen->poll_evtchn = 0;

out:
	/* Really, this is only needed in case of timeout */
	clear_bit(vcpu->vcpu_id, vcpu->kvm->arch.xen.poll_mask);

	if (unlikely(sched_poll.nr_ports > 1))
		kfree(ports);
	return ret;
}

static int kvm_xen_hcall_sched_op(struct kvm_vcpu *vcpu, int cmd, u64 param)
{
	int ret = -ENOSYS;
	gpa_t gpa;
	int idx;

	idx = srcu_read_lock(&vcpu->kvm->srcu);
	gpa = kvm_mmu_gva_to_gpa_system(vcpu, param, NULL);
	srcu_read_unlock(&vcpu->kvm->srcu, idx);

	if (!gpa)
		return -EFAULT;

	switch (cmd) {
	case SCHEDOP_yield:
		kvm_vcpu_on_spin(vcpu, true);
		ret = 0;
		break;
	case SCHEDOP_poll:
		ret = kvm_xen_schedop_poll(vcpu, gpa);
		break;
	default:
		break;
	}

	return ret;
}

static void kvm_xen_call_function_deliver(void *_)
{
	xen_hvm_evtchn_do_upcall();
}

static inline int kvm_xen_evtchn_call_function(struct evtchnfd *event)
{
	int ret;

	if (!irqs_disabled())
		return smp_call_function_single(event->vcpu,
						kvm_xen_call_function_deliver,
						NULL, 0);

	local_irq_enable();
	ret = smp_call_function_single(event->vcpu,
				       kvm_xen_call_function_deliver, NULL, 0);
	local_irq_disable();

	return ret;
}

static int kvm_xen_evtchn_send_shim(struct kvm_xen *dom0, struct evtchnfd *e)
{
	struct shared_info *s = HYPERVISOR_shared_info;
	struct evtchnfd *remote;
	int pending;

	remote = idr_find(&dom0->port_to_evt, e->remote.port);
	if (!remote)
		return -ENOENT;

	pending = kvm_xen_evtchn_2l_set_pending(s,
						per_cpu(xen_vcpu, remote->vcpu),
						remote->port);
	return kvm_xen_evtchn_call_function(remote);
}

static int __kvm_xen_evtchn_send_guest(struct kvm_vcpu *vcpu, int port)
{
	struct evtchnfd *evtchnfd;
	struct eventfd_ctx *eventfd;

	/* conn_to_evt is protected by vcpu->kvm->srcu */
	evtchnfd = idr_find(&vcpu->kvm->arch.xen.port_to_evt, port);
	if (!evtchnfd)
		return -ENOENT;

	eventfd = evtchnfd->ctx;
	if (!kvm_xen_evtchn_set_pending(vcpu, evtchnfd))
		kvm_xen_evtchnfd_upcall(vcpu, evtchnfd);

	kvm_xen_check_poller(kvm_get_vcpu(vcpu->kvm, evtchnfd->vcpu), port);
	return 0;
}

static int kvm_xen_evtchn_send_guest(struct evtchnfd *evt, int port)
{
	return __kvm_xen_evtchn_send_guest(get_remote_vcpu(evt), port);
}

int kvm_xen_hypercall(struct kvm_vcpu *vcpu)
{
	bool longmode;
	u64 input, params[5];
	int r;

	input = (u64)kvm_register_read(vcpu, VCPU_REGS_RAX);

	longmode = is_64_bit_mode(vcpu);
	if (!longmode) {
		params[0] = (u64)kvm_register_read(vcpu, VCPU_REGS_RBX);
		params[1] = (u64)kvm_register_read(vcpu, VCPU_REGS_RCX);
		params[2] = (u64)kvm_register_read(vcpu, VCPU_REGS_RDX);
		params[3] = (u64)kvm_register_read(vcpu, VCPU_REGS_RSI);
		params[4] = (u64)kvm_register_read(vcpu, VCPU_REGS_RDI);
	}
#ifdef CONFIG_X86_64
	else {
		params[0] = (u64)kvm_register_read(vcpu, VCPU_REGS_RDI);
		params[1] = (u64)kvm_register_read(vcpu, VCPU_REGS_RSI);
		params[2] = (u64)kvm_register_read(vcpu, VCPU_REGS_RDX);
		params[3] = (u64)kvm_register_read(vcpu, VCPU_REGS_R10);
		params[4] = (u64)kvm_register_read(vcpu, VCPU_REGS_R8);
	}
#endif
	trace_kvm_xen_hypercall(input, params[0], params[1], params[2],
				params[3], params[4]);

	switch (input) {
	case __HYPERVISOR_event_channel_op:
		r = kvm_xen_hcall_evtchn_send(vcpu, params[0],
					      params[1]);
		if (!r)
			goto hcall_success;
		break;
	case __HYPERVISOR_vcpu_op:
		r = kvm_xen_hcall_vcpu_op(vcpu, params[0], params[1],
					  params[2]);
		if (!r)
			goto hcall_success;
		break;
	case __HYPERVISOR_set_timer_op:
		r = kvm_xen_hcall_set_timer_op(vcpu, params[0]);
		if (!r)
			goto hcall_success;
		break;
	case __HYPERVISOR_sched_op:
		r = kvm_xen_hcall_sched_op(vcpu, params[0], params[1]);
		if (!r)
			goto hcall_success;
		else if (params[0] == SCHEDOP_poll)
			/* SCHEDOP_poll should be handled in kernel */
			return r;
		break;
	/* fallthrough */
	default:
		break;
	}

	vcpu->run->exit_reason = KVM_EXIT_XEN;
	vcpu->run->xen.type = KVM_EXIT_XEN_HCALL;
	vcpu->run->xen.u.hcall.input = input;
	vcpu->run->xen.u.hcall.params[0] = params[0];
	vcpu->run->xen.u.hcall.params[1] = params[1];
	vcpu->run->xen.u.hcall.params[2] = params[2];
	vcpu->run->xen.u.hcall.params[3] = params[3];
	vcpu->run->xen.u.hcall.params[4] = params[4];
	vcpu->arch.complete_userspace_io =
		kvm_xen_hypercall_complete_userspace;

	return 0;

hcall_success:
	kvm_xen_hypercall_set_result(vcpu, r);
	return kvm_skip_emulated_instruction(vcpu);
}

void kvm_xen_vcpu_init(struct kvm_vcpu *vcpu)
{
	init_waitqueue_head(&vcpu->arch.xen.sched_waitq);
	vcpu->arch.xen.poll_evtchn = 0;
}

void kvm_xen_vcpu_uninit(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_xen *vcpu_xen = vcpu_to_xen_vcpu(vcpu);

	if (vcpu_xen->vcpu_info)
		put_page(virt_to_page(vcpu_xen->vcpu_info));
	if (vcpu_xen->pv_time)
		put_page(virt_to_page(vcpu_xen->pv_time));
	if (vcpu_xen->steal_time)
		put_page(virt_to_page(vcpu_xen->steal_time));

	if (!kvm_xen_timer_enabled(vcpu))
		return;

	kvm_xen_stop_timer(vcpu);
}

void kvm_xen_init_vm(struct kvm *kvm)
{
	mutex_init(&kvm->arch.xen.xen_lock);
	idr_init(&kvm->arch.xen.port_to_evt);
}

void kvm_xen_destroy_vm(struct kvm *kvm)
{
	struct kvm_xen *xen = &kvm->arch.xen;

	if (xen->shinfo)
		put_page(virt_to_page(xen->shinfo));

	kvm_xen_free_domid(kvm);
	kvm_xen_gnttab_free(&kvm->arch.xen);
}

void kvm_xen_init(void)
{
	idr_init(&domid_to_kvm);
	rwlock_init(&domid_lock);
}

void kvm_xen_exit(void)
{
}

static int kvm_xen_eventfd_update(struct kvm *kvm, struct idr *port_to_evt,
				  struct mutex *port_lock,
				  struct kvm_xen_eventfd *args)
{
	struct eventfd_ctx *eventfd = NULL;
	struct evtchnfd *evtchnfd;

	mutex_lock(port_lock);
	evtchnfd = idr_find(port_to_evt, args->port);
	mutex_unlock(port_lock);

	if (!evtchnfd)
		return -ENOENT;

	if (args->fd != -1) {
		eventfd = eventfd_ctx_fdget(args->fd);
		if (IS_ERR(eventfd))
			return PTR_ERR(eventfd);
	}

	evtchnfd->vcpu = args->vcpu;
	return 0;
}

int kvm_xen_eventfd_assign(struct kvm *kvm, struct idr *port_to_evt,
			   struct mutex *port_lock,
			   struct kvm_xen_eventfd *args)
{
	struct evtchnfd *evtchnfd, *unbound = NULL;
	struct eventfd_ctx *eventfd = NULL;
	struct kvm *remote_vm = NULL;
	u32 port = args->port;
	u32 endport = 0;
	int ret;

	if (args->fd != -1) {
		eventfd = eventfd_ctx_fdget(args->fd);
		if (IS_ERR(eventfd))
			return PTR_ERR(eventfd);
	}

	if (args->type == XEN_EVTCHN_TYPE_VIRQ &&
	    args->virq.type >= KVM_XEN_NR_VIRQS)
		return -EINVAL;

	if (args->remote.domid == DOMID_SELF)
		remote_vm = kvm;
	else if (args->remote.domid == xen_shim->domid)
		remote_vm = NULL;
	else if ((args->type == XEN_EVTCHN_TYPE_INTERDOM ||
		  args->type == XEN_EVTCHN_TYPE_UNBOUND)) {
		remote_vm = kvm_xen_find_vm(args->remote.domid);
		if (!remote_vm)
			return -ENOENT;
	}

	if (args->type == XEN_EVTCHN_TYPE_INTERDOM) {
		unbound = port_to_evtchn(remote_vm, args->remote.port);
		if (!unbound)
			return -ENOENT;
	}

	evtchnfd =  kzalloc(sizeof(struct evtchnfd), GFP_KERNEL);
	if (!evtchnfd)
		return -ENOMEM;

	evtchnfd->ctx = eventfd;
	evtchnfd->vcpu = args->vcpu;
	evtchnfd->type = args->type;

	if (evtchnfd->type == XEN_EVTCHN_TYPE_VIRQ)
		evtchnfd->virq.type = args->virq.type;
	else if ((evtchnfd->type == XEN_EVTCHN_TYPE_UNBOUND) ||
		 (evtchnfd->type == XEN_EVTCHN_TYPE_INTERDOM)) {
		evtchnfd->remote.dom = args->remote.domid;
		evtchnfd->remote.vm = remote_vm;
		evtchnfd->remote.port = args->remote.port;
	}

	if (port == 0)
		port = 1; /* evtchns in range (0..INT_MAX] */
	else
		endport = port + 1;

	mutex_lock(port_lock);
	ret = idr_alloc(port_to_evt, evtchnfd, port, endport,
			GFP_KERNEL);
	mutex_unlock(port_lock);

	if (ret >= 0) {
		evtchnfd->port = args->port = ret;
		if (kvm && evtchnfd->type == XEN_EVTCHN_TYPE_VIRQ)
			kvm_xen_set_virq(kvm, evtchnfd);
		else if (evtchnfd->type == XEN_EVTCHN_TYPE_INTERDOM)
			unbound->remote.port = ret;
		return 0;
	}

	if (ret == -ENOSPC)
		ret = -EEXIST;

	if (eventfd)
		eventfd_ctx_put(eventfd);
	kfree(evtchnfd);
	return ret;
}

static int kvm_xen_eventfd_deassign(struct kvm *kvm, struct idr *port_to_evt,
				  struct mutex *port_lock, u32 port)
{
	struct evtchnfd *evtchnfd;

	mutex_lock(port_lock);
	evtchnfd = idr_remove(port_to_evt, port);
	mutex_unlock(port_lock);

	if (!evtchnfd)
		return -ENOENT;

	if (!kvm) {
		struct shared_info *shinfo = HYPERVISOR_shared_info;

		kvm_xen_evtchn_2l_reset_port(shinfo, port);
	} else {
		synchronize_srcu(&kvm->srcu);
	}

	if (evtchnfd->ctx)
		eventfd_ctx_put(evtchnfd->ctx);
	kfree(evtchnfd);
	return 0;
}

int kvm_vm_ioctl_xen_eventfd(struct kvm *kvm, struct kvm_xen_eventfd *args)
{
	struct kvm_xen *xen = &kvm->arch.xen;
	int allowed_flags = (KVM_XEN_EVENTFD_DEASSIGN | KVM_XEN_EVENTFD_UPDATE);

	if ((args->flags & (~allowed_flags)) ||
	    (args->port <= 0))
		return -EINVAL;

	if (args->flags == KVM_XEN_EVENTFD_DEASSIGN)
		return kvm_xen_eventfd_deassign(kvm, &xen->port_to_evt,
						&xen->xen_lock, args->port);
	if (args->flags == KVM_XEN_EVENTFD_UPDATE)
		return kvm_xen_eventfd_update(kvm, &xen->port_to_evt,
					      &xen->xen_lock, args);
	return kvm_xen_eventfd_assign(kvm, &xen->port_to_evt,
				      &xen->xen_lock, args);
}

int kvm_xen_gnttab_init(struct kvm *kvm, struct kvm_xen *xen,
			struct kvm_xen_gnttab *op, int dom0)
{
	u32 max_mt_frames = op->init.max_maptrack_frames;
	unsigned long initial = op->init.initial_frame;
	struct kvm_grant_table *gnttab = &xen->gnttab;
	u32 max_frames = op->init.max_frames;
	struct page *page = NULL;
	void *addr;

	if (!dom0) {
		if (!op->init.initial_frame ||
		    offset_in_page(op->init.initial_frame))
			return -EINVAL;

		if (get_user_pages_fast(initial, 1, 1, &page) != 1)
			return -EFAULT;

		gnttab->initial_addr = initial;
		gnttab->initial = page_to_virt(page);
		put_page(page);
	}

	addr = kcalloc(max_frames, sizeof(gfn_t), GFP_KERNEL);
	if (!addr)
		goto out;
	xen->gnttab.frames_addr = addr;

	addr = kcalloc(max_frames, sizeof(addr), GFP_KERNEL);
	if (!addr)
		goto out;

	gnttab->frames = addr;
	gnttab->frames[0] = xen->gnttab.initial;
	gnttab->max_nr_frames = max_frames;

	addr = kcalloc(max_mt_frames, sizeof(addr), GFP_KERNEL);
	if (!addr)
		goto out;

	/* Needs to be aligned at 16b boundary. */
	gnttab->handle = addr;
	gnttab->max_mt_frames = max_mt_frames;

	addr = (void *) get_zeroed_page(GFP_KERNEL);
	if (!addr)
		goto out;
	gnttab->handle[0] = addr;

	gnttab->nr_mt_frames = 1;
	gnttab->nr_frames = 0;

	pr_debug("kvm_xen: dom%u: grant table limits (gnttab:%d maptrack:%d)\n",
		 xen->domid, gnttab->max_nr_frames, gnttab->max_mt_frames);
	return 0;

out:
	kfree(xen->gnttab.handle);
	kfree(xen->gnttab.frames);
	kfree(xen->gnttab.frames_addr);
	if (page)
		put_page(page);
	memset(&xen->gnttab, 0, sizeof(xen->gnttab));
	return -ENOMEM;
}

static void kvm_xen_maptrack_free(struct kvm_xen *xen)
{
	u32 max_entries = xen->gnttab.nr_mt_frames * MPP;
	struct kvm_grant_map *map;
	int ref, inuse = 0;

	for (ref = 0; ref < max_entries; ref++) {
		map = maptrack_entry(xen->gnttab.handle, ref);

		if (test_and_clear_bit(_KVM_GNTMAP_ACTIVE,
				       (unsigned long *)&map->flags)) {
			put_page(virt_to_page(map->gpa));
			inuse++;
		}
	}

	if (inuse)
		pr_debug("kvm: dom%u teardown %u mappings\n",
			 xen->domid, inuse);
}

void kvm_xen_gnttab_free(struct kvm_xen *xen)
{
	struct kvm_grant_table *gnttab = &xen->gnttab;
	int i;

	if (xen->domid)
		kvm_xen_maptrack_free(xen);

	for (i = 0; i < gnttab->nr_mt_frames; i++)
		free_page((unsigned long)gnttab->handle[i]);

	for (i = 0; i < gnttab->nr_frames; i++)
		put_page(virt_to_page(gnttab->frames[i]));

	kfree(gnttab->frames);
	kfree(gnttab->frames_addr);
}

int kvm_xen_gnttab_copy_initial_frame(struct kvm *kvm)
{
	struct kvm_grant_table *gnttab = &kvm->arch.xen.gnttab;
	int idx = 0;

	/* Only meant to copy the first gpa being populated */
	if (!gnttab->initial_addr || !gnttab->frames[idx])
		return -EINVAL;

	memcpy(gnttab->frames[idx], gnttab->initial, PAGE_SIZE);
	return 0;
}

int kvm_xen_maptrack_grow(struct kvm_xen *xen, u32 target)
{
	u32 max_entries = target * GPP_V1;
	u32 nr_entries = xen->gnttab.nr_mt_frames * MPP;
	int i, j, err = 0;
	void *addr;

	for (i = nr_entries, j = xen->gnttab.nr_mt_frames;
	     i < max_entries; i += MPP, j++) {
		addr = (void *) get_zeroed_page(GFP_KERNEL);
		if (!addr) {
			err = -ENOMEM;
			break;
		}

		xen->gnttab.handle[j] = addr;
	}

	xen->gnttab.nr_mt_frames = j;
	xen->gnttab.nr_frames = target;
	return err;
}

int kvm_xen_gnttab_grow(struct kvm *kvm, struct kvm_xen_gnttab *op)
{
	struct kvm_xen *xen = &kvm->arch.xen;
	struct kvm_grant_table *gnttab = &xen->gnttab;
	gfn_t *map = gnttab->frames_addr;
	u64 gfn = op->grow.gfn;
	u32 idx = op->grow.idx;
	struct page *page;

	if (idx < gnttab->nr_frames || idx >= gnttab->max_nr_frames)
		return -EINVAL;

	if (!idx && !gnttab->nr_frames &&
	    !gnttab->initial) {
		return -EINVAL;
	}

	page = gfn_to_page(kvm, gfn);
	if (is_error_page(page))
		return -EINVAL;

	map[idx] = gfn;

	gnttab->frames[idx] = page_to_virt(page);
	if (!idx && !gnttab->nr_frames &&
	    kvm_xen_gnttab_copy_initial_frame(kvm)) {
		pr_err("kvm_xen: dom%u: failed to copy initial frame\n",
			xen->domid);
		return -EFAULT;
	}

	if (kvm_xen_maptrack_grow(xen, gnttab->nr_frames + 1)) {
		pr_warn("kvm_xen: dom%u: cannot grow maptrack\n", xen->domid);
		return -EFAULT;
	}

	pr_debug("kvm_xen: dom%u: grant table grow frames:%d/%d\n", xen->domid,
		 gnttab->nr_frames, gnttab->max_nr_frames);
	return 0;
}

int kvm_vm_ioctl_xen_gnttab(struct kvm *kvm, struct kvm_xen_gnttab *op)
{
	int r = -EINVAL;

	if (!op)
		return r;

	switch (op->flags) {
	case KVM_XEN_GNTTAB_F_INIT:
		r = kvm_xen_gnttab_init(kvm, &kvm->arch.xen, op, 0);
		break;
	case KVM_XEN_GNTTAB_F_GROW:
		r = kvm_xen_gnttab_grow(kvm, op);
		break;
	default:
		r = -ENOSYS;
		break;
	}

	return r;
}

asmlinkage int kvm_xen_host_hcall(void)
{
	register unsigned long a0 asm(__HYPERCALL_RETREG);
	register unsigned long a1 asm(__HYPERCALL_ARG1REG);
	register unsigned long a2 asm(__HYPERCALL_ARG2REG);
	register unsigned long a3 asm(__HYPERCALL_ARG3REG);
	register unsigned long a4 asm(__HYPERCALL_ARG4REG);
	register unsigned long a5 asm(__HYPERCALL_ARG5REG);
	int ret;

	preempt_disable();
	ret = shim_hypercall(a0, a1, a2, a3, a4, a5);
	preempt_enable();

	return ret;
}

void kvm_xen_register_lcall(struct kvm_xen *shim)
{
	hypercall_page_save = hypercall_page;
	hypercall_page = kvm_xen_hypercall_page;
	xen_shim = shim;
}
EXPORT_SYMBOL_GPL(kvm_xen_register_lcall);

void kvm_xen_unregister_lcall(void)
{
	hypercall_page = hypercall_page_save;
	hypercall_page_save = NULL;
}
EXPORT_SYMBOL_GPL(kvm_xen_unregister_lcall);

static inline int gnttab_entries(struct kvm *kvm)
{
	struct kvm_grant_table *gnttab = &kvm->arch.xen.gnttab;
	int n = max_t(unsigned int, gnttab->nr_frames, 1);

	return n * ((n << PAGE_SHIFT) / sizeof(struct grant_entry_v1));
}

/*
 * The first two members of a grant entry are updated as a combined pair.
 * The following union allows that to happen in an endian-neutral fashion.
 * Taken from Xen.
 */
union grant_combo {
	uint32_t word;
	struct {
		uint16_t flags;
		domid_t  domid;
	} shorts;
};

/* Marks a grant in use. Code largely borrowed from Xen. */
static int set_grant_status(domid_t domid, bool readonly,
			    struct grant_entry_v1 *shah)
{
	int rc = GNTST_okay;
	union grant_combo scombo, prev_scombo, new_scombo;
	uint16_t mask = GTF_type_mask;

	/*
	 * We bound the number of times we retry CMPXCHG on memory locations
	 * that we share with a guest OS. The reason is that the guest can
	 * modify that location at a higher rate than we can
	 * read-modify-CMPXCHG, so the guest could cause us to livelock. There
	 * are a few cases where it is valid for the guest to race our updates
	 * (e.g., to change the GTF_readonly flag), so we allow a few retries
	 * before failing.
	 */
	int retries = 0;

	scombo.word = *(u32 *)shah;

	/*
	 * This loop attempts to set the access (reading/writing) flags
	 * in the grant table entry.  It tries a cmpxchg on the field
	 * up to five times, and then fails under the assumption that
	 * the guest is misbehaving.
	 */
	for (;;) {
		/* If not already pinned, check the grant domid and type. */
		if ((((scombo.shorts.flags & mask) != GTF_permit_access) ||
		    (scombo.shorts.domid != domid))) {
			rc = GNTST_general_error;
			pr_err("Bad flags (%x) or dom (%d); expected d%d\n",
				scombo.shorts.flags, scombo.shorts.domid,
				domid);
			return rc;
		}

		new_scombo = scombo;
		new_scombo.shorts.flags |= GTF_reading;

		if (!readonly) {
			new_scombo.shorts.flags |= GTF_writing;
			if (unlikely(scombo.shorts.flags & GTF_readonly)) {
				rc = GNTST_general_error;
				pr_err("Attempt to write-pin a r/o grant entry\n");
				return rc;
			}
		}

		prev_scombo.word = cmpxchg((u32 *)shah,
					   scombo.word, new_scombo.word);
		if (likely(prev_scombo.word == scombo.word))
			break;

		if (retries++ == 4) {
			rc = GNTST_general_error;
			pr_err("Shared grant entry is unstable\n");
			return rc;
		}

		scombo = prev_scombo;
	}

	return rc;
}

#define MT_HANDLE_DOMID_SHIFT	17
#define MT_HANDLE_DOMID_MASK	0x7fff
#define MT_HANDLE_GREF_MASK	0x1ffff

static u32 handle_get(domid_t domid, grant_ref_t ref)
{
	return (domid << MT_HANDLE_DOMID_SHIFT) | ref;
}

static u16 handle_get_domid(grant_handle_t handle)
{
	return (handle >> MT_HANDLE_DOMID_SHIFT) & MT_HANDLE_DOMID_MASK;
}

static grant_ref_t handle_get_grant(grant_handle_t handle)
{
	return handle & MT_HANDLE_GREF_MASK;
}

static int map_grant_nosleep(struct kvm *rd, u64 frame, bool readonly,
			     struct page **page, u16 *err)
{
	unsigned long rhva;
	int gup_flags, non_blocking;
	int ret;

	*err = GNTST_general_error;

	if (!err || !page)
		return -EINVAL;

	rhva  = gfn_to_hva(rd, frame);
	if (kvm_is_error_hva(rhva)) {
		*err = GNTST_bad_page;
		return -EFAULT;
	}

	gup_flags = (readonly ? 0 : FOLL_WRITE) | FOLL_NOWAIT;

	/* get_user_pages will reset this were IO to be needed */
	non_blocking = 1;

	/*
	 * get_user_pages_*() family of functions can sleep if the page needs
	 * to be mapped in. However, our main consumer is the grant map
	 * hypercall and because we run in the same context as the caller
	 * (unlike a real hypercall) sleeping is not an option.
	 *
	 * This is how we avoid it:
	 *  - sleeping on mmap_sem acquisition: we handle that by acquiring the
	 *    read-lock before calling.
	 *    If mmap_sem is contended, return with GNTST_eagain.
	 *  - sync wait for pages to be swapped in: specify FOLL_NOWAIT. If IO
	 *    was needed, would be returned via @non_blocking. Return
	 *    GNTST_eagain if it is necessary and the user would retry.
	 *    Also, in the blocking case, mmap_sem will be released
	 *    asynchronously when the IO completes.
	 */
	ret = down_read_trylock(&rd->mm->mmap_sem);
	if (ret == 0) {
		*err = GNTST_eagain;
		return -EBUSY;
	}

	ret = get_user_pages_remote(rd->mm->owner, rd->mm, rhva, 1, gup_flags,
				    page, NULL, &non_blocking);
	if (non_blocking)
		up_read(&rd->mm->mmap_sem);

	if (ret == 1) {
		*err = GNTST_okay;
	} else if (ret == 0) {
		*err = GNTST_eagain;
		ret = -EBUSY;
	} else if (ret < 0) {
		pr_err("gnttab: failed to get pfn for hva %lx, err %d\n",
			rhva, ret);
		if (ret == -EFAULT) {
			*err = GNTST_bad_page;
		} else if (ret == -EBUSY) {
			WARN_ON(non_blocking);
			*err = GNTST_eagain;
		} else {
			*err = GNTST_general_error;
		}
	}

	return (ret >= 0) ? 0 : ret;
}

static int shim_hcall_gntmap(struct kvm_xen *ld,
			     struct gnttab_map_grant_ref *op)
{
	struct kvm_grant_map map_old, map_new, *map = NULL;
	bool readonly = op->flags & GNTMAP_readonly;
	struct grant_entry_v1 *shah;
	struct page *page = NULL;
	unsigned long host_kaddr;
	int err = -ENOSYS;
	struct kvm *rd;
	kvm_pfn_t rpfn;
	u32 frame;
	u32 idx;

	BUILD_BUG_ON(sizeof(*map) != 16);

	if (unlikely((op->host_addr))) {
		pr_err("gnttab: bad host_addr %llx in map\n", op->host_addr);
		op->status = GNTST_bad_virt_addr;
		return 0;
	}

	/*
	 * Make sure the guest does not try to smuggle any flags here
	 * (for instance _KVM_GNTMAP_ACTIVE.)
	 * The only allowable flag is GNTMAP_readonly.
	 */
	if (unlikely(op->flags & ~((u16) GNTMAP_readonly))) {
		pr_err("gnttab: bad flags %x in map\n", op->flags);
		op->status = GNTST_bad_gntref;
		return 0;
	}

	rd = kvm_xen_find_vm(op->dom);
	if (unlikely(!rd)) {
		pr_err("gnttab: could not find domain %u\n", op->dom);
		op->status = GNTST_bad_domain;
		return 0;
	}

	if (unlikely(op->ref >= gnttab_entries(rd))) {
		pr_err("gnttab: bad ref %u\n", op->ref);
		op->status = GNTST_bad_gntref;
		return 0;
	}

	/*
	 * shah is potentially controlled by the user. We cache the frame but
	 * don't care about any changes to domid or flags since those get
	 * validated in set_grant_status() anyway.
	 *
	 * Note that if the guest changes the frame we will end up mapping the
	 * old frame.
	 */
	shah = shared_entry(rd->arch.xen.gnttab.frames_v1, op->ref);
	frame = READ_ONCE(shah->frame);

	if (unlikely(shah->domid != ld->domid)) {
		pr_err("gnttab: bad domain (%u != %u)\n",
			shah->domid, ld->domid);
		op->status = GNTST_bad_gntref;
		goto out;
	}

	idx = handle_get(op->dom, op->ref);
	if (handle_get_grant(idx) < op->ref ||
	    handle_get_domid(idx) < op->dom) {
		pr_err("gnttab: out of maptrack entries (dom %u)\n", ld->domid);
		op->status = GNTST_general_error;
		goto out;
	}

	map = maptrack_entry(rd->arch.xen.gnttab.handle, op->ref);

	/*
	 * Cache the old map value so we can do our checks on the stable
	 * version. Once the map is done, swap the mapping with the new map.
	 */
	map_old = *map;
	if (map_old.flags & KVM_GNTMAP_ACTIVE) {
		pr_err("gnttab: grant ref %u dom %u in use\n",
			op->ref, ld->domid);
		op->status = GNTST_bad_gntref;
		goto out;
	}

	err = map_grant_nosleep(rd, frame, readonly, &page, &op->status);
	if (err) {
		if (err != -EBUSY)
			op->status = GNTST_bad_gntref;
		goto out;
	}

	err = set_grant_status(ld->domid, readonly, shah);
	if (err != GNTST_okay) {
		pr_err("gnttab: pin failed\n");
		put_page(page);
		op->status = err;
		goto out;
	}

	rpfn = page_to_pfn(page);
	host_kaddr = (unsigned long) pfn_to_kaddr(rpfn);

	map_new.domid = op->dom;
	map_new.ref = op->ref;
	map_new.flags = op->flags;
	map_new.gpa = host_kaddr;

	map_new.flags |= KVM_GNTMAP_ACTIVE;

	/*
	 * Protect against a grant-map that could come in between our check for
	 * KVM_GNTMAP_ACTIVE above and assuming the ownership of the mapping.
	 *
	 * Use cmpxchg_double() so we can update mapping atomically (which
	 * luckily fits in 16b.)
	 */
	if (cmpxchg_double(&map->gpa, &map->fields,
			map_old.gpa, map_old.fields,
			map_new.gpa, map_new.fields) == false) {
		put_page(page);
		op->status = GNTST_bad_gntref;
		goto out;
	}

	op->dev_bus_addr = rpfn << PAGE_SHIFT;
	op->handle = idx;
	op->status = GNTST_okay;
	op->host_addr = host_kaddr;
	return 0;

out:
	/* The error code is stored in @status. */
	return 0;
}

static int shim_hcall_gntunmap(struct kvm_xen *xen,
			       struct gnttab_unmap_grant_ref *op)
{
	struct kvm_grant_map *map, unmap;
	struct grant_entry_v1 **rgt;
	struct grant_entry_v1 *shah;
	struct kvm *rd = NULL;
	domid_t domid;
	u32 ref;

	domid = handle_get_domid(op->handle);
	ref = handle_get_grant(op->handle);


	rd = kvm_xen_find_vm(domid);
	if (unlikely(!rd)) {
		/* We already teardown all ongoing grant maps */
		op->status = GNTST_okay;
		return 0;
	}

	if (unlikely(ref >= gnttab_entries(rd))) {
		pr_err("gnttab: bad ref %u\n", ref);
		op->status = GNTST_bad_handle;
		return 0;
	}

	rgt = rd->arch.xen.gnttab.frames_v1;
	map = maptrack_entry(rd->arch.xen.gnttab.handle, ref);

	/*
	 * The test_and_clear_bit (below) serializes ownership of this
	 * grant-entry.  After we clear it, there can be a grant-map on this
	 * entry. So we cache the unmap entry before relinquishing ownership.
	 */
	unmap = *map;

	if (!test_and_clear_bit(_KVM_GNTMAP_ACTIVE,
				(unsigned long *) &map->flags)) {
		pr_err("gnttab: bad flags for %u (dom %u ref %u) flags %x\n",
			op->handle, domid, ref, unmap.flags);
		op->status = GNTST_bad_handle;
		return 0;
	}

	/* Give up the reference taken in get_user_pages_remote(). */
	put_page(virt_to_page(unmap.gpa));

	shah = shared_entry(rgt, unmap.ref);

	/*
	 * We have cleared _KVM_GNTMAP_ACTIVE, so a simultaneous grant-map
	 * could update the shah and we would stomp all over it but the
	 * guest deserves it.
	 */
	if (!(unmap.flags & GNTMAP_readonly))
		clear_bit(_GTF_writing, (unsigned long *) &shah->flags);
	clear_bit(_GTF_reading, (unsigned long *) &shah->flags);

	op->status = GNTST_okay;
	return 0;
}

static unsigned long __kvm_gfn_to_hva(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	struct kvm_xen *xen = vcpu ? &vcpu->kvm->arch.xen : xen_shim;
	unsigned long hva;

	if (xen->domid == 0)
		return (unsigned long) page_to_virt(pfn_to_page(gfn));

	hva = gfn_to_hva(vcpu->kvm, gfn);
	if (unlikely(kvm_is_error_hva(hva)))
		return 0;

	return hva;
}

static int __kvm_gref_to_page(struct kvm_vcpu *vcpu, grant_ref_t ref,
			      domid_t domid, struct page **page,
			      int16_t *status)
{
	struct kvm_xen *source = vcpu ? &vcpu->kvm->arch.xen : xen_shim;
	struct grant_entry_v1 *shah;
	struct grant_entry_v1 **gt;
	struct kvm *dest;

	dest = kvm_xen_find_vm(domid);
	if (unlikely(!dest)) {
		pr_err("gnttab: could not find domain %u\n", domid);
		*status = GNTST_bad_domain;
		return 0;
	}

	if (unlikely(ref >= gnttab_entries(dest))) {
		pr_err("gnttab: bad ref %u\n", ref);
		*status = GNTST_bad_gntref;
		return 0;
	}

	gt = dest->arch.xen.gnttab.frames_v1;
	shah = shared_entry(gt, ref);
	if (unlikely(shah->domid != source->domid)) {
		pr_err("gnttab: bad domain (%u != %u)\n",
			shah->domid, source->domid);
		*status = GNTST_bad_gntref;
		return 0;
	}

	(void) map_grant_nosleep(dest, shah->frame, 0, page, status);

	return 0;
}

static int shim_hcall_gntcopy(struct kvm_vcpu *vcpu,
				   struct gnttab_copy *op)
{
	void *saddr = NULL, *daddr = NULL;
	struct page *spage = NULL, *dpage = NULL;
	unsigned long hva;
	int err = -ENOSYS;
	gfn_t gfn;

	if (!(op->flags & GNTCOPY_source_gref) &&
	    (op->source.domid == DOMID_SELF)) {
		gfn = op->source.u.gmfn;
		hva = __kvm_gfn_to_hva(vcpu, gfn);
		if (unlikely(!hva)) {
			pr_err("gnttab: bad source gfn:%llx\n", gfn);
			op->status = GNTST_general_error;
			err = 0;
			return 0;
		}

		saddr = (void *) (((unsigned long) hva) + op->source.offset);
	} else if (op->flags & GNTCOPY_source_gref) {
		op->status = GNTST_okay;
		if (__kvm_gref_to_page(vcpu, op->source.u.ref,
				       op->source.domid, &spage, &op->status))
			return -EFAULT;

		if (!spage || op->status != GNTST_okay) {
			pr_err("gnttab: failed to get page for source gref:%x\n",
			       op->source.u.ref);
			err = 0;
			goto out;
		}

		saddr = kmap(spage);
		saddr = (void *) (((unsigned long) saddr) + op->source.offset);
	}

	if (!(op->flags & GNTCOPY_dest_gref) &&
	    (op->dest.domid == DOMID_SELF)) {
		gfn = op->dest.u.gmfn;
		hva = __kvm_gfn_to_hva(vcpu, gfn);
		if (unlikely(!hva)) {
			pr_err("gnttab: bad dest gfn:%llx\n", gfn);
			op->status = GNTST_general_error;
			err = 0;
			return 0;
		}

		daddr = (void *) (((unsigned long) hva) + op->dest.offset);
	} else if (op->flags & GNTCOPY_dest_gref) {
		op->status = GNTST_okay;
		if (__kvm_gref_to_page(vcpu, op->dest.u.ref,
				       op->dest.domid, &dpage, &op->status))
			return -EFAULT;

		if (!dpage || op->status != GNTST_okay) {
			pr_err("gnttab: failed to get page for dest gref:%x\n",
			       op->dest.u.ref);
			err = 0;
			goto out;
		}

		daddr = kmap(dpage);
		daddr = (void *) (((unsigned long) daddr) + op->dest.offset);
	}

	if (unlikely(!daddr || !saddr)) {
		op->status = GNTST_general_error;
		err = 0;
		goto out;
	}

	memcpy(daddr, saddr, op->len);

	if (spage)
		kunmap(spage);
	if (dpage)
		kunmap(dpage);


	err = 0;
	op->status = GNTST_okay;
out:
	if (spage)
		put_page(spage);
	if (dpage)
		put_page(dpage);
	return err;
}

static int shim_hcall_gnttab(int op, void *p, int count)
{
	int ret = -ENOSYS;
	int i;

	switch (op) {
	case GNTTABOP_map_grant_ref: {
		struct gnttab_map_grant_ref *ref = p;

		for (i = 0; i < count; i++)
			shim_hcall_gntmap(xen_shim, ref + i);
		ret = 0;
		break;
	}
	case GNTTABOP_unmap_grant_ref: {
		struct gnttab_unmap_grant_ref *ref = p;

		for (i = 0; i < count; i++) {
			shim_hcall_gntunmap(xen_shim, ref + i);
			ref[i].host_addr = 0;
		}
		ret = 0;
		break;
	}
	case GNTTABOP_copy: {
		struct gnttab_copy *op = p;

		for (i = 0; i < count; i++)
			shim_hcall_gntcopy(NULL, op + i);
		ret = 0;
		break;
	}
	default:
		pr_info("lcall-gnttab:op default=%d\n", op);
		break;
	}

	return ret;
}

static int shim_hcall_evtchn_send(struct kvm_xen *dom0, struct evtchn_send *snd)
{
	struct evtchnfd *event;

	event = idr_find(&dom0->port_to_evt, snd->port);
	if (!event)
		return -ENOENT;

	if (event->remote.vm == NULL)
		return kvm_xen_evtchn_send_shim(xen_shim, event);
	else if (event->type == XEN_EVTCHN_TYPE_INTERDOM ||
		 event->type == XEN_EVTCHN_TYPE_UNBOUND)
		return kvm_xen_evtchn_send_guest(event, event->remote.port);
	else
		return -EINVAL;

	return 0;
}

static int shim_hcall_evtchn(int op, void *p)
{
	int ret;
	struct kvm_xen_eventfd evt;

	if (p == NULL)
		return -EINVAL;

	memset(&evt, 0, sizeof(evt));

	switch (op) {
	case EVTCHNOP_bind_interdomain: {
		struct evtchn_bind_interdomain *un;

		un = (struct evtchn_bind_interdomain *) p;

		evt.fd = -1;
		evt.port = 0;
		if (un->remote_port == 0) {
			evt.type = XEN_EVTCHN_TYPE_UNBOUND;
			evt.remote.domid = un->remote_dom;
		} else {
			evt.type = XEN_EVTCHN_TYPE_INTERDOM;
			evt.remote.domid = un->remote_dom;
			evt.remote.port = un->remote_port;
		}

		ret = kvm_xen_eventfd_assign(NULL, &xen_shim->port_to_evt,
					     &xen_shim->xen_lock, &evt);
		un->local_port = evt.port;
		break;
	}
	case EVTCHNOP_alloc_unbound: {
		struct evtchn_alloc_unbound *un;

		un = (struct evtchn_alloc_unbound *) p;

		if (un->dom != DOMID_SELF || un->remote_dom != DOMID_SELF)
			return -EINVAL;
		evt.fd = -1;
		evt.port = 0;
		evt.type = XEN_EVTCHN_TYPE_UNBOUND;
		evt.remote.domid = DOMID_SELF;

		ret = kvm_xen_eventfd_assign(NULL, &xen_shim->port_to_evt,
					     &xen_shim->xen_lock, &evt);
		un->port = evt.port;
		break;
	}
	case EVTCHNOP_send: {
		struct evtchn_send *send;

		send = (struct evtchn_send *) p;
		ret = shim_hcall_evtchn_send(xen_shim, send);
		break;
	}
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int shim_hcall_version(int op, struct xen_feature_info *fi)
{
	if (op != XENVER_get_features || !fi || fi->submap_idx != 0)
		return -EINVAL;

	/*
	 * We need a limited set of features for a pseudo dom0.
	 */
	fi->submap = (1U << XENFEAT_auto_translated_physmap);
	return 0;
}

static int shim_hypercall(u64 code, u64 a0, u64 a1, u64 a2, u64 a3, u64 a4)
{
	int ret = -ENOSYS;

	switch (code) {
	case __HYPERVISOR_event_channel_op:
		ret = shim_hcall_evtchn((int) a0, (void *)a1);
		break;
	case __HYPERVISOR_grant_table_op:
		ret = shim_hcall_gnttab((int) a0, (void *) a1, (int) a2);
		break;
	case __HYPERVISOR_xen_version:
		ret = shim_hcall_version((int)a0, (void *)a1);
		break;
	default:
		break;
	}

	return ret;
}
