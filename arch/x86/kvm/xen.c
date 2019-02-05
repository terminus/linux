// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019 Oracle and/or its affiliates. All rights reserved.
 *
 * KVM Xen emulation
 */

#include "x86.h"
#include "xen.h"
#include "ioapic.h"

#include <linux/kvm_host.h>
#include <linux/eventfd.h>
#include <linux/sched/stat.h>

#include <trace/events/kvm.h>
#include <xen/interface/xen.h>
#include <xen/interface/vcpu.h>
#include <xen/interface/event_channel.h>
#include <xen/interface/sched.h>

#include "trace.h"

struct evtchnfd {
	struct eventfd_ctx *ctx;
	u32 vcpu;
	u32 port;
	u32 type;
	union {
		struct {
			u8 type;
		} virq;
	};
};

static int kvm_xen_evtchn_send(struct kvm_vcpu *vcpu, int port);
static void *xen_vcpu_info(struct kvm_vcpu *v);

int kvm_xen_has_interrupt(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_xen *vcpu_xen = vcpu_to_xen_vcpu(vcpu);
	struct vcpu_info *vcpu_info = xen_vcpu_info(vcpu);

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

static void *xen_vcpu_info(struct kvm_vcpu *v)
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
	void *hva = xen_vcpu_info(v);
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

#undef BITS_PER_EVTCHN_WORD

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

static int kvm_xen_evtchn_send(struct kvm_vcpu *vcpu, int port)
{
	struct eventfd_ctx *eventfd;
	struct evtchnfd *evtchnfd;

	/* conn_to_evt is protected by vcpu->kvm->srcu */
	evtchnfd = idr_find(&vcpu->kvm->arch.xen.port_to_evt, port);
	if (!evtchnfd)
		return -ENOENT;

	eventfd = evtchnfd->ctx;
	if (!kvm_xen_evtchn_set_pending(vcpu, evtchnfd)) {
		if (!eventfd)
			kvm_xen_evtchnfd_upcall(vcpu, evtchnfd);
		else
			eventfd_signal(eventfd, 1);
	}

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
	default:
		break;
	}

	return ret;
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

static int kvm_xen_eventfd_assign(struct kvm *kvm, struct idr *port_to_evt,
				  struct mutex *port_lock,
				  struct kvm_xen_eventfd *args)
{
	struct eventfd_ctx *eventfd = NULL;
	struct evtchnfd *evtchnfd;
	u32 port = args->port;
	int ret;

	if (args->fd != -1) {
		eventfd = eventfd_ctx_fdget(args->fd);
		if (IS_ERR(eventfd))
			return PTR_ERR(eventfd);
	}

	if (args->type == XEN_EVTCHN_TYPE_VIRQ &&
	    args->virq.type >= KVM_XEN_NR_VIRQS)
		return -EINVAL;

	evtchnfd =  kzalloc(sizeof(struct evtchnfd), GFP_KERNEL);
	if (!evtchnfd)
		return -ENOMEM;

	evtchnfd->ctx = eventfd;
	evtchnfd->port = port;
	evtchnfd->vcpu = args->vcpu;
	evtchnfd->type = args->type;
	if (evtchnfd->type == XEN_EVTCHN_TYPE_VIRQ)
		evtchnfd->virq.type = args->virq.type;

	mutex_lock(port_lock);
	ret = idr_alloc(port_to_evt, evtchnfd, port, port + 1,
			GFP_KERNEL);
	mutex_unlock(port_lock);

	if (ret >= 0) {
		if (evtchnfd->type == XEN_EVTCHN_TYPE_VIRQ)
			kvm_xen_set_virq(kvm, evtchnfd);
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

	if (kvm)
		synchronize_srcu(&kvm->srcu);
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
