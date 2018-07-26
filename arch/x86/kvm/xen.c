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
#include <linux/sched/stat.h>

#include <trace/events/kvm.h>
#include <xen/interface/xen.h>
#include <xen/interface/vcpu.h>

#include "trace.h"

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

int kvm_xen_hypercall(struct kvm_vcpu *vcpu)
{
	bool longmode;
	u64 input, params[5];

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
}

void kvm_xen_destroy_vm(struct kvm *kvm)
{
	struct kvm_xen *xen = &kvm->arch.xen;

	if (xen->shinfo)
		put_page(virt_to_page(xen->shinfo));
}
