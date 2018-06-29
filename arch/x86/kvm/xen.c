// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019 Oracle and/or its affiliates. All rights reserved.
 *
 * KVM Xen emulation
 */

#include "x86.h"
#include "xen.h"

#include <linux/kvm_host.h>

#include <trace/events/kvm.h>
#include <xen/interface/xen.h>

#include "trace.h"

static void set_vcpu_attr(struct kvm_vcpu *v, u16 type, gpa_t gpa, void *addr)
{
	struct kvm_vcpu_xen *vcpu_xen = vcpu_to_xen_vcpu(v);

	switch (type) {
	case KVM_XEN_ATTR_TYPE_VCPU_INFO:
		vcpu_xen->vcpu_info_addr = gpa;
		vcpu_xen->vcpu_info = addr;
		kvm_xen_setup_pvclock_page(v);
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

void kvm_xen_setup_pvclock_page(struct kvm_vcpu *v)
{
	struct kvm_vcpu_arch *vcpu = &v->arch;
	struct pvclock_vcpu_time_info *guest_hv_clock;
	void *hva = xen_vcpu_info(v);
	unsigned int offset;

	if (!hva)
		return;

	offset = offsetof(struct vcpu_info, time);

	guest_hv_clock = (struct pvclock_vcpu_time_info *)
		(hva + offset);

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

int kvm_xen_hvm_set_attr(struct kvm *kvm, struct kvm_xen_hvm_attr *data)
{
	int r = -ENOENT;

	switch (data->type) {
	case KVM_XEN_ATTR_TYPE_SHARED_INFO: {
		gfn_t gfn = data->u.shared_info.gfn;

		r = kvm_xen_shared_info_init(kvm, gfn);
		break;
	}
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
}

void kvm_xen_destroy_vm(struct kvm *kvm)
{
	struct kvm_xen *xen = &kvm->arch.xen;

	if (xen->shinfo)
		put_page(virt_to_page(xen->shinfo));
}
