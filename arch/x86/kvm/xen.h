/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2019 Oracle and/or its affiliates. All rights reserved. */
#ifndef __ARCH_X86_KVM_XEN_H__
#define __ARCH_X86_KVM_XEN_H__

static inline struct kvm_vcpu_xen *vcpu_to_xen_vcpu(struct kvm_vcpu *vcpu)
{
	return &vcpu->arch.xen;
}

static inline struct kvm_vcpu *xen_vcpu_to_vcpu(struct kvm_vcpu_xen *xen_vcpu)
{
	struct kvm_vcpu_arch *arch;

	arch = container_of(xen_vcpu, struct kvm_vcpu_arch, xen);
	return container_of(arch, struct kvm_vcpu, arch);
}

void kvm_xen_setup_pvclock_page(struct kvm_vcpu *vcpu);
void kvm_xen_setup_runstate_page(struct kvm_vcpu *vcpu);
void kvm_xen_runstate_set_preempted(struct kvm_vcpu *vcpu);
int kvm_xen_hvm_set_attr(struct kvm *kvm, struct kvm_xen_hvm_attr *data);
int kvm_xen_hvm_get_attr(struct kvm *kvm, struct kvm_xen_hvm_attr *data);
bool kvm_xen_hypercall_enabled(struct kvm *kvm);
bool kvm_xen_hypercall_set(struct kvm *kvm);
int kvm_xen_hypercall(struct kvm_vcpu *vcpu);

void kvm_xen_destroy_vm(struct kvm *kvm);
void kvm_xen_vcpu_uninit(struct kvm_vcpu *vcpu);

#endif
