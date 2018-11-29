/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2019 Oracle and/or its affiliates. All rights reserved. */
#ifndef __ARCH_X86_KVM_XEN_H__
#define __ARCH_X86_KVM_XEN_H__

#include <asm/xen/hypercall.h>

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

int kvm_xen_has_interrupt(struct kvm_vcpu *vcpu);
int kvm_xen_get_interrupt(struct kvm_vcpu *vcpu);

int kvm_xen_set_evtchn(struct kvm_kernel_irq_routing_entry *e,
		       struct kvm *kvm, int irq_source_id, int level,
		       bool line_status);
int kvm_xen_setup_evtchn(struct kvm *kvm,
			 struct kvm_kernel_irq_routing_entry *e);

void kvm_xen_init_vm(struct kvm *kvm);
void kvm_xen_destroy_vm(struct kvm *kvm);
int kvm_vm_ioctl_xen_eventfd(struct kvm *kvm, struct kvm_xen_eventfd *args);
int kvm_vm_ioctl_xen_gnttab(struct kvm *kvm, struct kvm_xen_gnttab *op);
void kvm_xen_vcpu_init(struct kvm_vcpu *vcpu);
void kvm_xen_vcpu_uninit(struct kvm_vcpu *vcpu);
void kvm_xen_init(void);
void kvm_xen_exit(void);

void __kvm_migrate_xen_timer(struct kvm_vcpu *vcpu);
int kvm_xen_has_pending_timer(struct kvm_vcpu *vcpu);
void kvm_xen_inject_timer_irqs(struct kvm_vcpu *vcpu);
bool kvm_xen_timer_enabled(struct kvm_vcpu *vcpu);

extern struct hypercall_entry kvm_xen_hypercall_page[128];

#endif
