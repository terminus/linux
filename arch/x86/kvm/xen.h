/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2019 Oracle and/or its affiliates. All rights reserved. */
#ifndef __ARCH_X86_KVM_XEN_H__
#define __ARCH_X86_KVM_XEN_H__

int kvm_xen_hvm_set_attr(struct kvm *kvm, struct kvm_xen_hvm_attr *data);
int kvm_xen_hvm_get_attr(struct kvm *kvm, struct kvm_xen_hvm_attr *data);
bool kvm_xen_hypercall_enabled(struct kvm *kvm);
bool kvm_xen_hypercall_set(struct kvm *kvm);
int kvm_xen_hypercall(struct kvm_vcpu *vcpu);

void kvm_xen_destroy_vm(struct kvm *kvm);

#endif
