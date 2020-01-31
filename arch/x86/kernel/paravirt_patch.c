// SPDX-License-Identifier: GPL-2.0
#include <linux/stringify.h>
#include <linux/errno.h>

#include <asm/paravirt.h>
#include <asm/asm-offsets.h>

#define PSTART(d, m)							\
	patch_data_##d.m

#define PEND(d, m)							\
	(PSTART(d, m) + sizeof(patch_data_##d.m))

#define PATCH(d, m, insn_buff, len)						\
	paravirt_patch_insns(insn_buff, len, PSTART(d, m), PEND(d, m))

#define PATCH_CASE(ops, m, data, insn_buff, len)				\
	case PARAVIRT_PATCH(ops.m):					\
		return PATCH(data, ops##_##m, insn_buff, len)

#ifdef CONFIG_PARAVIRT_XXL
struct patch_xxl {
	const unsigned char	irq_irq_disable[1];
	const unsigned char	irq_irq_enable[1];
	const unsigned char	irq_save_fl[2];
	const unsigned char	mmu_read_cr2[3];
	const unsigned char	mmu_read_cr3[3];
	const unsigned char	mmu_write_cr3[3];
	const unsigned char	irq_restore_fl[2];
# ifdef CONFIG_X86_64
	const unsigned char	cpu_wbinvd[2];
	const unsigned char	cpu_usergs_sysret64[6];
	const unsigned char	cpu_swapgs[3];
	const unsigned char	mov64[3];
# else
	const unsigned char	cpu_iret[1];
# endif
};

static const struct patch_xxl patch_data_xxl = {
	.irq_irq_disable	= { 0xfa },		// cli
	.irq_irq_enable		= { 0xfb },		// sti
	.irq_save_fl		= { 0x9c, 0x58 },	// pushf; pop %[re]ax
	.mmu_read_cr2		= { 0x0f, 0x20, 0xd0 },	// mov %cr2, %[re]ax
	.mmu_read_cr3		= { 0x0f, 0x20, 0xd8 },	// mov %cr3, %[re]ax
# ifdef CONFIG_X86_64
	.mmu_write_cr3		= { 0x0f, 0x22, 0xdf },	// mov %rdi, %cr3
	.irq_restore_fl		= { 0x57, 0x9d },	// push %rdi; popfq
	.cpu_wbinvd		= { 0x0f, 0x09 },	// wbinvd
	.cpu_usergs_sysret64	= { 0x0f, 0x01, 0xf8,
				    0x48, 0x0f, 0x07 },	// swapgs; sysretq
	.cpu_swapgs		= { 0x0f, 0x01, 0xf8 },	// swapgs
	.mov64			= { 0x48, 0x89, 0xf8 },	// mov %rdi, %rax
# else
	.mmu_write_cr3		= { 0x0f, 0x22, 0xd8 },	// mov %eax, %cr3
	.irq_restore_fl		= { 0x50, 0x9d },	// push %eax; popf
	.cpu_iret		= { 0xcf },		// iret
# endif
};

unsigned int paravirt_patch_ident_64(void *insn_buff, unsigned int len)
{
#ifdef CONFIG_X86_64
	return PATCH(xxl, mov64, insn_buff, len);
#endif
	return 0;
}
# endif /* CONFIG_PARAVIRT_XXL */

#ifdef CONFIG_PARAVIRT_SPINLOCKS
struct patch_lock {
	unsigned char queued_spin_unlock[3];
	unsigned char vcpu_is_preempted[2];
};

static const struct patch_lock patch_data_lock = {
	.vcpu_is_preempted	= { 0x31, 0xc0 },	// xor %eax, %eax

# ifdef CONFIG_X86_64
	.queued_spin_unlock	= { 0xc6, 0x07, 0x00 },	// movb $0, (%rdi)
# else
	.queued_spin_unlock	= { 0xc6, 0x00, 0x00 },	// movb $0, (%eax)
# endif
};
#endif /* CONFIG_PARAVIRT_SPINLOCKS */

unsigned int native_patch(u8 type, void *insn_buff, unsigned long addr,
			  unsigned int len)
{
	switch (type) {

#ifdef CONFIG_PARAVIRT_XXL
	PATCH_CASE(irq, restore_fl, xxl, insn_buff, len);
	PATCH_CASE(irq, save_fl, xxl, insn_buff, len);
	PATCH_CASE(irq, irq_enable, xxl, insn_buff, len);
	PATCH_CASE(irq, irq_disable, xxl, insn_buff, len);

	PATCH_CASE(mmu, read_cr2, xxl, insn_buff, len);
	PATCH_CASE(mmu, read_cr3, xxl, insn_buff, len);
	PATCH_CASE(mmu, write_cr3, xxl, insn_buff, len);

# ifdef CONFIG_X86_64
	PATCH_CASE(cpu, usergs_sysret64, xxl, insn_buff, len);
	PATCH_CASE(cpu, swapgs, xxl, insn_buff, len);
	PATCH_CASE(cpu, wbinvd, xxl, insn_buff, len);
# else
	PATCH_CASE(cpu, iret, xxl, insn_buff, len);
# endif
#endif

#ifdef CONFIG_PARAVIRT_SPINLOCKS
	case PARAVIRT_PATCH(lock.queued_spin_unlock):
		if (pv_is_native_spin_unlock())
			return PATCH(lock, queued_spin_unlock, insn_buff, len);
		break;

	case PARAVIRT_PATCH(lock.vcpu_is_preempted):
		if (pv_is_native_vcpu_is_preempted())
			return PATCH(lock, vcpu_is_preempted, insn_buff, len);
		break;
#endif
	default:
		break;
	}

	return paravirt_patch_default(type, insn_buff, addr, len);
}

#ifdef CONFIG_PARAVIRT_RUNTIME
/**
 * runtime_patch - Generate patching code for a native/paravirt op
 * @type: op type to generate code for
 * @insn_buff: destination buffer
 * @op: op target
 * @addr: call site address
 * @len: length of insn_buff
 *
 * Note that pv-ops are only suitable for runtime patching if they are
 * non-preemptible. This is necessary for two reasons: we don't want to
 * be overwriting insn sequences which might be referenced from call-stacks
 * (and thus would be returned to), and we want patching to act as a barrier
 * so no code from now stale paravirt ops should execute after an op has
 * changed.
 *
 * Return: size of insn sequence on success, -EINVAL on error.
 */
int runtime_patch(u8 type, void *insn_buff, void *op,
		  unsigned long addr, unsigned int len)
{
	void *native_op;
	int used = 0;

	/* Nothing whitelisted for now. */
	switch (type) {
	default:
		pr_warn("type=%d unsuitable for runtime-patching\n", type);
		return -EINVAL;
	}

	if (PARAVIRT_PATCH_OP(pv_ops, type) != (long)op)
		PARAVIRT_PATCH_OP(pv_ops, type) = (long)op;

	native_op = (void *)PARAVIRT_PATCH_OP(native_pv_ops, type);

	/*
	 * Use native_patch() to get the right insns if we are switching
	 * back to a native_op.
	 */
	if (op == native_op)
		used = native_patch(type, insn_buff, addr, len);
	else
		used = paravirt_patch_default(type, insn_buff, addr, len);
	return used;
}
#endif /* CONFIG_PARAVIRT_RUNTIME */
