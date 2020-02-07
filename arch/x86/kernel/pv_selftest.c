// SPDX-License-Identifier: GPL-2.0

#include <linux/delay.h>
#include <linux/irq.h>
#include <linux/spinlock.h>
#include <linux/debugfs.h>
#include <linux/memory.h>
#include <linux/nmi.h>
#include <linux/uaccess.h>
#include <asm/apic.h>
#include <asm/text-patching.h>
#include <asm/paravirt.h>
#include <asm/paravirt_types.h>
#include "pv_selftest.h"

static int nmi_selftest;
static bool cond_state;

#define SELFTEST_PARAVIRT	1
static int test_mode;

/*
 * Mark this and the following functions __always_inline to ensure
 * we generate multiple patch sites that can be hit independently
 * in thread, NMI etc contexts.
 */
static __always_inline void selftest_pv(void)
{
	struct qspinlock test;

	memset(&test, 0, sizeof(test));

	test.locked = _Q_LOCKED_VAL;

	/*
	 * Sits directly in the path of the test.
	 *
	 * The primary sets up an INT3 instruction at pv_queued_spin_unlock().
	 * Both the primary and secondary CPUs should hit that in both
	 * thread and NMI contexts.
	 *
	 * Additionally, this also gets inlined in nmi_pv_callback() so we
	 * should hit this with nmi_selftest.
	 *
	 * The fixup takes place in poke_int3_native().
	 */
	pv_queued_spin_unlock(&test);
}

static __always_inline void patch_selftest(void)
{
	if (test_mode == SELFTEST_PARAVIRT)
		selftest_pv();
}

static DEFINE_PER_CPU(int, selftest_count);
void pv_selftest_secondary(void)
{
	/*
	 * On the secondary we execute the same code in both the
	 * thread-context and the BP-context and so would hit this
	 * recursively if we do inside the fixup context.
	 *
	 * So we trigger the selftest only if it's not ongoing already
	 * (thus allowing the thread or NMI context, but excluding
	 * the INT3 handling path.)
	 */
	if (this_cpu_read(selftest_count))
		return;

	this_cpu_inc(selftest_count);

	patch_selftest();

	this_cpu_dec(selftest_count);
}

void pv_selftest_primary(void)
{
	patch_selftest();
}

/*
 * We only come here if nmi_selftest > 0.
 *  - nmi_selftest >= 1: execute a pv-op that will be patched
 *  - nmi_selftest >= 2: execute a paired pv-op that is also contended
 *  - nmi_selftest >= 3: add lock contention
 */
static int nmi_callback(unsigned int val, struct pt_regs *regs)
{
	static DEFINE_SPINLOCK(nmi_spin);

	if (!nmi_selftest)
		goto out;

	patch_selftest();

	if (nmi_selftest >= 2) {
		/*
		 * Depending on whether CONFIG_[UN]INLINE_SPIN_* are
		 * defined or not, these would get patched or just
		 * create race conditions between via NMIs.
		 */
		spin_lock(&nmi_spin);

		/* Dilate the critical section to force contention. */
		if (nmi_selftest >= 3)
			udelay(1);

		spin_unlock(&nmi_spin);
	}

	/*
	 * nmi_selftest > 0, but we should really have a bitmap where
	 * to check if this really was destined for us or not.
	 */
	return NMI_HANDLED;
out:
	return NMI_DONE;
}

void pv_selftest_register(void)
{
	register_nmi_handler(NMI_LOCAL, nmi_callback,
			     0, "paravirt_nmi_selftest");
}

void pv_selftest_unregister(void)
{
	unregister_nmi_handler(NMI_LOCAL, "paravirt_nmi_selftest");
}

void pv_selftest_send_nmi(void)
{
	int cpu = smp_processor_id();
	/* NMI or INT3 */
	if (nmi_selftest && !in_interrupt())
		apic->send_IPI(cpu + 1 % num_online_cpus(), NMI_VECTOR);
}

/*
 * Just declare these locally here instead of having them be
 * exposed to the whole world.
 */
void kvm_wait(u8 *ptr, u8 val);
void kvm_kick_cpu(int cpu);
bool __raw_callee_save___kvm_vcpu_is_preempted(long cpu);
static void pv_spinlocks(void)
{
	paravirt_stage_alt(cond_state,
			   lock.queued_spin_lock_slowpath,
			   __pv_queued_spin_lock_slowpath);
	paravirt_stage_alt(cond_state, lock.queued_spin_unlock.func,
			   PV_CALLEE_SAVE(__pv_queued_spin_unlock).func);
	paravirt_stage_alt(cond_state, lock.wait, kvm_wait);
	paravirt_stage_alt(cond_state, lock.kick, kvm_kick_cpu);

	paravirt_stage_alt(cond_state,
			   lock.vcpu_is_preempted.func,
			   PV_CALLEE_SAVE(__kvm_vcpu_is_preempted).func);
}

void pv_trigger(void)
{
	bool nmi_mode = nmi_selftest ? true : false;
	int ret;

	pr_debug("%s: nmi=%d; NMI-mode=%d\n", __func__, nmi_selftest, nmi_mode);

	mutex_lock(&text_mutex);

	paravirt_stage_zero();
	pv_spinlocks();

	/*
	 * paravirt patching for pv_locks can potentially deadlock
	 * if we are running with nmi_mode=false and we get an NMI.
	 *
	 * For the sake of testing that path, we risk it. However, if
	 * we are generating synthetic NMIs (nmi_selftest > 0) then
	 * run with nmi_mode=true.
	 */
	ret = paravirt_runtime_patch(nmi_mode);

	/*
	 * Flip the state so we switch the pv_lock_ops on the next test.
	 */
	cond_state = !cond_state;

	mutex_unlock(&text_mutex);

	pr_debug("%s: nmi=%d; NMI-mode=%d, ret=%d\n", __func__, nmi_selftest,
		 nmi_mode, ret);
}

static void pv_selftest_trigger(void)
{
	test_mode = SELFTEST_PARAVIRT;
	pv_trigger();
}

static ssize_t pv_selftest_write(struct file *file, const char __user *ubuf,
				 size_t count, loff_t *ppos)
{
	pv_selftest_register();
	pv_selftest_trigger();
	pv_selftest_unregister();

	return count;
}

static ssize_t pv_nmi_read(struct file *file, char __user *ubuf,
			   size_t count, loff_t *ppos)
{
	char buf[32];
	unsigned int len;

	len = snprintf(buf, sizeof(buf), "%d\n", nmi_selftest);
	return simple_read_from_buffer(ubuf, count, ppos, buf, len);
}

static ssize_t pv_nmi_write(struct file *file, const char __user *ubuf,
			    size_t count, loff_t *ppos)
{
	char buf[32];
	unsigned int len;
	unsigned int enabled;

	len = min(sizeof(buf) - 1, count);
	if (copy_from_user(buf, ubuf, len))
		return -EFAULT;

	buf[len] = '\0';
	if (kstrtoint(buf, 0, &enabled))
		return -EINVAL;

	nmi_selftest = enabled > 3 ? 3 : enabled;

	return count;
}

static const struct file_operations pv_selftest_fops = {
	.read = NULL,
	.write = pv_selftest_write,
	.llseek = default_llseek,
};

static const struct file_operations pv_nmi_fops = {
	.read = pv_nmi_read,
	.write = pv_nmi_write,
	.llseek = default_llseek,
};

static int __init pv_selftest_init(void)
{
	struct dentry *d = debugfs_create_dir("pv_selftest", NULL);

	debugfs_create_file("toggle", 0600, d, NULL, &pv_selftest_fops);
	debugfs_create_file("nmi", 0600, d, NULL, &pv_nmi_fops);

	return 0;
}

late_initcall(pv_selftest_init);
