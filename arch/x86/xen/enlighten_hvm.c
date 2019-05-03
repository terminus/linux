// SPDX-License-Identifier: GPL-2.0

#include <linux/acpi.h>
#include <linux/cpu.h>
#include <linux/kexec.h>
#include <linux/memblock.h>

#include <xen/interface/xen.h>
#include <xen/xenhost.h>
#include <xen/features.h>
#include <xen/events.h>
#include <xen/interface/memory.h>

#include <asm/cpu.h>
#include <asm/smp.h>
#include <asm/reboot.h>
#include <asm/setup.h>
#include <asm/hypervisor.h>
#include <asm/e820/api.h>
#include <asm/early_ioremap.h>

#include <asm/xen/cpuid.h>
#include <asm/xen/hypervisor.h>
#include <asm/xen/page.h>

#include "xen-ops.h"
#include "mmu.h"
#include "smp.h"

static void xen_hvm_init_shared_info(xenhost_t *xh)
{
	struct xen_add_to_physmap xatp;

	xatp.domid = DOMID_SELF;
	xatp.idx = 0;
	xatp.space = XENMAPSPACE_shared_info;
	xatp.gpfn = xh->shared_info_pfn;
	if (hypervisor_memory_op(xh, XENMEM_add_to_physmap, &xatp))
		BUG();
}

static void xen_hvm_reset_shared_info(xenhost_t *xh)
{
	early_memunmap(xh->HYPERVISOR_shared_info, PAGE_SIZE);
	xh->HYPERVISOR_shared_info = __va(PFN_PHYS(xh->shared_info_pfn));
}

static void __init reserve_shared_info(xenhost_t *xh)
{
	u64 pa;

	/*
	 * Search for a free page starting at 4kB physical address.
	 * Low memory is preferred to avoid an EPT large page split up
	 * by the mapping.
	 * Starting below X86_RESERVE_LOW (usually 64kB) is fine as
	 * the BIOS used for HVM guests is well behaved and won't
	 * clobber memory other than the first 4kB.
	 */
	for (pa = PAGE_SIZE;
	     !e820__mapped_all(pa, pa + PAGE_SIZE, E820_TYPE_RAM) ||
	     memblock_is_reserved(pa);
	     pa += PAGE_SIZE)
		;

	xh->shared_info_pfn = PHYS_PFN(pa);

	memblock_reserve(pa, PAGE_SIZE);
	xh->HYPERVISOR_shared_info = early_memremap(pa, PAGE_SIZE);
}

static void __init xen_hvm_init_mem_mapping(void)
{
	xenhost_t **xh;

	for_each_xenhost(xh) {
		xenhost_reset_shared_info(*xh);

		/*
		 * The virtual address of the shared_info page has changed, so
		 * the vcpu_info pointer for VCPU 0 is now stale.
		 *
		 * The prepare_boot_cpu callback will re-initialize it via
		 * xen_vcpu_setup, but we can't rely on that to be called for
		 * old Xen versions (xen_have_vector_callback == 0).
		 *
		 * It is, in any case, bad to have a stale vcpu_info pointer
		 * so reset it now.
		 */
		xen_vcpu_info_reset(*xh, 0);
	}
}

extern uint32_t xen_pv_cpuid_base(xenhost_t *xh);

void xen_hvm_setup_hypercall_page(xenhost_t *xh)
{
	u32 msr;
	u64 pfn;

	msr = cpuid_ebx(xenhost_cpuid_base(xh) + 2);
	pfn = __pa(xen_hypercall_page);
	wrmsr_safe(msr, (u32)pfn, (u32)(pfn >> 32));
	xh->hypercall_page = xen_hypercall_page;
}

static void xen_hvm_probe_vcpu_id(xenhost_t *xh, int cpu)
{
	uint32_t eax, ebx, ecx, edx, base;

	base = xenhost_cpuid_base(xh);

	if (cpu == 0) {
		cpuid(base + 4, &eax, &ebx, &ecx, &edx);
		if (eax & XEN_HVM_CPUID_VCPU_ID_PRESENT)
			xh->xen_vcpu_id[cpu] = ebx;
		else
			xh->xen_vcpu_id[cpu] = smp_processor_id();
	} else {
		if (cpu_acpi_id(cpu) != U32_MAX)
			xh->xen_vcpu_id[cpu] = cpu_acpi_id(cpu);
		else
			xh->xen_vcpu_id[cpu] = cpu;
	}
}

xenhost_ops_t xh_hvm_ops = {
	.cpuid_base = xen_pv_cpuid_base,
	.setup_hypercall_page = xen_hvm_setup_hypercall_page,
	.setup_shared_info = xen_hvm_init_shared_info,
	.reset_shared_info = xen_hvm_reset_shared_info,
	.probe_vcpu_id = xen_hvm_probe_vcpu_id,
};

xenhost_ops_t xh_hvm_nested_ops = {
};

static void __init init_hvm_pv_info(void)
{
	int major, minor;
	uint32_t eax, base;
	xenhost_t **xh;

	base = xenhost_cpuid_base(xh_default);
	eax = cpuid_eax(base + 1);

	major = eax >> 16;
	minor = eax & 0xffff;
	printk(KERN_INFO "Xen version %d.%d.\n", major, minor);

	xen_domain_type = XEN_HVM_DOMAIN;

	if (xen_pvh_domain())
		pv_info.name = "Xen PVH";
	else
		pv_info.name = "Xen HVM";

	for_each_xenhost(xh) {
		/* PVH set up hypercall page in xen_prepare_pvh(). */
		if (!xen_pvh_domain())
			xenhost_setup_hypercall_page(*xh);
		xen_setup_features(*xh);
	}

	/*
	 * Check if features are compatible across L1-Xen and L0-Xen;
	 * If not, get rid of xenhost_r2.
	 */
	if (xen_validate_features() == false)
		__xenhost_unregister(xenhost_r2);

	for_each_xenhost(xh)
		xenhost_probe_vcpu_id(*xh, smp_processor_id());
}

#ifdef CONFIG_KEXEC_CORE
static void xen_hvm_shutdown(void)
{
	native_machine_shutdown();
	if (kexec_in_progress)
		xen_reboot(SHUTDOWN_soft_reset);
}

static void xen_hvm_crash_shutdown(struct pt_regs *regs)
{
	native_machine_crash_shutdown(regs);
	xen_reboot(SHUTDOWN_soft_reset);
}
#endif

static int xen_cpu_up_prepare_hvm(unsigned int cpu)
{
	int rc = 0;
	xenhost_t **xh;

	/*
	 * This can happen if CPU was offlined earlier and
	 * offlining timed out in common_cpu_die().
	 */
	if (cpu_report_state(cpu) == CPU_DEAD_FROZEN) {
		xen_smp_intr_free(cpu);
		xen_uninit_lock_cpu(cpu);
	}

	for_each_xenhost(xh) {
		xenhost_probe_vcpu_id(*xh, cpu);
		rc = xen_vcpu_setup(*xh, cpu);
		if (rc)
			return rc;
	}

	if (xen_have_vector_callback && xen_feature(XENFEAT_hvm_safe_pvclock))
		xen_setup_timer(cpu);

	rc = xen_smp_intr_init(cpu);
	if (rc) {
		WARN(1, "xen_smp_intr_init() for CPU %d failed: %d\n",
		     cpu, rc);
	}
	return rc;
}

static int xen_cpu_dead_hvm(unsigned int cpu)
{
	xen_smp_intr_free(cpu);

	if (xen_have_vector_callback && xen_feature(XENFEAT_hvm_safe_pvclock))
		xen_teardown_timer(cpu);

       return 0;
}

static void __init xen_hvm_guest_init(void)
{
	xenhost_t **xh;

	if (xen_pv_domain())
		return;
	/*
	 * We need only xenhost_r1 for HVM guests since they cannot be
	 * driver domain (?) or dom0.
	 */
	if (!xen_pvh_domain())
		xenhost_register(xenhost_r1, &xh_hvm_ops);

	init_hvm_pv_info();

	for_each_xenhost(xh) {
		reserve_shared_info(*xh);
		xenhost_setup_shared_info(*xh);

		/*
		 * xen_vcpu is a pointer to the vcpu_info struct in the
		 * shared_info page, we use it in the event channel upcall
		 * and in some pvclock related functions.
		 */
		xen_vcpu_info_reset(*xh, 0);
	}


	xen_panic_handler_init();

	if (xen_feature(XENFEAT_hvm_callback_vector))
		xen_have_vector_callback = 1;

	xen_hvm_smp_init();
	WARN_ON(xen_cpuhp_setup(xen_cpu_up_prepare_hvm, xen_cpu_dead_hvm));
	xen_unplug_emulated_devices();
	x86_init.irqs.intr_init = xenhost_init_IRQ;
	xen_hvm_init_time_ops();
	xen_hvm_init_mmu_ops();

#ifdef CONFIG_KEXEC_CORE
	machine_ops.shutdown = xen_hvm_shutdown;
	machine_ops.crash_shutdown = xen_hvm_crash_shutdown;
#endif
}

static bool xen_nopv;
static __init int xen_parse_nopv(char *arg)
{
       xen_nopv = true;
       return 0;
}
early_param("xen_nopv", xen_parse_nopv);

bool xen_hvm_need_lapic(void)
{
	if (xen_nopv)
		return false;
	if (xen_pv_domain())
		return false;
	if (!xen_hvm_domain())
		return false;
	if (xen_feature(XENFEAT_hvm_pirqs) && xen_have_vector_callback)
		return false;
	return true;
}
EXPORT_SYMBOL_GPL(xen_hvm_need_lapic);

static uint32_t __init xen_platform_hvm(void)
{
	if (xen_pv_domain() || xen_nopv)
		return 0;

	return xenhost_cpuid_base(xh_default);
}

static __init void xen_hvm_guest_late_init(void)
{
#ifdef CONFIG_XEN_PVH
	/* Test for PVH domain (PVH boot path taken overrides ACPI flags). */
	if (!xen_pvh &&
	    (x86_platform.legacy.rtc || !x86_platform.legacy.no_vga))
		return;

	/* PVH detected. */
	xen_pvh = true;

	/* Make sure we don't fall back to (default) ACPI_IRQ_MODEL_PIC. */
	if (!nr_ioapics && acpi_irq_model == ACPI_IRQ_MODEL_PIC)
		acpi_irq_model = ACPI_IRQ_MODEL_PLATFORM;

	machine_ops.emergency_restart = xen_emergency_restart;
	pv_info.name = "Xen PVH";
#endif
}

const __initconst struct hypervisor_x86 x86_hyper_xen_hvm = {
	.name                   = "Xen HVM",
	.detect                 = xen_platform_hvm,
	.type			= X86_HYPER_XEN_HVM,
	.init.init_platform     = xen_hvm_guest_init,
	.init.x2apic_available  = xen_x2apic_para_available,
	.init.init_mem_mapping	= xen_hvm_init_mem_mapping,
	.init.guest_late_init	= xen_hvm_guest_late_init,
	.runtime.pin_vcpu       = xen_pin_vcpu,
};
