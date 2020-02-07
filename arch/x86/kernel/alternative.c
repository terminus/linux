// SPDX-License-Identifier: GPL-2.0-only
#define pr_fmt(fmt) "SMP alternatives: " fmt

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/stringify.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/memory.h>
#include <linux/stop_machine.h>
#include <linux/slab.h>
#include <linux/kdebug.h>
#include <linux/kprobes.h>
#include <linux/mmu_context.h>
#include <linux/bsearch.h>
#include <asm/text-patching.h>
#include <asm/alternative.h>
#include <asm/sections.h>
#include <asm/pgtable.h>
#include <asm/mce.h>
#include <asm/nmi.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>
#include <asm/insn.h>
#include <asm/io.h>
#include <asm/fixmap.h>
#include "pv_selftest.h"

int __read_mostly alternatives_patched;

EXPORT_SYMBOL_GPL(alternatives_patched);

#define MAX_PATCH_LEN (255-1)

static int __initdata_or_module debug_alternative;

static int __init debug_alt(char *str)
{
	debug_alternative = 1;
	return 1;
}
__setup("debug-alternative", debug_alt);

static int noreplace_smp;

static int __init setup_noreplace_smp(char *str)
{
	noreplace_smp = 1;
	return 1;
}
__setup("noreplace-smp", setup_noreplace_smp);

#define DPRINTK(fmt, args...)						\
do {									\
	if (debug_alternative)						\
		printk(KERN_DEBUG "%s: " fmt "\n", __func__, ##args);	\
} while (0)

#define DUMP_BYTES(buf, len, fmt, args...)				\
do {									\
	if (unlikely(debug_alternative)) {				\
		int j;							\
									\
		if (!(len))						\
			break;						\
									\
		printk(KERN_DEBUG fmt, ##args);				\
		for (j = 0; j < (len) - 1; j++)				\
			printk(KERN_CONT "%02hhx ", buf[j]);		\
		printk(KERN_CONT "%02hhx\n", buf[j]);			\
	}								\
} while (0)

/*
 * Each GENERIC_NOPX is of X bytes, and defined as an array of bytes
 * that correspond to that nop. Getting from one nop to the next, we
 * add to the array the offset that is equal to the sum of all sizes of
 * nops preceding the one we are after.
 *
 * Note: The GENERIC_NOP5_ATOMIC is at the end, as it breaks the
 * nice symmetry of sizes of the previous nops.
 */
#if defined(GENERIC_NOP1) && !defined(CONFIG_X86_64)
static const unsigned char intelnops[] =
{
	GENERIC_NOP1,
	GENERIC_NOP2,
	GENERIC_NOP3,
	GENERIC_NOP4,
	GENERIC_NOP5,
	GENERIC_NOP6,
	GENERIC_NOP7,
	GENERIC_NOP8,
	GENERIC_NOP5_ATOMIC
};
static const unsigned char * const intel_nops[ASM_NOP_MAX+2] =
{
	NULL,
	intelnops,
	intelnops + 1,
	intelnops + 1 + 2,
	intelnops + 1 + 2 + 3,
	intelnops + 1 + 2 + 3 + 4,
	intelnops + 1 + 2 + 3 + 4 + 5,
	intelnops + 1 + 2 + 3 + 4 + 5 + 6,
	intelnops + 1 + 2 + 3 + 4 + 5 + 6 + 7,
	intelnops + 1 + 2 + 3 + 4 + 5 + 6 + 7 + 8,
};
#endif

#ifdef K8_NOP1
static const unsigned char k8nops[] =
{
	K8_NOP1,
	K8_NOP2,
	K8_NOP3,
	K8_NOP4,
	K8_NOP5,
	K8_NOP6,
	K8_NOP7,
	K8_NOP8,
	K8_NOP5_ATOMIC
};
static const unsigned char * const k8_nops[ASM_NOP_MAX+2] =
{
	NULL,
	k8nops,
	k8nops + 1,
	k8nops + 1 + 2,
	k8nops + 1 + 2 + 3,
	k8nops + 1 + 2 + 3 + 4,
	k8nops + 1 + 2 + 3 + 4 + 5,
	k8nops + 1 + 2 + 3 + 4 + 5 + 6,
	k8nops + 1 + 2 + 3 + 4 + 5 + 6 + 7,
	k8nops + 1 + 2 + 3 + 4 + 5 + 6 + 7 + 8,
};
#endif

#if defined(K7_NOP1) && !defined(CONFIG_X86_64)
static const unsigned char k7nops[] =
{
	K7_NOP1,
	K7_NOP2,
	K7_NOP3,
	K7_NOP4,
	K7_NOP5,
	K7_NOP6,
	K7_NOP7,
	K7_NOP8,
	K7_NOP5_ATOMIC
};
static const unsigned char * const k7_nops[ASM_NOP_MAX+2] =
{
	NULL,
	k7nops,
	k7nops + 1,
	k7nops + 1 + 2,
	k7nops + 1 + 2 + 3,
	k7nops + 1 + 2 + 3 + 4,
	k7nops + 1 + 2 + 3 + 4 + 5,
	k7nops + 1 + 2 + 3 + 4 + 5 + 6,
	k7nops + 1 + 2 + 3 + 4 + 5 + 6 + 7,
	k7nops + 1 + 2 + 3 + 4 + 5 + 6 + 7 + 8,
};
#endif

#ifdef P6_NOP1
static const unsigned char p6nops[] =
{
	P6_NOP1,
	P6_NOP2,
	P6_NOP3,
	P6_NOP4,
	P6_NOP5,
	P6_NOP6,
	P6_NOP7,
	P6_NOP8,
	P6_NOP5_ATOMIC
};
static const unsigned char * const p6_nops[ASM_NOP_MAX+2] =
{
	NULL,
	p6nops,
	p6nops + 1,
	p6nops + 1 + 2,
	p6nops + 1 + 2 + 3,
	p6nops + 1 + 2 + 3 + 4,
	p6nops + 1 + 2 + 3 + 4 + 5,
	p6nops + 1 + 2 + 3 + 4 + 5 + 6,
	p6nops + 1 + 2 + 3 + 4 + 5 + 6 + 7,
	p6nops + 1 + 2 + 3 + 4 + 5 + 6 + 7 + 8,
};
#endif

/* Initialize these to a safe default */
#ifdef CONFIG_X86_64
const unsigned char * const *ideal_nops = p6_nops;
#else
const unsigned char * const *ideal_nops = intel_nops;
#endif

void __init arch_init_ideal_nops(void)
{
	switch (boot_cpu_data.x86_vendor) {
	case X86_VENDOR_INTEL:
		/*
		 * Due to a decoder implementation quirk, some
		 * specific Intel CPUs actually perform better with
		 * the "k8_nops" than with the SDM-recommended NOPs.
		 */
		if (boot_cpu_data.x86 == 6 &&
		    boot_cpu_data.x86_model >= 0x0f &&
		    boot_cpu_data.x86_model != 0x1c &&
		    boot_cpu_data.x86_model != 0x26 &&
		    boot_cpu_data.x86_model != 0x27 &&
		    boot_cpu_data.x86_model < 0x30) {
			ideal_nops = k8_nops;
		} else if (boot_cpu_has(X86_FEATURE_NOPL)) {
			   ideal_nops = p6_nops;
		} else {
#ifdef CONFIG_X86_64
			ideal_nops = k8_nops;
#else
			ideal_nops = intel_nops;
#endif
		}
		break;

	case X86_VENDOR_HYGON:
		ideal_nops = p6_nops;
		return;

	case X86_VENDOR_AMD:
		if (boot_cpu_data.x86 > 0xf) {
			ideal_nops = p6_nops;
			return;
		}

		/* fall through */

	default:
#ifdef CONFIG_X86_64
		ideal_nops = k8_nops;
#else
		if (boot_cpu_has(X86_FEATURE_K8))
			ideal_nops = k8_nops;
		else if (boot_cpu_has(X86_FEATURE_K7))
			ideal_nops = k7_nops;
		else
			ideal_nops = intel_nops;
#endif
	}
}

/* Use this to add nops to a buffer, then text_poke the whole buffer. */
static void __init_or_module add_nops(void *insns, unsigned int len)
{
	while (len > 0) {
		unsigned int noplen = len;
		if (noplen > ASM_NOP_MAX)
			noplen = ASM_NOP_MAX;
		memcpy(insns, ideal_nops[noplen], noplen);
		insns += noplen;
		len -= noplen;
	}
}

extern struct alt_instr __alt_instructions[], __alt_instructions_end[];
extern s32 __smp_locks[], __smp_locks_end[];
void text_poke_early(void *addr, const void *opcode, size_t len);

/*
 * Are we looking at a near JMP with a 1 or 4-byte displacement.
 */
static inline bool is_jmp(const u8 opcode)
{
	return opcode == 0xeb || opcode == 0xe9;
}

static void __init_or_module
recompute_jump(struct alt_instr *a, u8 *orig_insn, u8 *repl_insn, u8 *insn_buff)
{
	u8 *next_rip, *tgt_rip;
	s32 n_dspl, o_dspl;
	int repl_len;

	if (a->replacementlen != 5)
		return;

	o_dspl = *(s32 *)(insn_buff + 1);

	/* next_rip of the replacement JMP */
	next_rip = repl_insn + a->replacementlen;
	/* target rip of the replacement JMP */
	tgt_rip  = next_rip + o_dspl;
	n_dspl = tgt_rip - orig_insn;

	DPRINTK("target RIP: %px, new_displ: 0x%x", tgt_rip, n_dspl);

	if (tgt_rip - orig_insn >= 0) {
		if (n_dspl - 2 <= 127)
			goto two_byte_jmp;
		else
			goto five_byte_jmp;
	/* negative offset */
	} else {
		if (((n_dspl - 2) & 0xff) == (n_dspl - 2))
			goto two_byte_jmp;
		else
			goto five_byte_jmp;
	}

two_byte_jmp:
	n_dspl -= 2;

	insn_buff[0] = 0xeb;
	insn_buff[1] = (s8)n_dspl;
	add_nops(insn_buff + 2, 3);

	repl_len = 2;
	goto done;

five_byte_jmp:
	n_dspl -= 5;

	insn_buff[0] = 0xe9;
	*(s32 *)&insn_buff[1] = n_dspl;

	repl_len = 5;

done:

	DPRINTK("final displ: 0x%08x, JMP 0x%lx",
		n_dspl, (unsigned long)orig_insn + n_dspl + repl_len);
}

/*
 * "noinline" to cause control flow change and thus invalidate I$ and
 * cause refetch after modification.
 */
static void __init_or_module noinline optimize_nops(struct alt_instr *a, u8 *instr)
{
	unsigned long flags;
	int i;

	for (i = 0; i < a->padlen; i++) {
		if (instr[i] != 0x90)
			return;
	}

	local_irq_save(flags);
	add_nops(instr + (a->instrlen - a->padlen), a->padlen);
	local_irq_restore(flags);

	DUMP_BYTES(instr, a->instrlen, "%px: [%d:%d) optimized NOPs: ",
		   instr, a->instrlen - a->padlen, a->padlen);
}

/*
 * Replace instructions with better alternatives for this CPU type. This runs
 * before SMP is initialized to avoid SMP problems with self modifying code.
 * This implies that asymmetric systems where APs have less capabilities than
 * the boot processor are not handled. Tough. Make sure you disable such
 * features by hand.
 *
 * Marked "noinline" to cause control flow change and thus insn cache
 * to refetch changed I$ lines.
 */
void __init_or_module noinline apply_alternatives(struct alt_instr *start,
						  struct alt_instr *end)
{
	struct alt_instr *a;
	u8 *instr, *replacement;
	u8 insn_buff[MAX_PATCH_LEN];

	DPRINTK("alt table %px, -> %px", start, end);
	/*
	 * The scan order should be from start to end. A later scanned
	 * alternative code can overwrite previously scanned alternative code.
	 * Some kernel functions (e.g. memcpy, memset, etc) use this order to
	 * patch code.
	 *
	 * So be careful if you want to change the scan order to any other
	 * order.
	 */
	for (a = start; a < end; a++) {
		int insn_buff_sz = 0;

		instr = (u8 *)&a->instr_offset + a->instr_offset;
		replacement = (u8 *)&a->repl_offset + a->repl_offset;
		BUG_ON(a->instrlen > sizeof(insn_buff));
		BUG_ON(a->cpuid >= (NCAPINTS + NBUGINTS) * 32);
		if (!boot_cpu_has(a->cpuid)) {
			if (a->padlen > 1)
				optimize_nops(a, instr);

			continue;
		}

		DPRINTK("feat: %d*32+%d, old: (%pS (%px) len: %d), repl: (%px, len: %d), pad: %d",
			a->cpuid >> 5,
			a->cpuid & 0x1f,
			instr, instr, a->instrlen,
			replacement, a->replacementlen, a->padlen);

		DUMP_BYTES(instr, a->instrlen, "%px: old_insn: ", instr);
		DUMP_BYTES(replacement, a->replacementlen, "%px: rpl_insn: ", replacement);

		memcpy(insn_buff, replacement, a->replacementlen);
		insn_buff_sz = a->replacementlen;

		/*
		 * 0xe8 is a relative jump; fix the offset.
		 *
		 * Instruction length is checked before the opcode to avoid
		 * accessing uninitialized bytes for zero-length replacements.
		 */
		if (a->replacementlen == 5 && *insn_buff == 0xe8) {
			*(s32 *)(insn_buff + 1) += replacement - instr;
			DPRINTK("Fix CALL offset: 0x%x, CALL 0x%lx",
				*(s32 *)(insn_buff + 1),
				(unsigned long)instr + *(s32 *)(insn_buff + 1) + 5);
		}

		if (a->replacementlen && is_jmp(replacement[0]))
			recompute_jump(a, instr, replacement, insn_buff);

		if (a->instrlen > a->replacementlen) {
			add_nops(insn_buff + a->replacementlen,
				 a->instrlen - a->replacementlen);
			insn_buff_sz += a->instrlen - a->replacementlen;
		}
		DUMP_BYTES(insn_buff, insn_buff_sz, "%px: final_insn: ", instr);

		text_poke_early(instr, insn_buff, insn_buff_sz);
	}
}

#ifdef CONFIG_SMP
static void alternatives_smp_lock(const s32 *start, const s32 *end,
				  u8 *text, u8 *text_end)
{
	const s32 *poff;

	for (poff = start; poff < end; poff++) {
		u8 *ptr = (u8 *)poff + *poff;

		if (!*poff || ptr < text || ptr >= text_end)
			continue;
		/* turn DS segment override prefix into lock prefix */
		if (*ptr == 0x3e)
			text_poke(ptr, ((unsigned char []){0xf0}), 1);
	}
}

static void alternatives_smp_unlock(const s32 *start, const s32 *end,
				    u8 *text, u8 *text_end)
{
	const s32 *poff;

	for (poff = start; poff < end; poff++) {
		u8 *ptr = (u8 *)poff + *poff;

		if (!*poff || ptr < text || ptr >= text_end)
			continue;
		/* turn lock prefix into DS segment override prefix */
		if (*ptr == 0xf0)
			text_poke(ptr, ((unsigned char []){0x3E}), 1);
	}
}

static bool uniproc_patched;	/* protected by text_mutex */
#else	/* !CONFIG_SMP */
#define uniproc_patched false
static inline void alternatives_smp_unlock(const s32 *start, const s32 *end,
					   u8 *text, u8 *text_end) { }
#endif	/* CONFIG_SMP */

struct alt_module {
	/* what is this ??? */
	struct module	*mod;
	char		*name;

#ifdef CONFIG_PARAVIRT_RUNTIME
	/* ptrs to paravirt sites */
	struct paravirt_patch_site *para;
	struct paravirt_patch_site *para_end;
#endif

	/* ptrs to lock prefixes */
	const s32	*locks;
	const s32	*locks_end;

	/* .text segment, needed to avoid patching init code ;) */
	u8		*text;
	u8		*text_end;

	struct list_head next;
};

static LIST_HEAD(alt_modules);

void __init_or_module alternatives_module_add(struct module *mod, char *name,
					      void *para, void *para_end,
					      void *locks, void *locks_end,
					      void *text,  void *text_end)
{
	struct alt_module *alt;

#ifdef CONFIG_SMP
	/* Patch to UP if other cpus not imminent. */
	if (!noreplace_smp && (num_present_cpus() == 1 || setup_max_cpus <= 1))
		uniproc_patched = true;
#endif
	if (!IS_ENABLED(CONFIG_PARAVIRT_RUNTIME) && !uniproc_patched)
		return;

	mutex_lock(&text_mutex);

	alt = kzalloc(sizeof(*alt), GFP_KERNEL | __GFP_NOFAIL);

	alt->mod	= mod;
	alt->name	= name;

#ifdef CONFIG_PARAVIRT_RUNTIME
	alt->para	= para;
	alt->para_end	= para_end;
#endif

	if (num_possible_cpus() != 1 || uniproc_patched) {
		/* Remember only if we'll need to undo it. */
		alt->locks	= locks;
		alt->locks_end	= locks_end;
	}

	alt->text	= text;
	alt->text_end	= text_end;
	DPRINTK("locks %p -> %p, text %p -> %p, name %s\n",
		alt->locks, alt->locks_end,
		alt->text, alt->text_end, alt->name);

	list_add_tail(&alt->next, &alt_modules);

	if (uniproc_patched)
		alternatives_smp_unlock(locks, locks_end, text, text_end);
	mutex_unlock(&text_mutex);
}

void __init_or_module alternatives_module_del(struct module *mod)
{
	struct alt_module *item;

	mutex_lock(&text_mutex);
	list_for_each_entry(item, &alt_modules, next) {
		if (mod != item->mod)
			continue;
		list_del(&item->next);
		kfree(item);
		break;
	}
	mutex_unlock(&text_mutex);
}

#ifdef CONFIG_SMP
void alternatives_enable_smp(void)
{
	struct alt_module *mod;

	/* Why bother if there are no other CPUs? */
	BUG_ON(num_possible_cpus() == 1);

	mutex_lock(&text_mutex);

	if (uniproc_patched) {
		pr_info("switching to SMP code\n");
		BUG_ON(num_online_cpus() != 1);
		clear_cpu_cap(&boot_cpu_data, X86_FEATURE_UP);
		clear_cpu_cap(&cpu_data(0), X86_FEATURE_UP);
		list_for_each_entry(mod, &alt_modules, next)
			alternatives_smp_lock(mod->locks, mod->locks_end,
					      mod->text, mod->text_end);
		uniproc_patched = false;
	}
	mutex_unlock(&text_mutex);
}
#endif /* CONFIG_SMP */

/*
 * Return 1 if the address range is reserved for SMP-alternatives.
 * Must hold text_mutex.
 */
int alternatives_text_reserved(void *start, void *end)
{
	struct alt_module *mod;
	const s32 *poff;
	u8 *text_start = start;
	u8 *text_end = end;

	lockdep_assert_held(&text_mutex);

	list_for_each_entry(mod, &alt_modules, next) {
		if (mod->text > text_end || mod->text_end < text_start)
			continue;
		for (poff = mod->locks; poff < mod->locks_end; poff++) {
			const u8 *ptr = (const u8 *)poff + *poff;

			if (text_start <= ptr && text_end > ptr)
				return 1;
		}
	}

	return 0;
}

#ifdef CONFIG_PARAVIRT
void __init_or_module apply_paravirt(struct paravirt_patch_site *start,
				     struct paravirt_patch_site *end)
{
	struct paravirt_patch_site *p;
	char insn_buff[MAX_PATCH_LEN];

	for (p = start; p < end; p++) {
		unsigned int used;

		BUG_ON(p->len > MAX_PATCH_LEN);
		/* prep the buffer with the original instructions */
		memcpy(insn_buff, p->instr, p->len);
		used = pv_ops.init.patch(p->type, insn_buff, (unsigned long)p->instr, p->len);

		BUG_ON(used > p->len);

		/* Pad the rest with nops */
		add_nops(insn_buff + used, p->len - used);
		text_poke_early(p->instr, insn_buff, p->len);
	}
}
#endif	/* CONFIG_PARAVIRT */

/*
 * Self-test for the INT3 based CALL emulation code.
 *
 * This exercises int3_emulate_call() to make sure INT3 pt_regs are set up
 * properly and that there is a stack gap between the INT3 frame and the
 * previous context. Without this gap doing a virtual PUSH on the interrupted
 * stack would corrupt the INT3 IRET frame.
 *
 * See entry_{32,64}.S for more details.
 */

/*
 * We define the int3_magic() function in assembly to control the calling
 * convention such that we can 'call' it from assembly.
 */

extern void int3_magic(unsigned int *ptr); /* defined in asm */

asm (
"	.pushsection	.init.text, \"ax\", @progbits\n"
"	.type		int3_magic, @function\n"
"int3_magic:\n"
"	movl	$1, (%" _ASM_ARG1 ")\n"
"	ret\n"
"	.size		int3_magic, .-int3_magic\n"
"	.popsection\n"
);

extern __initdata unsigned long int3_selftest_ip; /* defined in asm below */

static int __init
int3_exception_notify(struct notifier_block *self, unsigned long val, void *data)
{
	struct die_args *args = data;
	struct pt_regs *regs = args->regs;

	if (!regs || user_mode(regs))
		return NOTIFY_DONE;

	if (val != DIE_INT3)
		return NOTIFY_DONE;

	if (regs->ip - INT3_INSN_SIZE != int3_selftest_ip)
		return NOTIFY_DONE;

	int3_emulate_call(regs, (unsigned long)&int3_magic);
	return NOTIFY_STOP;
}

static void __init int3_selftest(void)
{
	static __initdata struct notifier_block int3_exception_nb = {
		.notifier_call	= int3_exception_notify,
		.priority	= INT_MAX-1, /* last */
	};
	unsigned int val = 0;

	BUG_ON(register_die_notifier(&int3_exception_nb));

	/*
	 * Basically: int3_magic(&val); but really complicated :-)
	 *
	 * Stick the address of the INT3 instruction into int3_selftest_ip,
	 * then trigger the INT3, padded with NOPs to match a CALL instruction
	 * length.
	 */
	asm volatile ("1: int3; nop; nop; nop; nop\n\t"
		      ".pushsection .init.data,\"aw\"\n\t"
		      ".align " __ASM_SEL(4, 8) "\n\t"
		      ".type int3_selftest_ip, @object\n\t"
		      ".size int3_selftest_ip, " __ASM_SEL(4, 8) "\n\t"
		      "int3_selftest_ip:\n\t"
		      __ASM_SEL(.long, .quad) " 1b\n\t"
		      ".popsection\n\t"
		      : ASM_CALL_CONSTRAINT
		      : __ASM_SEL_RAW(a, D) (&val)
		      : "memory");

	BUG_ON(val != 1);

	unregister_die_notifier(&int3_exception_nb);
}

void __init alternative_instructions(void)
{
	int3_selftest();

	/*
	 * The patching is not fully atomic, so try to avoid local
	 * interruptions that might execute the to be patched code.
	 * Other CPUs are not running.
	 */
	stop_nmi();

	/*
	 * Don't stop machine check exceptions while patching.
	 * MCEs only happen when something got corrupted and in this
	 * case we must do something about the corruption.
	 * Ignoring it is worse than an unlikely patching race.
	 * Also machine checks tend to be broadcast and if one CPU
	 * goes into machine check the others follow quickly, so we don't
	 * expect a machine check to cause undue problems during to code
	 * patching.
	 */

	apply_alternatives(__alt_instructions, __alt_instructions_end);

	alternatives_module_add(NULL, "core kernel",
				__parainstructions_runtime,
				__parainstructions_runtime_end,
				__smp_locks, __smp_locks_end,
				_text, _etext);

	if (!uniproc_patched || num_possible_cpus() == 1) {
		free_init_pages("SMP alternatives",
				(unsigned long)__smp_locks,
				(unsigned long)__smp_locks_end);
	}

	apply_paravirt(__parainstructions, __parainstructions_end);
	apply_paravirt(__parainstructions_runtime,
		       __parainstructions_runtime_end);

	restart_nmi();
	alternatives_patched = 1;
}

/**
 * text_poke_early - Update instructions on a live kernel at boot time
 * @addr: address to modify
 * @opcode: source of the copy
 * @len: length to copy
 *
 * When you use this code to patch more than one byte of an instruction
 * you need to make sure that other CPUs cannot execute this code in parallel.
 * Also no thread must be currently preempted in the middle of these
 * instructions. And on the local CPU you need to be protected against NMI or
 * MCE handlers seeing an inconsistent instruction while you patch.
 */
void __init_or_module text_poke_early(void *addr, const void *opcode,
				      size_t len)
{
	unsigned long flags;

	if (boot_cpu_has(X86_FEATURE_NX) &&
	    is_module_text_address((unsigned long)addr)) {
		/*
		 * Modules text is marked initially as non-executable, so the
		 * code cannot be running and speculative code-fetches are
		 * prevented. Just change the code.
		 */
		memcpy(addr, opcode, len);
	} else {
		local_irq_save(flags);
		memcpy(addr, opcode, len);
		local_irq_restore(flags);
		sync_core();

		/*
		 * Could also do a CLFLUSH here to speed up CPU recovery; but
		 * that causes hangs on some VIA CPUs.
		 */
	}
}

__ro_after_init struct mm_struct *poking_mm;
__ro_after_init unsigned long poking_addr;

static void __text_poke_map(void *addr, size_t len,
			    temp_mm_state_t *prev_mm, pte_t **ptep)
{
	bool cross_page_boundary = offset_in_page(addr) + len > PAGE_SIZE;
	struct page *pages[2] = {NULL};
	pte_t pte;
	pgprot_t pgprot;

	/*
	 * While boot memory allocator is running we cannot use struct pages as
	 * they are not yet initialized. There is no way to recover.
	 */
	BUG_ON(!after_bootmem);

	if (!core_kernel_text((unsigned long)addr)) {
		pages[0] = vmalloc_to_page(addr);
		if (cross_page_boundary)
			pages[1] = vmalloc_to_page(addr + PAGE_SIZE);
	} else {
		pages[0] = virt_to_page(addr);
		WARN_ON(!PageReserved(pages[0]));
		if (cross_page_boundary)
			pages[1] = virt_to_page(addr + PAGE_SIZE);
	}
	/*
	 * If something went wrong, crash and burn since recovery paths are not
	 * implemented.
	 */
	BUG_ON(!pages[0] || (cross_page_boundary && !pages[1]));

	/*
	 * Map the page without the global bit, as TLB flushing is done with
	 * flush_tlb_mm_range(), which is intended for non-global PTEs.
	 */
	pgprot = __pgprot(pgprot_val(PAGE_KERNEL) & ~_PAGE_GLOBAL);

	/*
	 * text_poke() might be used to poke spinlock primitives so do this
	 * unlocked. This does mean that we need to be careful that no other
	 * context (ex. INT3 handler) is simultaneously writing to this pte.
	 */
	*ptep = __get_unlocked_pte(poking_mm, poking_addr);
	/*
	 * This must not fail; preallocated in poking_init().
	 */
	VM_BUG_ON(!*ptep);

	pte = mk_pte(pages[0], pgprot);
	set_pte_at(poking_mm, poking_addr, *ptep, pte);

	if (cross_page_boundary) {
		pte = mk_pte(pages[1], pgprot);
		set_pte_at(poking_mm, poking_addr + PAGE_SIZE, *ptep + 1, pte);
	}

	/*
	 * Loading the temporary mm behaves as a compiler barrier, which
	 * guarantees that the PTE will be set at the time memcpy() is done.
	 */
	*prev_mm = use_temporary_mm(poking_mm);
}

/*
 * Do the actual poke. Needs to be re-entrant as this can be called
 * via INT3 context as well.
 */
static void __text_do_poke(unsigned long offset, const void *opcode, size_t len)
{
	kasan_disable_current();
	memcpy((u8 *)poking_addr + offset, opcode, len);
	kasan_enable_current();
}

static void __text_poke_unmap(void *addr, const void *opcode, size_t len,
			      temp_mm_state_t *prev_mm, pte_t *ptep)
{
	bool cross_page_boundary = offset_in_page(addr) + len > PAGE_SIZE;
	/*
	 * Ensure that the PTE is only cleared after the instructions of memcpy
	 * were issued by using a compiler barrier.
	 */
	barrier();

	pte_clear(poking_mm, poking_addr, ptep);
	if (cross_page_boundary)
		pte_clear(poking_mm, poking_addr + PAGE_SIZE, ptep + 1);

	/*
	 * Loading the previous page-table hierarchy requires a serializing
	 * instruction that already allows the core to see the updated version.
	 * Xen-PV is assumed to serialize execution in a similar manner.
	 */
	unuse_temporary_mm(*prev_mm);

	/*
	 * Flushing the TLB might involve IPIs, which would require enabled
	 * IRQs, but not if the mm is not used, as it is in this point.
	 */
	flush_tlb_mm_range(poking_mm, poking_addr, poking_addr +
			   (cross_page_boundary ? 2 : 1) * PAGE_SIZE,
			   PAGE_SHIFT, false);

	/*
	 * If the text does not match what we just wrote then something is
	 * fundamentally screwy; there's nothing we can really do about that.
	 */
	BUG_ON(memcmp(addr, opcode, len));
}

static void __text_poke(void *addr, const void *opcode, size_t len)
{
	temp_mm_state_t prev_mm;
	unsigned long flags;
	pte_t *ptep;

	local_irq_save(flags);
	__text_poke_map(addr, len, &prev_mm, &ptep);
	__text_do_poke(offset_in_page(addr), opcode, len);
	__text_poke_unmap(addr, opcode, len, &prev_mm, ptep);
	local_irq_restore(flags);
}

/**
 * text_poke - Update instructions on a live kernel
 * @addr: address to modify
 * @opcode: source of the copy
 * @len: length to copy
 *
 * Only atomic text poke/set should be allowed when not doing early patching.
 * It means the size must be writable atomically and the address must be aligned
 * in a way that permits an atomic write. It also makes sure we fit on a single
 * page.
 *
 * Note that the caller must ensure that if the modified code is part of a
 * module, the module would not be removed during poking. This can be achieved
 * by registering a module notifier, and ordering module removal and patching
 * trough a mutex.
 */
void text_poke(void *addr, const void *opcode, size_t len)
{
	lockdep_assert_held(&text_mutex);

	__text_poke(addr, opcode, len);
}

/**
 * text_poke_kgdb - Update instructions on a live kernel by kgdb
 * @addr: address to modify
 * @opcode: source of the copy
 * @len: length to copy
 *
 * Only atomic text poke/set should be allowed when not doing early patching.
 * It means the size must be writable atomically and the address must be aligned
 * in a way that permits an atomic write. It also makes sure we fit on a single
 * page.
 *
 * Context: should only be used by kgdb, which ensures no other core is running,
 *	    despite the fact it does not hold the text_mutex.
 */
void text_poke_kgdb(void *addr, const void *opcode, size_t len)
{
	__text_poke(addr, opcode, len);
}

static void do_sync_core(void *info)
{
	sync_core();
}

void text_poke_sync(void)
{
	on_each_cpu(do_sync_core, NULL, 1);
}

static void __maybe_unused sync_one(void)
{
	/*
	 * We might be executing in NMI context, and so cannot use
	 * IRET as a synchronizing instruction.
	 *
	 * We could use native_write_cr2() but that is not guaranteed
	 * to work on Xen-PV -- it is emulated by Xen and might not
	 * execute an iret (or similar synchronizing instruction)
	 * internally.
	 *
	 * cpuid() would trap as well. Unclear if that's a solution
	 * either.
	 */
	if (in_nmi())
		cpuid_eax(1);
	else
		sync_core();
}

struct text_poke_loc {
	s32 rel_addr; /* addr := _stext + rel_addr */
	union {
		struct {
			s32 rel32;
			u8 opcode;
		} emulated;
		struct {
			u8 len;
		} native;
	};
	const u8 text[POKE_MAX_OPCODE_SIZE];
};

struct bp_patching_desc {
	struct text_poke_loc *vec;
	int nr_entries;
	atomic_t refs;
	bool native;
};

static struct bp_patching_desc *bp_desc;

static inline struct bp_patching_desc *try_get_desc(struct bp_patching_desc **descp)
{
	struct bp_patching_desc *desc = READ_ONCE(*descp); /* rcu_dereference */

	if (!desc || !atomic_inc_not_zero(&desc->refs))
		return NULL;

	return desc;
}

static inline void put_desc(struct bp_patching_desc *desc)
{
	smp_mb__before_atomic();
	atomic_dec(&desc->refs);
}

static inline void *text_poke_addr(struct text_poke_loc *tp)
{
	return _stext + tp->rel_addr;
}

static int notrace patch_cmp(const void *key, const void *elt)
{
	struct text_poke_loc *tp = (struct text_poke_loc *) elt;

	if (key < text_poke_addr(tp))
		return -1;
	if (key > text_poke_addr(tp))
		return 1;
	return 0;
}
NOKPROBE_SYMBOL(patch_cmp);

static void poke_int3_native(struct pt_regs *regs,
			     struct text_poke_loc *tp);
int notrace poke_int3_handler(struct pt_regs *regs)
{
	struct bp_patching_desc *desc;
	struct text_poke_loc *tp;
	int len, ret = 0;
	void *ip;

	if (user_mode(regs))
		return 0;

	/*
	 * Having observed our INT3 instruction, we now must observe
	 * bp_desc:
	 *
	 *	bp_desc = desc			INT3
	 *	WMB				RMB
	 *	write INT3			if (desc)
	 */
	smp_rmb();

	desc = try_get_desc(&bp_desc);
	if (!desc)
		return 0;

	/*
	 * Discount the INT3. See text_poke_bp_batch().
	 */
	ip = (void *) regs->ip - INT3_INSN_SIZE;

	/*
	 * Skip the binary search if there is a single member in the vector.
	 */
	if (unlikely(desc->nr_entries > 1)) {
		tp = bsearch(ip, desc->vec, desc->nr_entries,
			     sizeof(struct text_poke_loc),
			     patch_cmp);
		if (!tp)
			goto out_put;
	} else {
		tp = desc->vec;
		if (text_poke_addr(tp) != ip)
			goto out_put;
	}

	if (desc->native) {
		poke_int3_native(regs, tp);
		ret = 1; /* handled */
		goto out_put;
	}

	len = text_opcode_size(tp->emulated.opcode);
	ip += len;

	switch (tp->emulated.opcode) {
	case INT3_INSN_OPCODE:
		/*
		 * Someone poked an explicit INT3, they'll want to handle it,
		 * do not consume.
		 */
		goto out_put;

	case CALL_INSN_OPCODE:
		int3_emulate_call(regs, (long)ip + tp->emulated.rel32);
		break;

	case JMP32_INSN_OPCODE:
	case JMP8_INSN_OPCODE:
		int3_emulate_jmp(regs, (long)ip + tp->emulated.rel32);
		break;

	default:
		BUG();
	}

	ret = 1;

out_put:
	put_desc(desc);
	return ret;
}
NOKPROBE_SYMBOL(poke_int3_handler);

#define TP_VEC_MAX (PAGE_SIZE / sizeof(struct text_poke_loc))
static struct text_poke_loc tp_vec[TP_VEC_MAX];
static int tp_vec_nr;

/**
 * text_poke_bp_batch() -- update instructions on live kernel on SMP
 * @tp:			vector of instructions to patch
 * @nr_entries:		number of entries in the vector
 *
 * Modify multi-byte instruction by using int3 breakpoint on SMP.
 * We completely avoid stop_machine() here, and achieve the
 * synchronization using int3 breakpoint.
 *
 * The way it is done:
 *	- For each entry in the vector:
 *		- add a int3 trap to the address that will be patched
 *	- sync cores
 *	- For each entry in the vector:
 *		- update all but the first byte of the patched range
 *	- sync cores
 *	- For each entry in the vector:
 *		- replace the first byte (int3) by the first byte of
 *		  replacing opcode
 *	- sync cores
 */
static void text_poke_bp_batch(struct text_poke_loc *tp, unsigned int nr_entries)
{
	struct bp_patching_desc desc = {
		.vec = tp,
		.nr_entries = nr_entries,
		.refs = ATOMIC_INIT(1),
		.native = false,
	};
	unsigned char int3 = INT3_INSN_OPCODE;
	unsigned int i;
	int do_sync;

	lockdep_assert_held(&text_mutex);

	smp_store_release(&bp_desc, &desc); /* rcu_assign_pointer */

	/*
	 * Corresponding read barrier in int3 notifier for making sure the
	 * nr_entries and handler are correctly ordered wrt. patching.
	 */
	smp_wmb();

	/*
	 * First step: add a int3 trap to the address that will be patched.
	 */
	for (i = 0; i < nr_entries; i++)
		text_poke(text_poke_addr(&tp[i]), &int3, INT3_INSN_SIZE);

	text_poke_sync();

	/*
	 * Second step: update all but the first byte of the patched range.
	 */
	for (do_sync = 0, i = 0; i < nr_entries; i++) {
		int len = text_opcode_size(tp[i].emulated.opcode);

		if (len - INT3_INSN_SIZE > 0) {
			text_poke(text_poke_addr(&tp[i]) + INT3_INSN_SIZE,
				  (const char *)tp[i].text + INT3_INSN_SIZE,
				  len - INT3_INSN_SIZE);
			do_sync++;
		}
	}

	if (do_sync) {
		/*
		 * According to Intel, this core syncing is very likely
		 * not necessary and we'd be safe even without it. But
		 * better safe than sorry (plus there's not only Intel).
		 */
		text_poke_sync();
	}

	/*
	 * Third step: replace the first byte (int3) by the first byte of
	 * replacing opcode.
	 */
	for (do_sync = 0, i = 0; i < nr_entries; i++) {
		if (tp[i].text[0] == INT3_INSN_OPCODE)
			continue;

		text_poke(text_poke_addr(&tp[i]), tp[i].text, INT3_INSN_SIZE);
		do_sync++;
	}

	if (do_sync)
		text_poke_sync();

	/*
	 * Remove and synchronize_rcu(), except we have a very primitive
	 * refcount based completion.
	 */
	WRITE_ONCE(bp_desc, NULL); /* RCU_INIT_POINTER */
	if (!atomic_dec_and_test(&desc.refs))
		atomic_cond_read_acquire(&desc.refs, !VAL);
}

static void text_poke_loc_init(struct text_poke_loc *tp, void *addr,
			       const void *opcode, size_t len,
			       const void *emulate, bool native)
{
	struct insn insn;

	memset((void *)tp, 0, sizeof(*tp));
	memcpy((void *)tp->text, opcode, len);

	tp->rel_addr = addr - (void *)_stext;

	/*
	 * Native mode: when we might be poking
	 * arbitrary (perhaps) multiple instructions.
	 */
	if (native) {
		tp->native.len = (u8)len;
		return;
	}

	if (!emulate)
		emulate = opcode;

	kernel_insn_init(&insn, emulate, MAX_INSN_SIZE);
	insn_get_length(&insn);

	BUG_ON(!insn_complete(&insn));
	BUG_ON(len != insn.length);

	tp->emulated.opcode = insn.opcode.bytes[0];

	switch (tp->emulated.opcode) {
	case INT3_INSN_OPCODE:
		break;

	case CALL_INSN_OPCODE:
	case JMP32_INSN_OPCODE:
	case JMP8_INSN_OPCODE:
		tp->emulated.rel32 = insn.immediate.value;
		break;

	default: /* assume NOP */
		switch (len) {
		case 2: /* NOP2 -- emulate as JMP8+0 */
			BUG_ON(memcmp(emulate, ideal_nops[len], len));
			tp->emulated.opcode = JMP8_INSN_OPCODE;
			tp->emulated.rel32 = 0;
			break;

		case 5: /* NOP5 -- emulate as JMP32+0 */
			BUG_ON(memcmp(emulate, ideal_nops[NOP_ATOMIC5], len));
			tp->emulated.opcode = JMP32_INSN_OPCODE;
			tp->emulated.rel32 = 0;
			break;

		default: /* unknown instruction */
			BUG();
		}
		break;
	}
}

/*
 * We hard rely on the tp_vec being ordered; ensure this is so by flushing
 * early if needed.
 */
static bool tp_order_fail(void *addr)
{
	struct text_poke_loc *tp;

	if (!tp_vec_nr)
		return false;

	if (!addr) /* force */
		return true;

	tp = &tp_vec[tp_vec_nr - 1];
	if ((unsigned long)text_poke_addr(tp) > (unsigned long)addr)
		return true;

	return false;
}

static void text_poke_flush(void *addr)
{
	if (tp_vec_nr == TP_VEC_MAX || tp_order_fail(addr)) {
		text_poke_bp_batch(tp_vec, tp_vec_nr);
		tp_vec_nr = 0;
	}
}

void text_poke_finish(void)
{
	text_poke_flush(NULL);
}

void __ref text_poke_queue(void *addr, const void *opcode, size_t len, const void *emulate)
{
	struct text_poke_loc *tp;

	if (unlikely(system_state == SYSTEM_BOOTING)) {
		text_poke_early(addr, opcode, len);
		return;
	}

	text_poke_flush(addr);

	tp = &tp_vec[tp_vec_nr++];
	text_poke_loc_init(tp, addr, opcode, len, emulate, false);
}

/**
 * text_poke_bp() -- update instructions on live kernel on SMP
 * @addr:	address to patch
 * @opcode:	opcode of new instruction
 * @len:	length to copy
 * @handler:	address to jump to when the temporary breakpoint is hit
 *
 * Update a single instruction with the vector in the stack, avoiding
 * dynamically allocated memory. This function should be used when it is
 * not possible to allocate memory.
 */
void __ref text_poke_bp(void *addr, const void *opcode, size_t len, const void *emulate)
{
	struct text_poke_loc tp;

	if (unlikely(system_state == SYSTEM_BOOTING)) {
		text_poke_early(addr, opcode, len);
		return;
	}

	text_poke_loc_init(&tp, addr, opcode, len, emulate, false);
	text_poke_bp_batch(&tp, 1);
}

struct text_poke_state;
typedef void (*patch_worker_t)(struct text_poke_state *tps);

/*
 *                        +-----------possible-BP----------+
 *                        |                                |
 *         +--write-INT3--+   +--suffix--+   +-insn-prefix-+
 *        /               | _/           |__/              |
 *       /                v'             v                 v
 * PATCH_SYNC_0    PATCH_SYNC_1    PATCH_SYNC_2   *PATCH_SYNC_DONE*
 *       \                                                    |`----> PATCH_DONE
 *        `----------<---------<---------<---------<----------+
 *
 * We start in state PATCH_SYNC_DONE and loop through PATCH_SYNC_* states
 * to end at PATCH_DONE. The primary drives these in text_poke_site()
 * with patch_worker() making the final transition to PATCH_DONE.
 * All transitions but the last iteration need to be globally observed.
 *
 * On secondary CPUs, text_poke_sync_finish() waits in a cpu_relax()
 * loop waiting for a transition to PATCH_SYNC_0 at which point it would
 * start observing transitions until PATCH_SYNC_DONE.
 * Eventually the master moves to PATCH_DONE and secondary CPUs finish.
 */
enum patch_state {
	/*
	 * Add an artificial state that we can do a bitwise operation
	 * over all the PATCH_SYNC_* states.
	 */
	PATCH_SYNC_x = 4,
	PATCH_SYNC_0 = PATCH_SYNC_x | 0,	/* Serialize INT3 */
	PATCH_SYNC_1 = PATCH_SYNC_x | 1,	/* Serialize rest */
	PATCH_SYNC_2 = PATCH_SYNC_x | 2,	/* Serialize first opcode */
	PATCH_SYNC_DONE = PATCH_SYNC_x | 3,	/* Site done, and start state */

	PATCH_DONE = 8,				/* End state */
};

/*
 * State for driving text-poking via stop_machine().
 */
struct text_poke_state {
	/* Whatever we are poking */
	void *stage;

	/* Modules to be processed. */
	struct list_head *head;

	/*
	 * Accesses to sync_ack_map are ordered by the primary
	 * via tps.state.
	 */
	struct cpumask sync_ack_map;

	/*
	 * Generates insn sequences for call-sites to be patched and
	 * calls text_poke_site() to do the actual poking.
	 */
	patch_worker_t	patch_worker;

	/*
	 * Where are we in the patching state-machine.
	 */
	enum patch_state state;

	unsigned int primary_cpu; /* CPU doing the patching. */
	unsigned int num_acks; /* Number of Acks needed. */

	/*
	 * To synchronize with the NMI handler.
	 */
	atomic_t nmi_work;

	/* Ensure this is patched atomically against NMIs. */
	bool nmi_context;
};

static struct text_poke_state text_poke_state;

static void wait_for_acks(struct text_poke_state *tps)
{
	int cpu = smp_processor_id();

	cpumask_set_cpu(cpu, &tps->sync_ack_map);

	/* Wait until all CPUs are known to have observed the state change. */
	while (cpumask_weight(&tps->sync_ack_map) < tps->num_acks)
		cpu_relax();
}

/**
 * poke_sync() - carries out one poke-step for a single site and
 * transitions to the specified state.
 * Called with the target populated in poking_mm and poking_addr.
 *
 * @tps - struct text_poke_state *
 * @state - one of PATCH_SYNC_* states
 * @offset - offset to be patched
 * @insns - insns to write
 * @len - length of insn sequence
 *
 * Returns after all CPUs have observed the state change and called
 * sync_core().
 */
static void poke_sync(struct text_poke_state *tps, int state, int offset,
		      const char *insns, int len)
{
	if (len) {
		/*
		 * Note that we could hit a BP right after patching memory
		 * below. This could happen before the state change further
		 * down. The primary BP handler allows us to make
		 * forward-progress in that case.
		 */
		__text_do_poke(offset, insns, len);
	}
	/*
	 * Stores to tps.sync_ack_map are ordered with
	 * smp_load_acquire(tps->state) in text_poke_sync_site()
	 * so we can safely clear the cpumask.
	 */
	smp_store_release(&tps->state, state);

	cpumask_clear(&tps->sync_ack_map);

	/*
	 * Introduce a synchronizing instruction in local and remote insn
	 * streams. This flushes any stale cached uops from CPU pipelines.
	 */
	sync_one();

	wait_for_acks(tps);
}

/**
 * text_poke_site() - called on the primary to patch a single call site.
 * The interlocking sync work on the secondary is done in text_poke_sync_site().
 *
 * Called in thread context with tps->state == PATCH_SYNC_DONE where it
 * takes tps->state through different PATCH_SYNC_* states, returning
 * after having switched the tps->state back to PATCH_SYNC_DONE.
 */
static void __maybe_unused text_poke_site(struct text_poke_state *tps,
					  struct text_poke_loc *tp)
{
	const unsigned char int3 = INT3_INSN_OPCODE;
	temp_mm_state_t prev_mm;
	pte_t *ptep;
	int offset;
	struct bp_patching_desc desc = {
		.vec = tp,
		.nr_entries = 1,
		.native = true,
		.refs = ATOMIC_INIT(1),
	};

	__text_poke_map(text_poke_addr(tp), tp->native.len, &prev_mm, &ptep);

	offset = offset_in_page(text_poke_addr(tp));

	/*
	 * For INT3 use the same exclusion logic as BP emulation path.
	 */
	smp_store_release(&bp_desc, &desc); /* rcu_assign_pointer */

	/*
	 * All secondary CPUs are waiting in tps->state == PATCH_SYNC_DONE
	 * to move to PATCH_SYNC_0. Poke the INT3 and wait until all CPUs
	 * are known to have observed PATCH_SYNC_0.
	 *
	 * The earliest we can hit an INT3 is just after the first poke.
	 */
	poke_sync(tps, PATCH_SYNC_0, offset, &int3, INT3_INSN_SIZE);

	/*
	 * We have an INT3 in place; execute a contrived selftest that
	 * has an insn sequence that is under patching.
	 */
	pv_selftest_primary();

	/* Poke remaining */
	poke_sync(tps, PATCH_SYNC_1, offset + INT3_INSN_SIZE,
		  tp->text + INT3_INSN_SIZE, tp->native.len - INT3_INSN_SIZE);

	/*
	 * Replace the INT3 with the first opcode and force the serializing
	 * instruction for the last time. Any secondaries in the BP
	 * handler should be able to move past the INT3 handler after this.
	 * (See poke_int3_native() for details on this.)
	 */
	poke_sync(tps, PATCH_SYNC_2, offset, tp->text, INT3_INSN_SIZE);

	/*
	 * Force all CPUS to observe PATCH_SYNC_DONE (in the BP handler or
	 * in text_poke_site()), so they know that this iteration is done
	 * and it is safe to exit the wait-until-a-sync-is-required loop.
	 */
	poke_sync(tps, PATCH_SYNC_DONE, 0, NULL, 0);

	/*
	 * All CPUs have ack'd PATCH_SYNC_DONE. So there can be no
	 * laggard CPUs executing BP handlers. Reset bp_desc.
	 */
	WRITE_ONCE(bp_desc, NULL); /* RCU_INIT_POINTER */

	/*
	 * We've already done the synchronization so this should not
	 * race.
	 */
	if (!atomic_dec_and_test(&desc.refs))
		atomic_cond_read_acquire(&desc.refs, !VAL);

	/*
	 * Unmap the poking_addr, poking_mm.
	 */
	__text_poke_unmap(text_poke_addr(tp), tp->text, tp->native.len,
			  &prev_mm, ptep);
}

/**
 * text_poke_sync_site() -- called to synchronize the CPU pipeline
 * on secondary CPUs for each patch site.
 *
 * Called in thread context with tps->state == PATCH_SYNC_0 and in
 * BP context with tps->state < PATCH_SYNC_DONE.
 *
 * Returns after having observed tps->state == PATCH_SYNC_DONE.
 */
static void text_poke_sync_site(struct text_poke_state *tps)
{
	int cpu = smp_processor_id();
	int prevstate = -1;
	int acked;

	/*
	 * In thread context we arrive here expecting tps->state to move
	 * in-order from PATCH_SYNC_{0 -> 1 -> 2} -> PATCH_SYNC_DONE.
	 *
	 * We could also arrive here in BP-context some point after having
	 * observed bp_patching.nr_entries (and after poking the first INT3.)
	 * This could happen by way of an NMI while we are patching a site
	 * that'll get executed in the NMI handler, or if we hit a site
	 * being patched in text_poke_sync_site().
	 *
	 * Just as thread-context, the BP handler calls text_poke_sync_site()
	 * to keep the primary's state-machine moving forward until it has
	 * finished patching the call-site. At that point it is safe to
	 * unwind the contexts.
	 *
	 * The second case, where we are patching a site in
	 * text_poke_sync_site(), could end up in recursive BP handlers
	 * and is not handled.
	 *
	 * Note that unlike thread-context where the start state can only
	 * be PATCH_SYNC_0, in the BP-context, the start state could be any
	 * PATCH_SYNC_x, so long as (state < PATCH_SYNC_DONE) since once a
	 * CPU has acked PATCH_SYNC_2, there is no INT3 left for it to observe.
	 */
	do {
		/*
		 * Wait until there's some work for us to do.
		 */
		smp_cond_load_acquire(&tps->state,
				      prevstate != VAL);

		/*
		 * Send an NMI to one of the other CPUs.
		 */
		pv_selftest_send_nmi();

		/*
		 * We have an INT3 in place; execute a contrived selftest that
		 * has an insn sequence that is under patching.
		 *
		 * Note that this function is also called from BP fixup but
		 * is just an NOP when called from there.
		 */
		pv_selftest_secondary();
		prevstate = READ_ONCE(tps->state);

		/*
		 * As described above, text_poke_sync_site() gets called
		 * from both thread-context and potentially in a re-entrant
		 * fashion in BP-context. Accordingly expect to potentially
		 * enter and exit this loop twice.
		 *
		 * Concretely, this means we need to handle the case where we
		 * see an already acked state at BP/NMI entry and, see a
		 * state discontinuity when returning to thread-context from
		 * BP-context which would return after having observed
		 * tps->state == PATCH_SYNC_DONE.
		 *
		 * Help this along by always exiting with tps->state ==
		 * PATCH_SYNC_DONE but without acking it. Not acking it in
		 * text_poke_sync_site(), guarantees that the state can only
		 * forward once all secondary CPUs have exited both thread
		 * and BP-contexts.
		 */
		acked = cpumask_test_cpu(cpu, &tps->sync_ack_map);
		if (prevstate < PATCH_SYNC_DONE && !acked) {
			sync_one();
			cpumask_set_cpu(cpu, &tps->sync_ack_map);
		}
	} while (prevstate < PATCH_SYNC_DONE);
}

static void poke_int3_native(struct pt_regs *regs,
			     struct text_poke_loc *tp)
{
	int cpu = smp_processor_id();
	struct text_poke_state *tps = &text_poke_state;

	if (cpu != tps->primary_cpu) {
		/*
		 * We came here from the sync loop in text_poke_sync_site().
		 * Continue syncing. The primary is waiting.
		 */
		text_poke_sync_site(tps);
	} else {
		int offset = offset_in_page(text_poke_addr(tp));

		/*
		 * We are in the primary context and have hit the INT3 barrier
		 * either ourselves or via an NMI.
		 *
		 * The secondary CPUs at this time are either in the original
		 * text_poke_sync_site() loop or after having hit an NMI->INT3
		 * themselves in the BP text_poke_sync_site() loop.
		 *
		 * The minimum that we need to do here is to update the local
		 * insn stream such that we can return to the primary loop.
		 * Without executing sync_core() on the secondary CPUs it is
		 * possible that some of them might be executing stale uops in
		 * their respective pipelines.
		 *
		 * This should be safe because we will get back to the patching
		 * loop in text_poke_site() in due course and will resume
		 * the state-machine where we left off including by re-writing
		 * some of the insns sequences just written here.
		 *
		 * Note that we continue to be in poking_mm context and so can
		 * safely call __text_do_poke() here.
		 */
		__text_do_poke(offset + INT3_INSN_SIZE,
			       tp->text + INT3_INSN_SIZE,
			       tp->native.len - INT3_INSN_SIZE);
		__text_do_poke(offset, tp->text, INT3_INSN_SIZE);

		/*
		 * We only introduce a serializing instruction locally. As
		 * noted above, the secondary CPUs can stay where they are --
		 * potentially executing in the now stale INT3.) This is fine
		 * because the primary will force the sync_core() on the
		 * secondary CPUs once it returns.
		 */
		sync_one();
	}

	/* A new start */
	regs->ip -= INT3_INSN_SIZE;
}

/**
 * text_poke_sync_finish() -- called to synchronize the CPU pipeline
 * on secondary CPUs for all patch sites.
 *
 * Called in thread context with tps->state == PATCH_SYNC_DONE.
 * Also might be called from NMI context with an arbitrary tps->state.
 * Returns with tps->state == PATCH_DONE.
 */
static void text_poke_sync_finish(struct text_poke_state *tps)
{
	while (true) {
		enum patch_state state;
		int cpu = smp_processor_id();

		state = READ_ONCE(tps->state);

		/*
		 * We aren't doing any actual poking yet, so we don't
		 * handle any other states.
		 */
		if (state == PATCH_DONE)
			break;

		if (state == PATCH_SYNC_DONE) {
			/*
			 * Ack that we've seen the end of this iteration
			 * and then wait until everybody's ready to move
			 * to the next iteration or exit.
			 */
			cpumask_set_cpu(cpu, &tps->sync_ack_map);
			smp_cond_load_acquire(&tps->state,
					      (state != VAL));
		} else if (in_nmi() && (state & PATCH_SYNC_x)) {
			/*
			 * Called in case of NMI so we should be ready
			 * to be called with any PATCH_SYNC_x.
			 */
			text_poke_sync_site(tps);
		} else if (state == PATCH_SYNC_0) {
			/*
			 * PATCH_SYNC_1, PATCH_SYNC_2 are handled
			 * inside text_poke_sync_site().
			 */
			text_poke_sync_site(tps);
		} else {
			BUG();
		}
	}
}

/*
 * text_poke_nmi() - primary CPU comes here (via self NMI) and the
 * secondary (if there's an NMI.)
 *
 * By placing this NMI handler first, we can restrict execution of any
 * NMI code that might be under patching.
 * Local NMI handling also does not go through any locking code so it
 * should be safe to install one.
 *
 * In both these roles the state-machine is identical to the one that
 * we had in task context.
 */
static int text_poke_nmi(unsigned int val, struct pt_regs *regs)
{
	int ret, cpu = smp_processor_id();
	struct text_poke_state *tps = &text_poke_state;

	/*
	 * We came here because there's a text-poke handler
	 * installed. Get out if there's no work assigned yet.
	 */
	if (atomic_read(&tps->nmi_work) == 0)
		return NMI_DONE;

	if (cpu == tps->primary_cpu) {
		/*
		 * Do what we came here for. We can safely patch: any
		 * secondary CPUs executing in NMI context have been
		 * captured in the code below and are doing useful
		 * work.
		 */
		tps->patch_worker(tps);

		/*
		 * Both the primary and the secondary CPUs are done (in NMI
		 * or thread context.) Mark work done so any future NMIs can
		 * skip this and go to the real handler.
		 */
		atomic_dec(&tps->nmi_work);

		/*
		 * The NMI was self-induced, consume it.
		 */
		ret = NMI_HANDLED;
	} else {
		/*
		 * Unexpected NMI on a secondary CPU: do sync_core()
		 * work until done.
		 */
		text_poke_sync_finish(tps);

		/*
		 * The NMI was spontaneous, not self-induced.
		 * Don't consume it.
		 */
		ret = NMI_DONE;
	}

	return ret;
}

/*
 * patch_worker_nmi() - sets up an NMI handler to do the
 * patching work.
 * This stops any NMIs from interrupting any code that might
 * be getting patched.
 */
static void __maybe_unused patch_worker_nmi(void)
{
	atomic_set(&text_poke_state.nmi_work, 1);
	/*
	 * We could just use apic->send_IPI_self here. However, for reasons
	 * that I don't understand, apic->send_IPI() or apic->send_IPI_mask()
	 * work but apic->send_IPI_self (which internally does apic_write())
	 * does not.
	 */
	apic->send_IPI(smp_processor_id(), NMI_VECTOR);

	/*
	 * Barrier to ensure that we do actually execute the NMI
	 * before exiting.
	 */
	atomic_cond_read_acquire(&text_poke_state.nmi_work, !VAL);
}

static int patch_worker(void *t)
{
	int cpu = smp_processor_id();
	struct text_poke_state *tps = t;

	if (cpu == tps->primary_cpu) {
		/*
		 * The init state is PATCH_SYNC_DONE. Wait until the
		 * secondaries have assembled before we start patching.
		 */
		wait_for_acks(tps);

		/*
		 * Generates insns and calls text_poke_site() to do the poking
		 * and sync.
		 */
		if (!tps->nmi_context)
			tps->patch_worker(tps);
		else
			patch_worker_nmi();

		/*
		 * We are done patching. Switch the state to PATCH_DONE
		 * so the secondaries can exit.
		 */
		smp_store_release(&tps->state, PATCH_DONE);
	} else {
		/* Secondary CPUs spin in a sync_core() state-machine. */
		text_poke_sync_finish(tps);
	}
	return 0;
}

/**
 * text_poke_late() -- late patching via stop_machine().
 *
 * Called holding the text_mutex.
 *
 * Return: 0 on success, -errno on failure.
 */
static int __maybe_unused text_poke_late(patch_worker_t worker, void *stage,
					 bool nmi)
{
	int ret;

	lockdep_assert_held(&text_mutex);

	if (system_state != SYSTEM_RUNNING)
		return -EINVAL;

	text_poke_state.stage = stage;
	text_poke_state.num_acks = cpumask_weight(cpu_online_mask);
	text_poke_state.head = &alt_modules;

	text_poke_state.patch_worker = worker;
	text_poke_state.state = PATCH_SYNC_DONE; /* Start state */
	text_poke_state.primary_cpu = smp_processor_id();

	text_poke_state.nmi_context = nmi;

	if (nmi)
		register_nmi_handler(NMI_LOCAL, text_poke_nmi,
				     NMI_FLAG_FIRST, "text_poke_nmi");
	/*
	 * Run the worker on all online CPUs. Don't need to do anything
	 * for offline CPUs as they come back online with a clean cache.
	 */
	ret = stop_machine(patch_worker, &text_poke_state, cpu_online_mask);

	if (nmi)
		unregister_nmi_handler(NMI_LOCAL, "text_poke_nmi");

	return ret;
}

/*
 * Check if this address is still in scope of this module's .text section.
 */
static bool __maybe_unused stale_address(struct alt_module *am, u8 *p)
{
	if (p < am->text || p >= am->text_end)
		return true;
	return false;
}

#ifdef CONFIG_PARAVIRT_RUNTIME
struct paravirt_stage_entry {
	void *dest;	/* pv_op destination */
	u8 type;	/* pv_op type */
};

/*
 * We don't anticipate many pv-ops being written at runtime.
 */
#define PARAVIRT_STAGE_MAX 8
struct paravirt_stage {
	struct paravirt_stage_entry ops[PARAVIRT_STAGE_MAX];
	u32 count;
};

/* Protected by text_mutex */
static struct paravirt_stage pv_stage;

/**
 * text_poke_pv_stage - Stage paravirt-op for poking.
 * @addr: address in struct paravirt_patch_template
 * @type: pv-op type
 * @opfn: destination of the pv-op
 *
 * Return: staging status.
 */
bool text_poke_pv_stage(u8 type, void *opfn)
{
	if (system_state == SYSTEM_BOOTING) { /* Passthrough */
		PARAVIRT_PATCH_OP(pv_ops, type) = (long)opfn;
		goto out;
	}

	lockdep_assert_held(&text_mutex);

	if (PARAVIRT_PATCH_OP(pv_ops, type) == (long)opfn)
		goto out;

	if (pv_stage.count >= PARAVIRT_STAGE_MAX)
		goto out;

	pv_stage.ops[pv_stage.count].type = type;
	pv_stage.ops[pv_stage.count].dest = opfn;

	pv_stage.count++;

	return true;
out:
	return false;
}

void text_poke_pv_stage_zero(void)
{
	lockdep_assert_held(&text_mutex);
	pv_stage.count = 0;
}

/**
 * generate_paravirt - fill up the insn sequence for a pv-op.
 *
 * @tp - address of struct text_poke_loc
 * @op - the pv-op entry for this location
 * @site - patch site (kernel or module text)
 */
static void generate_paravirt(struct text_poke_loc *tp,
			      struct paravirt_stage_entry *op,
			      struct paravirt_patch_site *site)
{
	unsigned int used;

	BUG_ON(site->len > POKE_MAX_OPCODE_SIZE);

	text_poke_loc_init(tp, site->instr, site->instr, site->len, NULL, true);

	/*
	 * Paravirt patches can patch calls (ex. mmu.tlb_flush),
	 * callee_saves(ex. queued_spin_unlock).
	 *
	 * runtime_patch() calls native_patch(), or paravirt_patch()
	 * based on the destination.
	 */
	used = runtime_patch(site->type, (void *)tp->text, op->dest,
			     (unsigned long)site->instr, site->len);

	/* No good way to recover. */
	BUG_ON(used < 0);

	/* Pad the rest with nops */
	add_nops((void *)tp->text + used, site->len - used);
}

/**
 * paravirt_worker - generate the paravirt patching
 * insns and calls text_poke_site() to do the actual patching.
 */
static void paravirt_worker(struct text_poke_state *tps)
{
	struct paravirt_patch_site *site;
	struct paravirt_stage *stage = tps->stage;
	struct paravirt_stage_entry *op = &stage->ops[0];
	struct alt_module *am;
	struct text_poke_loc tp;
	int i;

	list_for_each_entry(am, tps->head, next) {
		for (site = am->para; site < am->para_end; site++) {
			if (stale_address(am, site->instr))
				continue;

			for (i = 0;  i < stage->count; i++) {
				if (op[i].type != site->type)
					continue;

				generate_paravirt(&tp, &op[i], site);

				text_poke_site(tps, &tp);
			}
		}
	}
}

/**
 * paravirt_runtime_patch() -- patch pv-ops, including paired ops.
 *
 * Called holding the text_mutex.
 *
 * Modify possibly multiple mutually-dependent pv-op callsites
 * (ex. pv_lock_ops) using stop_machine().
 *
 * Return: 0 on success, -errno on failure.
 */
int paravirt_runtime_patch(bool nmi)
{
	lockdep_assert_held(&text_mutex);

	if (!pv_stage.count)
		return -EINVAL;

	return text_poke_late(paravirt_worker, &pv_stage, nmi);
}
#endif /* CONFIG_PARAVIRT_RUNTIME */
