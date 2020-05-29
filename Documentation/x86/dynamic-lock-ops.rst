================
Dynamic lock-ops
================


Background
===========

The spinlocks used in prior versions of Linux kernel were either a FIFO
ticketlock or byte-locking. Starting with Linux 4.11 the queue-based spinlock
replaced this. The qspinlock is a modified version of the MCS spinlock:
Non-Blocking Algorithms and Preemption-Safe Lockingon Multiprogrammed Shared
Memory Multiprocessors.

The native path uses these primtivies::

	.lock.queued_spin_lock_slowpath = native_queued_spin_lock_slowpath,
	.lock.queued_spin_unlock        = PV_CALLEE_SAVE(__native_queued_spin_unlock),
	.lock.wait                      = paravirt_nop,
	.lock.kick                      = paravirt_nop,
	.lock.vcpu_is_preempted         = PV_CALLEE_SAVE(__native_vcpu_is_preempted),

And, the paravirt path on KVM::

  	void __init kvm_spinlock_init(void)
  	{
  	    /* Does host kernel support KVM_FEATURE_PV_UNHALT? */
  	    if (!kvm_para_has_feature(KVM_FEATURE_PV_UNHALT))
  	            return;

  	    if (kvm_para_has_hint(KVM_HINTS_REALTIME))
  	            return;

  	    /* Don't use the pvqspinlock code if there is only 1 vCPU. */
  	    if (num_possible_cpus() == 1)
  	            return;

  	    __pv_init_lock_hash();
  	    pv_ops.lock.queued_spin_lock_slowpath = __pv_queued_spin_lock_slowpath;
  	    pv_ops.lock.queued_spin_unlock =
  	            PV_CALLEE_SAVE(__pv_queued_spin_unlock);
  	    pv_ops.lock.wait = kvm_wait;
  	    pv_ops.lock.kick = kvm_kick_cpu;

  	    if (kvm_para_has_feature(KVM_FEATURE_STEAL_TIME)) {
  	            pv_ops.lock.vcpu_is_preempted =
  	                    PV_CALLEE_SAVE(__kvm_vcpu_is_preempted);
  	    }
  	}


The code-gen for both `native_queued_spin_lock_slowpath()` and
`__pv_queued_spin_lock_slowpath()` is in `queued_spin_lock_slowpath()`
which gets compiled twice variously selecting either paravirt waiting, kicking ops
to be NOP or using the underlying primitives.

`native_queued_spin_lock_slowpath()`::

    /*
    * Generate the native code for queued_spin_unlock_slowpath(); provide NOPs for
    * all the PV callbacks.
    */

    static __always_inline void __pv_init_node(struct mcs_spinlock *node) { }
    static __always_inline void __pv_wait_node(struct mcs_spinlock *node,
                                              struct mcs_spinlock *prev) { }
    static __always_inline void __pv_kick_node(struct qspinlock *lock,
                                              struct mcs_spinlock *node) { }
    static __always_inline u32  __pv_wait_head_or_lock(struct qspinlock *lock,
                                                      struct mcs_spinlock *node)
                                                      { return 0; }

    #define pv_enabled()            false

    #define pv_init_node            __pv_init_node
    #define pv_wait_node            __pv_wait_node
    #define pv_kick_node            __pv_kick_node
    #define pv_wait_head_or_lock    __pv_wait_head_or_lock


`__pv_queued_spin_lock_slowpath()` ends up using with calls to `__pv_{init,wait,kick}_node()`::

    /*
    * Generate the paravirt code for queued_spin_unlock_slowpath().
    */
    #if !defined(_GEN_PV_LOCK_SLOWPATH) && defined(CONFIG_PARAVIRT_SPINLOCKS)
    #define _GEN_PV_LOCK_SLOWPATH

    #undef  pv_enabled
    #define pv_enabled()    true

    #undef pv_init_node
    #undef pv_wait_node
    #undef pv_kick_node
    #undef pv_wait_head_or_lock


The generated `_raw_spin_lock()` is a `lock; cmpxchg` and if that is contended, an
indirect call to `lock.queued_spin_lock_slowpath()`::

      ffffffff81a6a240 <_raw_spin_lock>:
      ffffffff81a6a240:   e8 fb 55 60 ff      callq  ffffffff8106f840 <__fentry__>
                          ffffffff81a6a241: R_X86_64_PLT32        __fentry__-0x4
      ffffffff81a6a245:   31 c0               xor    %eax,%eax
      ffffffff81a6a247:   ba 01 00 00 00      mov    $0x1,%edx
      ffffffff81a6a24c:   f0 0f b1 17         lock cmpxchg %edx,(%rdi)
      ffffffff81a6a250:   75 01               jne    ffffffff81a6a253 <_raw_spin_lock+0x1
      ffffffff81a6a252:   c3                  retq
      ffffffff81a6a253:   55                  push   %rbp
      ffffffff81a6a254:   89 c6               mov    %eax,%esi
      ffffffff81a6a256:   48 89 e5            mov    %rsp,%rbp
      ffffffff81a6a259:   ff 14 25 a8 52 64 82  callq  *0xffffffff826452a8
                          ffffffff81a6a25c: R_X86_64_32S  pv_ops+0x2a8
      ffffffff81a6a260:   5d                   pop    %rbp
      ffffffff81a6a261:   c3                   retq
      ffffffff81a6a262:   66 66 2e 0f 1f 84 00 data16 nopw %cs:0x0(%rax,%rax,1)
      ffffffff81a6a269:   00 00 00 00
      ffffffff81a6a26d:   0f 1f 00             nopl   (%rax)

This stays as an indirect call until the patching happens (the field
`lock.queued_spin_lock_slowpath`) starts as `native_queued_spin_lock_slowpath()`
and might get changed to the `__pv_queued_spin_lock_slowpath()` if the KVM
guest supports paravirt spinlocks.

The patching would essentially end up pointing to either of these::

    $ nm --defined vmlinux | grep _queued_spin_lock_slowpath | grep T
    ffffffff810fb250 T native_queued_spin_lock_slowpath
    ffffffff810fb4c0 T __pv_queued_spin_lock_slowpath


structure mcs_spinlock and struct qnode
----------------------------------------

Both `native_queued_spin_lock_slowpath()` and `__pv_queued_spin_lock_slowpath()`
utilize `struct mcs_spinlock` to keep track of taken spinlocks and have per-CPU
areas to spin on::

   /*
    * Per-CPU queue node structures; we can never have more than 4 nested
    * contexts: task, softirq, hardirq, nmi.
    *
    * Exactly fits one 64-byte cacheline on a 64-bit architecture.
    *
    * PV doubles the storage and uses the second cacheline for PV state.
    */
    static DEFINE_PER_CPU_ALIGNED(struct qnode, qnodes[MAX_NODES]);

The MAX_NODES allows tracking of four different nested spinlock slowpaths -- say
one at the task level, then an softirq, followed by a hardirq and then an nmi.
Notice that We can only have a single ongoing slowpath at each level.

The `struct qnode` is used in `native_queued_spin_lock_slowpath()` and
`__pv_queued_spin_lock_slowpath()` when we fallback to MCS queueing on
contention.

INT3 based patching
--------------------

The Linux kernel uses INT3 based patching infrastructure. We'll be using that as
well. For patching any code location the steps are:

 #. prefix int3 trap to the address that will be patched
 #. sync cores
 #. update remaining bytes with target bytes
 #. sync cores
 #. replace the first byte (int3) by the first byte of replacing opcode
 #. sync cores

The writes are done via a separate data page which maps to the PA for the code
location (earlier code used a fixmap, now we just use a separate mm.) The
CPU's cache coherence protocol ensures that the caches are synchronized.

Why do we need the sync_core?: processor pipelines cache decoded uops. With code updates,
the caches are now up-to-date but the cached uops might now be stale (ex. a
`spin_lock()`, `spin_unlock()` tight loop.) On UP, a control flow change is enough
to flush these out. On SMP (on a cross-modification scenario), the patching CPU
needs to introduce a serializing instruction (ex. `iret`, `cpuid` etc) on all remote
processors to ensure that the pipeline discards the cached uops. Notice that
this generally needs an IPI which could execute the code under patching itself.

Why INT3?: The INT3 patching approach was sanctioned here:
http://lkml.iu.edu/hypermail/linux/kernel/1001.1/01530.html. INT3 is useful in
allowing code to be executed while it is being patched (the BP handler emulates
the code sequence at this location by doing a call, jmp, nop etc. The other nice
thing about INT3 is that it comes in a single byte variant: 0xcc which can be
written atomically (cannot straddle cachelines for instance.)


Proposal for v2
================

The complexity in patching spinlocks is that they get used all over the place and
all the time. In addition there's inter-dependence between the lock operations (ex.
`lock.queued_lock_slowpath`, `lock.queued_lock_unlock` are paired and so
need to be updated atomically.)
In addition, these operations can be called via interrupts which complicates using
IPIs for flushing. This also means that we cannot do binary patching while holding
a spinlock (since then the locking operation and the unlocking operation would not
be both PV or both native type.)

The problems in patching boil down to:

   * Other CPUs are executing arbitrary code
   * Patching a single site itself involves multiple steps and can be
     interrupted by NMIs.
   * We are patching multiple sites (ex. `queued_spin_lock_slowpath()`, `queued_spin_unlock()`)
     which need to be drawn from a common set of locking primitives (native OR
     paravirt). In particular, there can be no ongoing spinlocks with native
     or paravirt `lock_ops` straddling across patching.

High level solution: to handle the arbitrary code under execution on other CPUs,
we need a site-local barrier, for which we use INT3 (which is what
`text_poke_bp()` uses.) With this barrier, we can now decide what gets executed
at each call-site.

With the execution under control, next we need a barrier which decides what
phase of patching we are in. Based on the state of this barrier, we execute
either the before or after op from pv_lock_ops.

Once both of these are in place, the rest of patching should be mostly formulaic.

Step 1: prefix INT3
---------------------

Prefix all `pv_lock_op` sites with an INT3. This acts as a barrier: any
execution of a `pv_lock_op` ends up in the BP handler where we can choose which
variant to use. Important to note that the lock operation itself is not a `pv_lock_op`.

The CPU time graph below gives an example of how this might go::

  CPU0: ......la.......x..lb........iub..iua...ika..........  # kick CPU1
                                                  \
  CPU1: ...............x.....la....isa....iwa     isa....iua  # wait for lock-a
  CPU2: ..................................ld....ud......x...
  CPU3: .for_each()
              write_INT3_prefix()...                   ..x..
  CPU3-NMI:                         \....lc.....iuc.../

Notation for time graphs:

 * Prefixes `l, s, u, w, k`: refer to the `lock; cmpxchg` for the `l` prefix and the rest to:
   `.queued_spin_lock_slowpath()`, `.queued_spin_unlock()`, `.wait()`, `.kick()` and `.vcpu_is_preempted()`.
 * Prefix `S, U, W, K`: refer to the post `pv_lock_ops`. Note that there of course no corresponding `L` prefix.
 * Suffix `a, b, c, d` : is the specific lock being operated upon.
 * `x` : signifies that all relevant INT3 prefixes for ops on that CPU's time-graph
   have been written. Note that this is only meant for clarity purposes –- there is
   no actual way of grouping together related call-sites.
 * Prefix `i` :  signifies execution by way of the INT3 handler.
 * `|` : signifies barrier (introduced in the next step)


This time graph shows a nested, uncontended locking scenario on CPU0; CPU1 tries
to acquire one of the locks that CPU0 holds and takes the slowpath; CPU2,
acquires an uncontended lock; CPU3, does the patching and gets an NMI in the
middle of it.

Two things to note: while the INT3 prefix writing is going on, some call-sites
will go through the BP handler (prefix i), and once the INT3 prefixes are
written, we send an IPI to execute sync_core() everywhere. That would acquire a
spinlock as well and is not shown here.

Emulation
~~~~~~~~~~~~~

The INT3 prefixes result in traps to the BP handler. This would end up in us
emulating calls to the underlying `pv_lock_op` – based on when the emulation is
happening, pre or post. This is described further in the Section on emulation.

Handling NMIs and interrupts is also straight-forward (and simpler compared to
V1) – these trap into the INT3 handler just as from thread context.

Step 2: Barrier
------------------

At this point all the prefixes are written, and the system is executing with
the emulated pre `pv_lock_op` variants which need to be switched over to the post
variants. The first order of business is to actually start with a clean
slate where we know that no `pv_lock_ops` are executing.

We execute a barrier on all CPUs like so::

    atomic_t barrier_cpus, lock_refcount;

    DEFINE_PER_CPU(int, paravirt_switch_barrier);

    void patch_barrier(void) {
        this_cpu_write(paravirt_switch_barrier, 1);
        atomic_inc(&barrier_cpus);
          /* Count lock_refcount if this_cpu_read(paravirt_switch_barrier). */
    }

This can be called in a thread context where we are guaranteed that no spinlocks
are being held on *that* CPU.

Timegraph for this step with the `|` representing a barrier::


    CPU0: ..........lb...iub..|......lc.........iUc..............
    CPU1: ................|....ld.......iSd...iWd   iSd....iUd...
                                               /
    CPU2: .....ld........................iud..ikd........|.......  # kick lock-d
    CPU3: ...patch_barrier().......|.............................


Here CPU0, switches to the post primitive for lock c; CPU1 is in the slowpath
for lock d and has switched to the post primitive; CPU2, however, is in lock
d, and is still using the before primitives; CPU3, is the patching CPU and just
executed the `patch_barrier()`.

Notice that though CPU1 and CPU2 are connected via spinlock d, they are using
different locking primitives. This is incorrect and implies that we need
something stronger than a local barrier.

The obvious solution seems to be tracking on a per-lock basis: if CPU1, while
acquiring lock d, can figure out if the lock is in use with before or after
primitives, it would allow us to transition on a per-lock basis (viz. lock c
doesn't have any ongoing users, so emulate the after primitive for any future
users; lock d does, so emulate the before primitives.) This information is
present in the spinlock state but would need the patching code to be far too
friendly with the spinlock internals. Even given that, it seems like a
distributed consensus problem which'll turn out to be a mess with multiple
locking contexts (thread, softirq, irq, NMI) coupled with potentially nested
locks.

A simpler solution might be having a global refcount (say, in atomic_t
lock_refcount) which does not tell us about the state of any particular lock but
can tell us about the state of all the locks. With this, we can count spinlock
operations and do the switch after this count has gone to zero (there are
possible issues with starvation, discussed later.)

(Given that there might be ongoing spinlock operations, only CPUs which have
executed their callback (and can thus start counting from a blank slate) do
the counting.)

The condition that guarantees that there are no spinlocks executing in the system::

  atomic_read(&barrier_cpus) == num_online_cpus &&
      atomic_read(&lock_refcount) == 0;

This property should hold for any spinlock nesting in threads, IRQs, NMIs and
softirqs. The natural place for evaluating this is in the BP handler at lock
slowpath entry and once it holds, we can start emulating the after `pv_lock_op`.

Spinlock refcounting
~~~~~~~~~~~~~~~~~~~~~~~~

To start with we decouple two phases of a lock's lifetime:

 * fastpath: `queued_spin_lock()` ... `.queued_spin_unlock()`
 * slowpath: `.queued_spin_lock_slowpath()` ... `.queued_spin_unlock()` (these
   also call `.wait()`, `.kick()`, `.vcpu_is_preempted()`.)

As mentioned earlier: in the fastpath `queued_spin_lock()` is not a `pv_lock_op` so
any calls to it cannot be tracked via BP patching. However, given that it has a
common implementation (which is just a bitlock), we can get away without needing
to track the fastpath lifetime::

  #define _Q_LOCKED_OFFSET        0
  #define _Q_LOCKED_VAL           (1U << _Q_LOCKED_OFFSET)

  static __always_inline void queued_spin_lock(struct qspinlock *lock)
  {
      u32 val = 0;
      if (likely(atomic_try_cmpxchg_acquire(&lock->val, &val, _Q_LOCKED_VAL)))
              return;
      queued_spin_lock_slowpath(lock, val);
  }

The slowpath, of course touches spinlock implementation dependent state that
needs to stick around until all the `.queued_spin_unlock()` ops for a particular
lock have been called. Even on the fastpath, `.queued_spin_unlock()` can access
spinlock state (for calling `.kick()` on other CPUs waiting in slowpath on the
same lock.)

Once a CPU has executed its barrier and is thus start counting from a blank slate,
it needs to count two things as part of it's BP handling:

 * References to spinlock internal state: lifetime of a reference starts at
   entry to `.queued_spin_lock_slowpath()` and ends at `.queued_spin_unlock()`
   exit.
 * BP trampoline count: the BP handler constructs a trampoline to call the
   destination op. This count is held only while the `pv_lock_op` call itself is ongoing.
   Note that all slowpath accesses are already protected by the state reference
   above, so this count calls might be unnecessary. The only case where we might
   need this count is for unprotected calls: out of line calls to `.vcpu_is_preempted()`
   and the fastpath call in `.queued_spin_unlock()` (which can call `.kick()`).

With this, we can amend our earlier description of when this condition holds:
when there are no spinlock *slowpaths* executing in the system.

Given that there is no spinlock implementation dependent state in the fastpath,
it is safe to switch to the after `pv_lock_ops` even when a `queued_spin_lock()` has
been called, but without the `.queued_spin_unlock()` having been called. Notice
that the `.queued_spin_unlock()` call might dereference spinlock state but *only if*
another CPU is in the slowpath in which case `atomic_read(&lock_refcount)` would
be non-zero.

Fastpath vs slowpath: The only problem now remains is differentiating between
the two in the call to `.queued_spin_unlock()`. This is necessary because if the
acquisition was via `queued_spin_lock()`, then we need to only drop the trampoline
count. However, if the acquisition was via `.queued_spin_lock_slowpath()` then we
need to drop the spinlock state count as well.

As an example, here we have an atrociously long chain of nested locks (as before
the lock name is in the subscript and `l`, `s` and `u` correspond to
`queued_spin_lock()`, `.queued_spin_lock_slowpath()`, and `.queued_spin_unlock()`).
The other ops are simpler cases of the `s` case so are not listed here::

  CPUx: la...                                                             ...ua

  CPUx:      lb...sb...                                               ...ub

  CPUx:                lc...sc...                                ...uc

  CPUx-IRQ:                      ld...                      ...ud

  CPUx-NMI:                           le...            ...ue

  CPUx-NMI:                                lf...sf...uf


The BP handling code obviously sees independent operations and not a stream. At
lock exit (`.queued_spin_unlock()`), it needs to know if the exit was for a lock
acquired via slowpath or the fastpath (and accordingly drop the refcount by 2 or
by 1.) Additionally, we only see the lock entry (via `.queued_spin_lock_slowpath()`)
for locks `b`, `c` and `f`.

To do this, we use the fact that when a lock is active, it is associated with a unique
preempt count. This can be mapped to the execution of `.queued_spin_lock_slowpath()`
at entry and and mapped back at exit while handling `.queued_spin_unlock()`.


Emulation
~~~~~~~~~~~~~

The discussion above elides how we do the emulation in the BP handling.
Essentially the BP handler adds a gap on the stack where it creates a trampoline
and emulates the call via a JMP::

      1   /* int3_emulate_push(regs, val) */
      2     regs->sp -= sizeof(unsigned long);
      3     *(unsigned long *)regs->sp = val;
      4
      5   /* int3_emulate_jmp(regs, func) */
      6     regs->ip = func;
      7
      8   /* int3_emulate_call(regs, val) */
      9     int3_emulate_push(regs, regs->ip - INT3_INSN_SIZE + CALL_INSN_SIZE);
      10
      11  /* emulate CALL_INSN_OPCODE: */
      12    int3_emulate_call(regs, (long)ip + tp->rel32);

Now ordinarily, the emulate would just emulate a call to our destination op.
However, we need to call the destination op and additionally do refcnt handling
(ex. drop refcounts at return from `.queued_spin_unlock()`.) This will likely need
calling a helper or possibly a hand encoded trampoline for each `pv_lock_op`.

For the mechanism the `CALL_INSN_OPCODE` (line 11 above) which emulates via JMP
should suffice.

Starvation
------------

Spinlocks aren't exactly uncommon in the kernel and so on a system under high
kernel load -– and with a large number of CPUs, it is possible that we might wait
a long time before the safety condition holds. That would be bad since
emulation+tracking isn't a cheap operation (ex. lots of cacheline pingpoing on
`lock_refcount`.) There are two complementary ways around this:

 * Use the fact that the entry to the slowpath is gated by the BP handler code:
   if the `lock_refcount` is small, optimistically wait before calling
   `.queued_spin_lock_slowpath()` to see if the lock_refcount drops to 0. If it
   does, transition to the after state.

 * Document that spinlock switching can fail and recommend that it be done on a
   lightly loaded system (though we only care about high systime, not high
   usertime). To guard against spikes or user error, make this a cancellable
   operation where if called under high load or after a fixed wait time, we
   fail, undo Step 1 and return `-EAGAIN`.


Step 3: finish the patching
----------------------------

Write the suffix and then replace the INT3 (0xCC) with the correct opcode (or
the old opcode in case of failure). Nothing really novel in this step.
