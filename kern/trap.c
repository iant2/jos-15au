#include <inc/mmu.h>
#include <inc/x86.h>
#include <inc/assert.h>

#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/env.h>
#include <kern/syscall.h>

static struct Taskstate ts;

/* For debugging, so print_trapframe can distinguish between printing
 * a saved trapframe and printing the current trapframe and print some
 * additional information in the latter case.
 */
static struct Trapframe *last_tf;

/* Interrupt descriptor table.  (Must be built at run time because
 * shifted function addresses can't be represented in relocation records.)
 */
struct Gatedesc idt[256] = { { 0 } };
struct Pseudodesc idt_pd = {
	sizeof(idt) - 1, (uint32_t) idt
};


static const char *trapname(int trapno)
{
	static const char * const excnames[] = {
		"Divide error",
		"Debug",
		"Non-Maskable Interrupt",
		"Breakpoint",
		"Overflow",
		"BOUND Range Exceeded",
		"Invalid Opcode",
		"Device Not Available",
		"Double Fault",
		"Coprocessor Segment Overrun",
		"Invalid TSS",
		"Segment Not Present",
		"Stack Fault",
		"General Protection",
		"Page Fault",
		"(unknown trap)",
		"x87 FPU Floating-Point Error",
		"Alignment Check",
		"Machine-Check",
		"SIMD Floating-Point Exception"
	};

	if (trapno < ARRAY_SIZE(excnames))
		return excnames[trapno];
	if (trapno == T_SYSCALL)
		return "System call";
	return "(unknown trap)";
}

/*
Gate descriptors for interrupts and traps
struct Gatedesc {
	unsigned gd_off_15_0 : 16;   // low 16 bits of offset in segment
	unsigned gd_sel : 16;        // segment selector
	unsigned gd_args : 5;        // # args, 0 for interrupt/trap gates
	unsigned gd_rsv1 : 3;        // reserved(should be zero I guess)
	unsigned gd_type : 4;        // type(STS_{TG,IG32,TG32})
	unsigned gd_s : 1;           // must be 0 (system)
	unsigned gd_dpl : 2;         // descriptor(meaning new) privilege level
	unsigned gd_p : 1;           // Present
	unsigned gd_off_31_16 : 16;  // high bits of offset in segment
};
*/

void
trap_init(void)
{
	extern struct Segdesc gdt[];

	extern void trapHandlerEntry0();
	extern void trapHandlerEntry1();
	extern void trapHandlerEntry2();
	extern void trapHandlerEntry3();
	extern void trapHandlerEntry4();
	extern void trapHandlerEntry5();
	extern void trapHandlerEntry6();
	extern void trapHandlerEntry7();
	extern void trapHandlerEntry8();
	extern void trapHandlerEntry10();
	extern void trapHandlerEntry11();
	extern void trapHandlerEntry12();
	extern void trapHandlerEntry13();
	extern void trapHandlerEntry14();
	extern void trapHandlerEntry16();
	extern void trapHandlerEntry17();
	extern void trapHandlerEntry18();
	extern void trapHandlerEntry19();
	extern void trapHandlerEntry20();
	extern void trapHandlerEntry21();
	extern void trapHandlerEntry22();
	extern void trapHandlerEntry23();
	extern void trapHandlerEntry24();
	extern void trapHandlerEntry25();
	extern void trapHandlerEntry26();
	extern void trapHandlerEntry27();
	extern void trapHandlerEntry28();
	extern void trapHandlerEntry29();
	extern void trapHandlerEntry30();
	extern void trapHandlerEntry31();
	// #define SETGATE(gate, istrap, sel, off, dpl)
	// Set up a normal interrupt/trap gate descriptor.
	// - istrap: 1 for a trap (= exception) gate
	//			 0 for an interrupt gate.

	    //   see section 9.6.1.3 of the i386 reference: "The difference between
	    //   an interrupt gate and a trap gate is in the effect on IF (the
	    //   interrupt-enable flag). An interrupt that vectors through an
	    //   interrupt gate resets IF, thereby preventing other interrupts from
	    //   interfering with the current interrupt trapHandlerEntry. A subsequent IRET
	    //   instruction restores IF to the value in the EFLAGS image on the
	    //   stack. An interrupt through a trap gate does not change IF."

	// - sel: Code segment selector for interrupt/trap trapHandlerEntry
	// - off: Offset in code segment for interrupt/trap trapHandlerEntry
	// - dpl: Descriptor Privilege Level -
	//	  the privilege level required for software to invoke
	//	  this interrupt/trap gate explicitly using an int instruction.
	//		HIGHEST    Faults except debug faults
	//		Trap instructions INTO, INT n, INT 3
	//		Debug traps for this instruction
	//		Debug faults for next instruction
	//		NMI interrupt
	//		LOWEST     INTR interrupt

	// LAB 3: Your code here.
	// 9.8.1 Interrupt 0 -- Divide Error
	SETGATE(idt[0], 0, 0x8, trapHandlerEntry0, 0);
	// 9.8.2 Interrupt 1 -- Debug Exceptions
    SETGATE(idt[1], 0, 0x8, trapHandlerEntry1, 0);
    // non maskable interupt 
    SETGATE(idt[2], 0, 0x8, trapHandlerEntry2, 0);
    //9.8.3 Interrupt 3 -- Breakpoint
    SETGATE(idt[3], 0, 0x8, trapHandlerEntry3, 3); // dpl = 3 becuase user can invoke a debug exception
    										  // therefore the cpl can be set to 3
    // 9.8.4 Interrupt 4 -- Overflow
    SETGATE(idt[4], 0, 0x8, trapHandlerEntry4, 0);
    // 9.8.5 Interrupt 5 -- Bounds Check
    SETGATE(idt[5], 0, 0x8, trapHandlerEntry5, 0);
    // 9.8.6 Interrupt 6 -- Invalid Opcode
    SETGATE(idt[6], 0, 0x8, trapHandlerEntry6, 0);
    // 9.8.7 Interrupt 7 -- Coprocessor Not Available
    SETGATE(idt[7], 0, 0x8, trapHandlerEntry7, 0);
    // 9.8.8 Interrupt 8 -- Double Fault
    SETGATE(idt[8], 0, 0x8, trapHandlerEntry8, 0);

    //9.8.9 Interrupt 9 -- Coprocessor Segment Overrun

    //9.8.10 Interrupt 10 -- Invalid TSS
    SETGATE(idt[10], 0, 0x8, trapHandlerEntry10, 0);
    //9.8.11 Interrupt 11 -- Segment Not Present
    SETGATE(idt[11], 0, 0x8, trapHandlerEntry11, 0);
    //9.8.12 Interrupt 12 -- Stack Exception
    SETGATE(idt[12], 0, 0x8, trapHandlerEntry12, 0);
    //9.8.13 Interrupt 13 -- General Protection Exception
    SETGATE(idt[13], 0, 0x8, trapHandlerEntry13, 0);
    //9.8.14 Interrupt 14 -- Page Fault
    SETGATE(idt[14], 0, 0x8, trapHandlerEntry14, 0);
    // no 15 (T_RES)

    SETGATE(idt[16], 0, 0x8, trapHandlerEntry16, 0);
    SETGATE(idt[17], 0, 0x8, trapHandlerEntry17, 0);
    SETGATE(idt[18], 0, 0x8, trapHandlerEntry18, 0);
    SETGATE(idt[19], 0, 0x8, trapHandlerEntry19, 0);
    SETGATE(idt[20], 0, 0x8, trapHandlerEntry20, 0);
    SETGATE(idt[21], 0, 0x8, trapHandlerEntry21, 0);
    SETGATE(idt[22], 0, 0x8, trapHandlerEntry22, 0);
    SETGATE(idt[23], 0, 0x8, trapHandlerEntry23, 0);
    SETGATE(idt[24], 0, 0x8, trapHandlerEntry24, 0);
    SETGATE(idt[25], 0, 0x8, trapHandlerEntry25, 0);
    SETGATE(idt[26], 0, 0x8, trapHandlerEntry26, 0);
    SETGATE(idt[27], 0, 0x8, trapHandlerEntry27, 0);
    SETGATE(idt[28], 0, 0x8, trapHandlerEntry28, 0);
    SETGATE(idt[29], 0, 0x8, trapHandlerEntry29, 0);
    SETGATE(idt[30], 0, 0x8, trapHandlerEntry30, 0);
    SETGATE(idt[31], 0, 0x8, trapHandlerEntry31, 0);
	// Per-CPU setup 
	trap_init_percpu();
}

// Initialize and load the per-CPU TSS and IDT
void
trap_init_percpu(void)
{
	// Setup a TSS so that we get the right stack
	// when we trap to the kernel.
	ts.ts_esp0 = KSTACKTOP;
	ts.ts_ss0 = GD_KD;

	// Initialize the TSS slot of the gdt.
	gdt[GD_TSS0 >> 3] = SEG16(STS_T32A, (uint32_t) (&ts),
					sizeof(struct Taskstate) - 1, 0);
	gdt[GD_TSS0 >> 3].sd_s = 0;

	// Load the TSS selector (like other segment selectors, the
	// bottom three bits are special; we leave them 0)
	ltr(GD_TSS0);

	// Load the IDT
	lidt(&idt_pd);
}

void
print_trapframe(struct Trapframe *tf)
{
	cprintf("TRAP frame at %p\n", tf);
	print_regs(&tf->tf_regs);
	cprintf("  es   0x----%04x\n", tf->tf_es);
	cprintf("  ds   0x----%04x\n", tf->tf_ds);
	cprintf("  trap 0x%08x %s\n", tf->tf_trapno, trapname(tf->tf_trapno));
	// If this trap was a page fault that just happened
	// (so %cr2 is meaningful), print the faulting linear address.
	if (tf == last_tf && tf->tf_trapno == T_PGFLT)
		cprintf("  cr2  0x%08x\n", rcr2());
	cprintf("  err  0x%08x", tf->tf_err);
	// For page faults, print decoded fault error code:
	// U/K=fault occurred in user/kernel mode
	// W/R=a write/read caused the fault
	// PR=a protection violation caused the fault (NP=page not present).
	if (tf->tf_trapno == T_PGFLT)
		cprintf(" [%s, %s, %s]\n",
			tf->tf_err & 4 ? "user" : "kernel",
			tf->tf_err & 2 ? "write" : "read",
			tf->tf_err & 1 ? "protection" : "not-present");
	else
		cprintf("\n");
	cprintf("  eip  0x%08x\n", tf->tf_eip);
	cprintf("  cs   0x----%04x\n", tf->tf_cs);
	cprintf("  flag 0x%08x\n", tf->tf_eflags);
	if ((tf->tf_cs & 3) != 0) {
		cprintf("  esp  0x%08x\n", tf->tf_esp);
		cprintf("  ss   0x----%04x\n", tf->tf_ss);
	}
}

void
print_regs(struct PushRegs *regs)
{
	cprintf("  edi  0x%08x\n", regs->reg_edi);
	cprintf("  esi  0x%08x\n", regs->reg_esi);
	cprintf("  ebp  0x%08x\n", regs->reg_ebp);
	cprintf("  oesp 0x%08x\n", regs->reg_oesp);
	cprintf("  ebx  0x%08x\n", regs->reg_ebx);
	cprintf("  edx  0x%08x\n", regs->reg_edx);
	cprintf("  ecx  0x%08x\n", regs->reg_ecx);
	cprintf("  eax  0x%08x\n", regs->reg_eax);
}

static void
trap_dispatch(struct Trapframe *tf)
{
	// Handle processor exceptions.
	// LAB 3: Your code here.

	// Unexpected trap: The user process or the kernel has a bug.
	print_trapframe(tf);
	if (tf->tf_cs == GD_KT)
		panic("unhandled trap in kernel");
	else {
		env_destroy(curenv);
		return;
	}
}

void
trap(struct Trapframe *tf)
{
	// The environment may have set DF and some versions
	// of GCC rely on DF being clear
	asm volatile("cld" ::: "cc");

	// Check that interrupts are disabled.  If this assertion
	// fails, DO NOT be tempted to fix it by inserting a "cli" in
	// the interrupt path.
	assert(!(read_eflags() & FL_IF));

	cprintf("Incoming TRAP frame at %p\n", tf);

	if ((tf->tf_cs & 3) == 3) {
		// Trapped from user mode.
		assert(curenv);

		// Copy trap frame (which is currently on the stack)
		// into 'curenv->env_tf', so that running the environment
		// will restart at the trap point.
		curenv->env_tf = *tf;
		// The trapframe on the stack should be ignored from here on.
		tf = &curenv->env_tf;
	}

	// Record that tf is the last real trapframe so
	// print_trapframe can print some additional information.
	last_tf = tf;

	// Dispatch based on what type of trap occurred
	trap_dispatch(tf);

	// Return to the current environment, which should be running.
	assert(curenv && curenv->env_status == ENV_RUNNING);
	env_run(curenv);
}


void
page_fault_handler(struct Trapframe *tf)
{
	uint32_t fault_va;

	// Read processor's CR2 register to find the faulting address
	fault_va = rcr2();

	// Handle kernel-mode page faults.

	// LAB 3: Your code here.

	// We've already handled kernel-mode exceptions, so if we get here,
	// the page fault happened in user mode.

	// Destroy the environment that caused the fault.
	cprintf("[%08x] user fault va %08x ip %08x\n",
		curenv->env_id, fault_va, tf->tf_eip);
	print_trapframe(tf);
	env_destroy(curenv);
}

