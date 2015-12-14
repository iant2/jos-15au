/* See COPYRIGHT for copyright information. */

#include <inc/mmu.h>
#include <inc/memlayout.h>
#include <inc/trap.h>

###################################################################
# exceptions/interrupts
###################################################################

/* TRAPHANDLER defines a globally-visible function for handling a trap.
 * It pushes a trap number onto the stack, then jumps to _alltraps.
 * Use TRAPHANDLER for traps where the CPU automatically pushes an error code.
 *
 * You shouldn't call a TRAPHANDLER function from C, but you may
 * need to _declare_ one in C (for instance, to get a function pointer
 * during IDT setup).  You can declare the function with
 *   void NAME();
 * where NAME is the argument passed to TRAPHANDLER.
 */
#define TRAPHANDLER(name, num)						\
    .text;								\
	  .globl name;		/* define global symbol for 'name' */	\
	  .type name, @function;	/* symbol type is function */		\
	  .align 2;		/* align function definition */		\
	  name:			/* function starts here */		\
	  pushl $(num);							\
	  jmp _alltraps;							\
    .data;								\
    .long name

/* Use TRAPHANDLER_NOEC for traps where the CPU doesn't push an error code.
 * It pushes a 0 in place of the error code, so the trap frame has the same
 * format in either case.
 */
#define TRAPHANDLER_NOEC(name, num)					\
  .text;								\
	.globl name;							\
	.type name, @function;						\
	.align 2;							\
	name:								\
	pushl $0;							\
	pushl $(num);							\
	jmp _alltraps;							\
  .data;								\
  .long name

#challenge
.data
.globl vectors
vectors:
.text

/*
 * Lab 3: Your code here for generating entry points for the different traps.
 */
 TRAPHANDLER_NOEC(trapHandlerEntry0,T_DIVIDE);
 TRAPHANDLER_NOEC(trapHandlerEntry1,T_DEBUG);
 TRAPHANDLER_NOEC(trapHandlerEntry2,T_NMI);
 TRAPHANDLER_NOEC(trapHandlerEntry3,T_BRKPT);
 TRAPHANDLER_NOEC(trapHandlerEntry4,T_OFLOW);
 TRAPHANDLER_NOEC(trapHandlerEntry5,T_BOUND);
 TRAPHANDLER_NOEC(trapHandlerEntry6,T_ILLOP);
 TRAPHANDLER_NOEC(trapHandlerEntry7,T_DEVICE);
 TRAPHANDLER(trapHandlerEntry8,T_DBLFLT);

 

 TRAPHANDLER(trapHandlerEntry10,T_TSS);
 TRAPHANDLER(trapHandlerEntry11,T_SEGNP);
 TRAPHANDLER(trapHandlerEntry12,T_STACK);
 TRAPHANDLER(trapHandlerEntry13,T_GPFLT);
 TRAPHANDLER(trapHandlerEntry14,T_PGFLT);



 TRAPHANDLER_NOEC(trapHandlerEntry16,T_FPERR);
 TRAPHANDLER_NOEC(trapHandlerEntry17,T_ALIGN);
 TRAPHANDLER_NOEC(trapHandlerEntry18,T_MCHK);
 TRAPHANDLER_NOEC(trapHandlerEntry19,T_SIMDERR);
 TRAPHANDLER_NOEC(trapHandlerEntry20, 20);
 
 TRAPHANDLER(trapHandlerEntry21, 21);
 TRAPHANDLER(trapHandlerEntry22, 22);
 TRAPHANDLER(trapHandlerEntry23, 23);
 TRAPHANDLER(trapHandlerEntry24, 24);
 TRAPHANDLER(trapHandlerEntry25, 25);
 TRAPHANDLER(trapHandlerEntry26, 26);
 TRAPHANDLER(trapHandlerEntry27, 27);
 TRAPHANDLER(trapHandlerEntry28, 28);
 TRAPHANDLER(trapHandlerEntry29, 29);
 TRAPHANDLER(trapHandlerEntry30, 30);
 TRAPHANDLER(trapHandlerEntry31, 31);

 //system call from the user
 TRAPHANDLER_NOEC(trapHandlerEntry48, T_SYSCALL);



/*
 * Lab 3: Your code here for _alltraps
 * 
 */
 _alltraps:
 	pushl %ds
	pushl %es

	// push values to make the stack look like a struct Trapframe
	pushal
	// load GD_KD into %ds and %es
	// define GD_KD     0x10     // kernel data
	movl $GD_KD, %eax
	movw %ax, %ds
	movw %ax, %es

	// pushl %esp to pass a pointer to the Trapframe as an argument to trap()
	pushl %esp

	// call trap
	call trap

	// can trap return?