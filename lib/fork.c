// implement fork from user space

#include <inc/string.h>
#include <inc/lib.h>

// PTE_COW marks copy-on-write page table entries.
// It is one of the bits explicitly allocated to user processes (PTE_AVAIL).
#define PTE_COW		0x800

//
// Custom page fault handler - if faulting page is copy-on-write,
// map in our own private writable copy.
//
static void
pgfault(struct UTrapframe *utf)
{
	void *addr = (void *) utf->utf_fault_va;
	uint32_t err = utf->utf_err;
	int r;

	// Check that the faulting access was (1) a write, and (2) to a
	// copy-on-write page.  If not, panic.
	// Hint:
	//   Use the read-only page table mappings at uvpt
	//   (see <inc/memlayout.h>).

	// LAB 4: Your code here.

	// from mmu.h
	// define FEC_WR 0x2: Page fault caused by a write
	if (!(err & FEC_WR))
		panic("pgfault: not a page fault caused by write!\n");

	// A linear address 'la' has a three-part structure as follows:
	//
	// +--------10------+-------10-------+---------12----------+
	// | Page Directory |   Page Table   | Offset within Page  |
	// |      Index     |      Index     |                     |
	// +----------------+----------------+---------------------+
	//  \--- PDX(la) --/ \--- PTX(la) --/ \---- PGOFF(la) ----/
	//  \---------- PGNUM(la) ----------/
	//
	// The PDX, PTX, PGOFF, and PGNUM macros decompose linear addresses as shown.
	// To construct a linear address la from PDX(la), PTX(la), and PGOFF(la),
	// use PGADDR(PDX(la), PTX(la), PGOFF(la)).

	// The PTE for page number N is stored in uvpt[N]
	// pte_t uvpt[];     VA of "virtual page table"
	// pde_t uvpd[];     VA of current page directory
	if (!(uvpt[PGNUM(addr)] & PTE_COW))
		panic("pgfault: not a copy-on-write page!\n");

	// Allocate a new page, map it at a temporary location (PFTEMP),
	r = sys_page_alloc(0, PFTEMP, PTE_W | PTE_U | PTE_P);
	if (r < 0)
		panic("pgfault: sys_page_alloc failed for new page at temporary location! \n");

	// copy the data from the old page to the new page
	memcpy(PFTEMP, ROUNDDOWN(addr,PGSIZE), PGSIZE);

	// then move the new page to the old page's address.
	// sys_page_map(envid_t srcenvid, void *srcva, envid_t dstenvid, void *dstva, int perm)
	r = sys_page_map(0, PFTEMP, 0, ROUNDDOWN(addr, PGSIZE), PTE_W | PTE_U | PTE_P);
	if (r < 0)
		panic("pgfault: sys_page_map failed for moving new page to old pages location! \n");
	
	r = sys_page_unmap(0, PFTEMP);
	if (r < 0)
		panic("pgfault: sys_page_unmap failed at temporary location! \n");

	return;
	
	// Hint:
	//   You should make three system calls.

	// LAB 4: Your code here.

	//panic("pgfault not implemented");
}

//
// Map our virtual page pn (address pn*PGSIZE) into the target envid
// at the same virtual address.  If the page is writable or copy-on-write,
// the new mapping must be created copy-on-write, and then our mapping must be
// marked copy-on-write as well.  (Exercise: Why do we need to mark ours
// copy-on-write again if it was already copy-on-write at the beginning of
// this function?)
//
// Returns: 0 on success, < 0 on error.
// It is also OK to panic on error.
//
static int
duppage(envid_t envid, unsigned pn)
{
	int r;
	void * virt_page_addr = (void *)(pn*PGSIZE);
	// check if the page is writeable or copy on write
	if(!(uvpt[pn] & PTE_SHARE) && ((uvpt[pn] & PTE_W) || ((uvpt[pn]) & PTE_COW))){
		/*
		if ((uvpt[pn] & PTE_W)){
			cprintf("new page is writable!\n");
		} else {
			cprintf("new page is copy on write!\n");
		}*/

		// 0 = curnenv envid
		r = sys_page_map(0, virt_page_addr, envid, virt_page_addr, PTE_COW | PTE_U | PTE_P);
		if (r < 0)
			return r;
		//cprintf("mapped new page!\n");
		
		r = sys_page_map(0, virt_page_addr, 0, virt_page_addr, PTE_COW | PTE_U | PTE_P);
		if (r < 0)
			return r;
		//cprintf("remapped cur page!\n");
	} else {
		// not writeable or copy on write, new page doesnt need to be COW,
		// and we dont need mark our page COW again
		int perm = PTE_U | PTE_P;
		if (uvpt[pn] & PTE_SHARE)
			perm |= PTE_SHARE;

		r = sys_page_map(0, virt_page_addr, envid, virt_page_addr, (uvpt[pn] & PTE_SYSCALL) | perm);
		if (r < 0)
			return r; 
	}
	// LAB 4: Your code here.
	//panic("duppage not implemented");
	return 0;
}

//
// User-level fork with copy-on-write.
// Set up our page fault handler appropriately.
// Create a child.
// Copy our address space and page fault handler setup to the child.
// Then mark the child as runnable and return.
//
// Returns: child's envid to the parent, 0 to the child, < 0 on error.
// It is also OK to panic on error.
//
// Hint:
//   Use uvpd, uvpt, and duppage.
//   Remember to fix "thisenv" in the child process.
//   Neither user exception stack should ever be marked copy-on-write,
//   so you must allocate a new page for the child's user exception stack.
//
envid_t
fork(void)
{
	// LAB 4: Your code here.
	//panic("fork not implemented");

	// Set up our page fault handler appropriately.
	set_pgfault_handler(pgfault);

	// Create a child.
	envid_t child;
	child = sys_exofork(); // sets eax to 0 for child
	if (child < 0)
		panic("fork: error on child creation! \n");

	if (child == 0) {
		// We're the child.
		// The copied value of the global variable 'thisenv'
		// is no longer valid (it refers to the parent!).
		// Fix it and return 0.
		thisenv = &envs[ENVX(sys_getenvid())];
		return 0;
	}

	// Copy our address space and page fault handler setup to the child.
	int pde;
	int pte;
	for (pde = 0; pde < PDX(UTOP); pde++) {
		for (pte = pde * NPTENTRIES; pte < (pde * NPTENTRIES) + NPTENTRIES; pte++) {
			if (pde == PDX(UXSTACKTOP-PGSIZE) && pte == PGNUM(UXSTACKTOP-PGSIZE))
				continue; // userexception stack should NOT be marked COW
			if ((uvpd[pde] & PTE_P) && (uvpt[pte] & PTE_P)){
				//cprintf("copy page! \n");
				duppage(child, pte);
			}
		}

		/*
		cprintf("increment address \n");
		cprintf("PDX(UTOP): %d \n", PDX(UTOP));
		cprintf("pde: %d \n", pde);
		cprintf("pte: %d \n", pte);
		*/
	}
	//cprintf("allocate expection stack \n");
	//  Neither user exception stack should ever be marked copy-on-write,
	//  so you must allocate a new page for the child's user exception stack.
	sys_page_alloc(child, (void *)(UXSTACKTOP - PGSIZE), PTE_W | PTE_U | PTE_P);
	//cprintf("expection stack allocated\n");
	//cprintf("UXSTACKTOP-PGSIZE: %08x  \n", UXSTACKTOP - PGSIZE);

	// Then mark the child as runnable and return.
	sys_env_set_pgfault_upcall(child, thisenv->env_pgfault_upcall);
	sys_env_set_status(child, ENV_RUNNABLE);
	//cprintf("return child id \n");
	
	return child;
}

// Challenge!
int
sfork(void)
{
	panic("sfork not implemented");
	return -E_INVAL;
}
