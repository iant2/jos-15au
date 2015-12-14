// Ping-pong a counter between two processes.
// Only need to start one of these -- splits into two, crudely.

#include <inc/string.h>
#include <inc/lib.h>
#include <lib/fork.c>

envid_t dumbfork(void);

void
umain(int argc, char **argv)
{

	envid_t who;
	int i;

	// fork a child process
	who = pfork(1);

	if(who){
		cprintf("I am the parent and I will only run once, after which I will yeild to the child who has \n a higher priority. I will run again once the child is done. \n");
	} else {
		cprintf("I am the child and will always run over my parent as i was forkerd with a higher priority than it.\n");
	}
	
	// print a message and yield to the other a few times
	for (i = 0; i < (who ? 10 : 20); i++) {
		cprintf("%d: I am the %s!\n", i, who ? "parent" : "child");
		sys_yield();
	}
}


