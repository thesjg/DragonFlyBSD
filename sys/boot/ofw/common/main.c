/*-
 * Copyright (c) 2000 Benno Rice <benno@jeamland.net>
 * Copyright (c) 2000 Stephane Potvin <sepotvin@videotron.ca>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/boot/ofw/common/main.c,v 1.3 2002/11/10 19:17:35 jake Exp $
 * $DragonFly: src/sys/boot/ofw/common/main.c,v 1.1 2003/11/10 06:08:37 dillon Exp $
 */

#include <stand.h>
#include "openfirm.h"
#include "libofw.h"
#include "bootstrap.h"

struct arch_switch	archsw;		/* MI/MD interface boundary */

extern char end[];
extern char bootprog_name[];
extern char bootprog_rev[];
extern char bootprog_date[];
extern char bootprog_maker[];

phandle_t	chosen;

#define	HEAP_SIZE	0x40000

void
init_heap(void)
{
	void	*base;

	if ((base = ofw_alloc_heap(HEAP_SIZE)) == (void *)0xffffffff) {
		printf("Heap memory claim failed!\n");
		OF_enter();
	}

	setheap(base, base + (HEAP_SIZE / sizeof(base)));
}

uint32_t
memsize(void)
{
	ihandle_t	meminstance;
	phandle_t	memory;
	struct ofw_reg	reg;

	OF_getprop(chosen, "memory", &meminstance, sizeof(meminstance));
	memory = OF_instance_to_package(meminstance);

	OF_getprop(memory, "reg", &reg, sizeof(reg));

	return (reg.size);
}

int
main(int (*openfirm)(void *))
{
	int		i;
	char		bootpath[64];
	char		*ch;

	/*
	 * Initalise the OpenFirmware routines by giving them the entry point.
	 */
	OF_init(openfirm);

	chosen = OF_finddevice("/chosen");

	/*
         * Set up console.
         */
	cons_probe();

	/*
	 * Initialise the heap as early as possible.  Once this is done,
	 * alloc() is usable. The stack is buried inside us, so this is
	 * safe.
	 */
	init_heap();

	/*
	 * Initialise the block cache
	 */
	bcache_init(32, 512);		/* 16k XXX tune this */

	/*
	 * March through the device switch probing for things.
	 */
	for (i = 0; devsw[i] != NULL; i++)
		if (devsw[i]->dv_init != NULL)
			(devsw[i]->dv_init)();

	printf("\n");
	printf("%s, Revision %s\n", bootprog_name, bootprog_rev);
	printf("(%s, %s)\n", bootprog_maker, bootprog_date);
	printf("Memory: %dKB\n", memsize() / 1024);

	OF_getprop(chosen, "bootpath", bootpath, 64);
	ch = index(bootpath, ':');
	*ch = '\0';
	printf("Booted from: %s\n", bootpath);

	printf("\n");

	env_setenv("currdev", EV_VOLATILE, bootpath,
	    ofw_setcurrdev, env_nounset);
	env_setenv("loaddev", EV_VOLATILE, bootpath, env_noset,
	    env_nounset);
	setenv("LINES", "24", 1);		/* optional */

	archsw.arch_getdev = ofw_getdev;
	archsw.arch_copyin = ofw_copyin;
	archsw.arch_copyout = ofw_copyout;
	archsw.arch_readin = ofw_readin;
	archsw.arch_autoload = ofw_autoload;

	interact();				/* doesn't return */

	OF_exit();

	return 0;
}

COMMAND_SET(halt, "halt", "halt the system", command_halt);

static int
command_halt(int argc, char *argv[])
{

	OF_exit();
	return (CMD_OK);
}

COMMAND_SET(memmap, "memmap", "print memory map", command_memmap);

int
command_memmap(int argc, char **argv)
{

	ofw_memmap();
	return (CMD_OK);
}
