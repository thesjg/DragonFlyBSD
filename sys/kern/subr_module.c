/*-
 * Copyright (c) 1998 Michael Smith
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
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
 * $FreeBSD: src/sys/kern/subr_module.c,v 1.6 1999/10/11 15:19:10 peter Exp $
 * $DragonFly: src/sys/kern/subr_module.c,v 1.4 2004/05/26 08:32:41 dillon Exp $
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/linker.h>

/*
 * Preloaded module support
 */

caddr_t	preload_metadata;

/*
 * Search for the preloaded module (name)
 */
caddr_t
preload_search_by_name(const char *name)
{
    caddr_t	curp;
    u_int32_t	*hdr;
    int		next;
    int		i;
    char	*scanname;

    if (preload_metadata == NULL)
	return(NULL);

    curp = preload_metadata;
    for (;;) {
	hdr = (u_int32_t *)curp;
	if (hdr[0] == 0 && hdr[1] == 0)
	    break;

	/*
	 * Search for a MODINFO_NAME field.  the boot loader really
	 * ought to strip the path names
	 */
	if (hdr[0] == MODINFO_NAME) {
	    scanname = curp + sizeof(u_int32_t) * 2;
	    i = strlen(scanname);
	    while (i > 0 && scanname[i-1] != '/')
		--i;
	    if (strcmp(name, scanname) == 0)
		return(curp);
	    if (strcmp(name, scanname + i) == 0)
		return(curp);
	}
	/* skip to next field */
	next = sizeof(u_int32_t) * 2 + hdr[1];
	next = roundup(next, sizeof(u_long));
	curp += next;
    }
    return(NULL);
}

/*
 * Search for the first preloaded module of (type)
 */
caddr_t
preload_search_by_type(const char *type)
{
    caddr_t	curp, lname;
    u_int32_t	*hdr;
    int		next;

    if (preload_metadata != NULL) {

	curp = preload_metadata;
	lname = NULL;
	for (;;) {
	    hdr = (u_int32_t *)curp;
	    if (hdr[0] == 0 && hdr[1] == 0)
		break;

	    /* remember the start of each record */
	    if (hdr[0] == MODINFO_NAME)
		lname = curp;

	    /* Search for a MODINFO_TYPE field */
	    if ((hdr[0] == MODINFO_TYPE) &&
		!strcmp(type, curp + sizeof(u_int32_t) * 2))
		return(lname);

	    /* skip to next field */
	    next = sizeof(u_int32_t) * 2 + hdr[1];
	    next = roundup(next, sizeof(u_long));
	    curp += next;
	}
    }
    return(NULL);
}

/*
 * Walk through the preloaded module list
 */
caddr_t
preload_search_next_name(caddr_t base)
{
    caddr_t	curp;
    u_int32_t	*hdr;
    int		next;
    
    if (preload_metadata != NULL) {
	
	/* Pick up where we left off last time */
	if (base) {
	    /* skip to next field */
	    curp = base;
	    hdr = (u_int32_t *)curp;
	    next = sizeof(u_int32_t) * 2 + hdr[1];
	    next = roundup(next, sizeof(u_long));
	    curp += next;
	} else
	    curp = preload_metadata;

	for (;;) {
	    hdr = (u_int32_t *)curp;
	    if (hdr[0] == 0 && hdr[1] == 0)
		break;

	    /* Found a new record? */
	    if (hdr[0] == MODINFO_NAME)
		return curp;

	    /* skip to next field */
	    next = sizeof(u_int32_t) * 2 + hdr[1];
	    next = roundup(next, sizeof(u_long));
	    curp += next;
	}
    }
    return(NULL);
}

/*
 * Given a preloaded module handle (mod), return a pointer
 * to the data for the attribute (inf).
 */
caddr_t
preload_search_info(caddr_t mod, int inf)
{
    caddr_t	curp;
    u_int32_t	*hdr;
    u_int32_t	type = 0;
    int		next;

    curp = mod;
    for (;;) {
	hdr = (u_int32_t *)curp;
	/* end of module data? */
	if (hdr[0] == 0 && hdr[1] == 0)
	    break;
	/* 
	 * We give up once we've looped back to what we were looking at 
	 * first - this should normally be a MODINFO_NAME field.
	 */
	if (type == 0) {
	    type = hdr[0];
	} else {
	    if (hdr[0] == type)
		break;
	}
	
	/* 
	 * Attribute match? Return pointer to data.
	 * Consumer may safely assume that size value preceeds	
	 * data.
	 */
	if (hdr[0] == inf)
	    return(curp + (sizeof(u_int32_t) * 2));

	/* skip to next field */
	next = sizeof(u_int32_t) * 2 + hdr[1];
	next = roundup(next, sizeof(u_long));
	curp += next;
    }
    return(NULL);
}

/*
 * Delete a preload record by name.
 *
 * XXX we should really pass the base of the preloaded module here and not
 * require rematching of the name.  If the wrong module (or no module) is
 * deleted, the original preloaded module might be loaded again, causing it's
 * data to be relocated twice.
 */
void
preload_delete_name(const char *name)
{
    caddr_t	curp;
    u_int32_t	*hdr;
    int		next;
    int		clearing;
    int		i;
    char	*scanname;
    
    if (preload_metadata != NULL) {
	clearing = 0;
	curp = preload_metadata;
	for (;;) {
	    hdr = (u_int32_t *)curp;
	    if (hdr[0] == 0 && hdr[1] == 0)
		break;

	    /* Search for a MODINFO_NAME field */
	    if (hdr[0] == MODINFO_NAME) {
		scanname = curp + sizeof(u_int32_t) * 2;
		i = strlen(scanname);
		while (i > 0 && scanname[i-1] != '/')
		    --i;
		if (strcmp(name, scanname) == 0)
		    clearing = 1;
		else if (strcmp(name, scanname + i) == 0)
		    clearing = 1;
		else
		    clearing = 0;	/* at next module now, stop clearing */
	    }
	    if (clearing)
		hdr[0] = MODINFO_EMPTY;

	    /* skip to next field */
	    next = sizeof(u_int32_t) * 2 + hdr[1];
	    next = roundup(next, sizeof(u_long));
	    curp += next;
	}
    }
}

/* Called from locore on i386.  Convert physical pointers to kvm. Sigh. */
void
preload_bootstrap_relocate(vm_offset_t offset)
{
    caddr_t	curp;
    u_int32_t	*hdr;
    vm_offset_t	*ptr;
    int		next;
    
    if (preload_metadata != NULL) {
	
	curp = preload_metadata;
	for (;;) {
	    hdr = (u_int32_t *)curp;
	    if (hdr[0] == 0 && hdr[1] == 0)
		break;

	    /* Deal with the ones that we know we have to fix */
	    switch (hdr[0]) {
	    case MODINFO_ADDR:
	    case MODINFO_METADATA|MODINFOMD_SSYM:
	    case MODINFO_METADATA|MODINFOMD_ESYM:
		ptr = (vm_offset_t *)(curp + (sizeof(u_int32_t) * 2));
		*ptr += offset;
		break;
	    }
	    /* The rest is beyond us for now */

	    /* skip to next field */
	    next = sizeof(u_int32_t) * 2 + hdr[1];
	    next = roundup(next, sizeof(u_long));
	    curp += next;
	}
    }
}
