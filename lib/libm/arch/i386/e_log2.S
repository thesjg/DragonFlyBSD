/*
 * Written by Rui Paulo <rpaulo@NetBSD.org>, based on e_log.S.
 * Public domain.
 * $NetBSD: e_log2.S,v 1.1 2005/07/21 20:58:21 rpaulo Exp $
 * $DragonFly: src/lib/libm/arch/i386/e_log2.S,v 1.1 2007/06/16 22:26:53 pavalos Exp $
 */

#include <machine/asm.h>

#include "abi.h"

ENTRY(log2)
	XMM_ONE_ARG_DOUBLE_PROLOGUE
	fld1
	fldl	ARG_DOUBLE_ONE
	fyl2x
	XMM_DOUBLE_EPILOGUE
	ret
