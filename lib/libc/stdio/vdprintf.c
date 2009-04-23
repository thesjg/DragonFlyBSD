/*-
 * Copyright (c) 2009 David Schultz <das@FreeBSD.org>
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
 * $FreeBSD: src/lib/libc/stdio/vdprintf.c,v 1.1 2009/03/04 03:38:51 das Exp $
 */

#include "namespace.h"
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include "un-namespace.h"

#include "local.h"
#include "priv_stdio.h"

int
vdprintf(int fd, const char * __restrict fmt, va_list ap)
{
	FILE f;
	unsigned char buf[BUFSIZ];
	int ret;

	if (fd > SHRT_MAX) {
		errno = EMFILE;
		return (EOF);
	}

	f.pub._p = buf;
	f.pub._w = sizeof(buf);
	f.pub._flags = __SWR;
	f.pub._fileno = fd;
	f._cookie = &f;
	f._write = __swrite;
	f._bf._base = buf;
	f._bf._size = sizeof(buf);
	memset(WCIO_GET(&f), 0, sizeof(struct wchar_io_data));

	if ((ret = __vfprintf(&f, fmt, ap)) < 0)
		return (ret);

	return (__fflush(&f) ? EOF : ret);
}