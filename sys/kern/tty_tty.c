/*-
 * (MPSAFE)
 *
 * Copyright (c) 1982, 1986, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)tty_tty.c	8.2 (Berkeley) 9/23/93
 * $FreeBSD: src/sys/kern/tty_tty.c,v 1.30 1999/09/25 18:24:24 phk Exp $
 */

/*
 * Indirect driver for controlling tty.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/device.h>
#include <sys/lock.h>
#include <sys/fcntl.h>
#include <sys/proc.h>
#include <sys/ttycom.h>
#include <sys/vnode.h>
#include <sys/kernel.h>
#include <sys/poll.h> /* XXX: poll args used in KQ filters */
#include <sys/event.h>

static	d_open_t	cttyopen;
static	d_close_t	cttyclose;
static	d_read_t	cttyread;
static	d_write_t	cttywrite;
static	d_ioctl_t	cttyioctl;

static boolean_t	cty_filter_read (struct kev_filter_note *fn, long hint,
    caddr_t hook);
static boolean_t	cty_filter_write (struct kev_filter_note *fn, long hint,
    caddr_t hook);

#define	CDEV_MAJOR	1
static struct dev_ops ctty_ops = {
	{ "ctty", 0, D_TTY },
	.d_open =	cttyopen,
	.d_close =	cttyclose,
	.d_read =	cttyread,
	.d_write =	cttywrite,
	.d_ioctl =	cttyioctl
};

#define cttyvp(p) (((p)->p_flags & P_CONTROLT) ? \
			(p)->p_session->s_ttyvp : NULL)

/*
 * This opens /dev/tty.  Because multiple opens of /dev/tty only
 * generate a single open to the actual tty, the file modes are
 * locked to FREAD|FWRITE.
 */
static	int
cttyopen(struct dev_open_args *ap)
{
	struct proc *p = curproc;
	struct vnode *ttyvp;
	int error;

	KKASSERT(p);
retry:
	if ((ttyvp = cttyvp(p)) == NULL)
		return (ENXIO);
	if (ttyvp->v_flag & VCTTYISOPEN)
		return (0);

	/*
	 * Messy interlock, don't let the vnode go away while we try to
	 * lock it and check for race after we might have blocked.
	 */
	vhold(ttyvp);
	vn_lock(ttyvp, LK_EXCLUSIVE | LK_RETRY);
	if (ttyvp != cttyvp(p) || (ttyvp->v_flag & VCTTYISOPEN)) {
		kprintf("Warning: cttyopen: race avoided\n");
		vn_unlock(ttyvp);
		vdrop(ttyvp);
		goto retry;
	}
	vsetflags(ttyvp, VCTTYISOPEN);
	error = VOP_OPEN(ttyvp, FREAD|FWRITE, ap->a_cred, NULL);
	if (error)
		vclrflags(ttyvp, VCTTYISOPEN);
	vn_unlock(ttyvp);
	vdrop(ttyvp);
	return(error);
}

/*
 * This closes /dev/tty.  Because multiple opens of /dev/tty only
 * generate a single open to the actual tty, the file modes are
 * locked to FREAD|FWRITE.
 */
static int
cttyclose(struct dev_close_args *ap)
{
	struct proc *p = curproc;
	struct vnode *ttyvp;
	int error;

	KKASSERT(p);
retry:
	/*
	 * The tty may have been TIOCNOTTY'd, don't return an
	 * error on close.  We just have nothing to do.
	 */
	if ((ttyvp = cttyvp(p)) == NULL)
		return(0);
	if (ttyvp->v_flag & VCTTYISOPEN) {
		/*
		 * Avoid a nasty race if we block while getting the lock.
		 */
		vref(ttyvp);
		error = vn_lock(ttyvp, LK_EXCLUSIVE | LK_RETRY);
		if (error) {
			vrele(ttyvp);
			goto retry;
		}
		if (ttyvp != cttyvp(p) || (ttyvp->v_flag & VCTTYISOPEN) == 0) {
			kprintf("Warning: cttyclose: race avoided\n");
			vn_unlock(ttyvp);
			vrele(ttyvp);
			goto retry;
		}
		vclrflags(ttyvp, VCTTYISOPEN);
		error = VOP_CLOSE(ttyvp, FREAD|FWRITE);
		vn_unlock(ttyvp);
		vrele(ttyvp);
	} else {
		error = 0;
	}
	return(error);
}

/*
 * Read from the controlling terminal (/dev/tty).  The tty is refed as
 * of the cttyvp(), but the ref can get ripped out from under us if
 * the controlling terminal is revoked while we are blocked on the lock,
 * so use vget() instead of vn_lock().
 */
static	int
cttyread(struct dev_read_args *ap)
{
	struct proc *p = curproc;
	struct vnode *ttyvp;
	int error;

	KKASSERT(p);
	ttyvp = cttyvp(p);
	if (ttyvp == NULL)
		return (EIO);
	if ((error = vget(ttyvp, LK_EXCLUSIVE | LK_RETRY)) == 0) {
		error = VOP_READ(ttyvp, ap->a_uio, ap->a_ioflag, NOCRED);
		vput(ttyvp);
	}
	return (error);
}

/*
 * Read from the controlling terminal (/dev/tty).  The tty is refed as
 * of the cttyvp(), but the ref can get ripped out from under us if
 * the controlling terminal is revoked while we are blocked on the lock,
 * so use vget() instead of vn_lock().
 */
static	int
cttywrite(struct dev_write_args *ap)
{
	struct proc *p = curproc;
	struct vnode *ttyvp;
	int error;

	KKASSERT(p);
	ttyvp = cttyvp(p);
	if (ttyvp == NULL)
		return (EIO);
	if ((error = vget(ttyvp, LK_EXCLUSIVE | LK_RETRY)) == 0) {
		error = VOP_WRITE(ttyvp, ap->a_uio, ap->a_ioflag, NOCRED);
		vput(ttyvp);
	}
	return (error);
}

/*ARGSUSED*/
static	int
cttyioctl(struct dev_ioctl_args *ap)
{
	struct vnode *ttyvp;
	struct proc *p = curproc;

	KKASSERT(p);
	lwkt_gettoken(&p->p_token);
	lwkt_gettoken(&proc_token);
	ttyvp = cttyvp(p);
	if (ttyvp == NULL) {
		lwkt_reltoken(&proc_token);
		lwkt_reltoken(&p->p_token);
		return (EIO);
	}
	/*
	 * Don't allow controlling tty to be set to the controlling tty
	 * (infinite recursion).
	 */
	if (ap->a_cmd == TIOCSCTTY) {
		lwkt_reltoken(&proc_token);
		lwkt_reltoken(&p->p_token);
		return EINVAL;
	}
	if (ap->a_cmd == TIOCNOTTY) {
		if (!SESS_LEADER(p)) {
			p->p_flags &= ~P_CONTROLT;
			lwkt_reltoken(&proc_token);
			lwkt_reltoken(&p->p_token);
			return (0);
		} else {
			lwkt_reltoken(&proc_token);
			lwkt_reltoken(&p->p_token);
			return (EINVAL);
		}
	}
	lwkt_reltoken(&proc_token);
	lwkt_reltoken(&p->p_token);

	return (VOP_IOCTL(ttyvp, ap->a_cmd, ap->a_data, ap->a_fflag,
			  ap->a_cred, ap->a_sysmsg));
}

static boolean_t
cty_filter_read(struct kev_filter_note *fn, long hint, caddr_t hook)
{
	cdev_t dev = (cdev_t)hook;

	if (seltrue(dev, POLLIN | POLLRDNORM))
		return (TRUE);

	return (FALSE);
}

static boolean_t
cty_filter_write(struct kev_filter_note *fn, long hint, caddr_t hook)
{
	cdev_t dev = (cdev_t)hook;

	if (seltrue(dev, POLLOUT | POLLWRNORM))
		return (TRUE);

	return (FALSE);
}

static void
ctty_drvinit(void *unused __unused)
{
	cdev_t dev;
	static struct kev_filter_ops kev_fops = {
		.fop_read = { cty_filter_read, KEV_FILTOP_NOTMPSAFE },
		.fop_write = { cty_filter_write, KEV_FILTOP_NOTMPSAFE }
	};

	dev = make_dev(&ctty_ops, 0, 0, 0, 0666, "tty");
	kev_dev_filter_init(dev, &kev_fops, (caddr_t)dev);
}

SYSINIT(cttydev,SI_SUB_DRIVERS,SI_ORDER_MIDDLE+CDEV_MAJOR,ctty_drvinit,NULL)
