/*-
 * Copyright (c) 1999,2000,2001 Jonathan Lemon <jlemon@FreeBSD.org>
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
 *	$FreeBSD: src/sys/sys/event.h,v 1.5.2.6 2003/02/09 15:28:13 nectar Exp $
 *	$DragonFly: src/sys/sys/event.h,v 1.7 2007/01/15 01:26:56 dillon Exp $
 */

#ifndef _SYS_EVENT_H_
#define _SYS_EVENT_H_

#ifndef _SYS_TYPES_H_
#include <sys/types.h>
#endif
#ifndef _SYS_QUEUE_H_
#include <sys/queue.h>
#endif

enum {
	EVFILT_READ = 	-1,
	EVFILT_WRITE =	-2,
	EVFILT_AIO =	-3,	/* attached to aio requests */
	EVFILT_VNODE =	-4,	/* attached to vnodes */
	EVFILT_PROC =	-5,	/* attached to struct proc */
	EVFILT_SIGNAL =	-6,	/* attached to struct proc */
	EVFILT_TIMER =	-7,	/* timers */
	EVFILT_EXCEPT = -8	/* exceptional conditions */
};
#define EVFILT_SYSCOUNT		8	/* filter count */

#define EV_SET(kevp_, a, b, c, d, e, f) do {	\
	struct kevent *kevp = (kevp_);		\
	(kevp)->ident = (a);			\
	(kevp)->filter = (b);			\
	(kevp)->flags = (c);			\
	(kevp)->fflags = (d);			\
	(kevp)->data = (e);			\
	(kevp)->udata = (f);			\
} while(0)

struct kevent {
	uintptr_t	ident;		/* identifier for this event */
	short		filter;		/* filter for event */
	u_short		flags;
	u_int		fflags;
	intptr_t	data;
	void		*udata;		/* opaque user data identifier */
};

/* actions */
#define EV_ADD		0x0001		/* add event to kq (implies enable) */
#define EV_DELETE	0x0002		/* delete event from kq */
#define EV_ENABLE	0x0004		/* enable event */
#define EV_DISABLE	0x0008		/* disable event (not reported) */

/* flags */
#define EV_ONESHOT	0x0010		/* only report one occurrence */
#define EV_CLEAR	0x0020		/* clear event state after reporting */

#define EV_SYSFLAGS	0xF000		/* reserved by system */
#define EV_FLAG1	0x2000		/* filter-specific flag */

/* returned values */
#define EV_EOF		0x8000		/* EOF detected */
#define EV_ERROR	0x4000		/* error, data contains errno */

/*
 * data/hint flags for EVFILT_{READ|WRITE}, shared with userspace
 */
#define NOTE_LOWAT	0x0001			/* low water mark */

/*
 * data/hint flags for EVFILT_EXCEPT, shared with userspace and with
 * EVFILT_{READ|WRITE}
 */
#define NOTE_OOB	0x0002			/* OOB data on a socket */

/*
 * data/hint flags for EVFILT_VNODE, shared with userspace
 */
#define	NOTE_DELETE	0x0001			/* vnode was removed */
#define	NOTE_WRITE	0x0002			/* data contents changed */
#define	NOTE_EXTEND	0x0004			/* size increased */
#define	NOTE_ATTRIB	0x0008			/* attributes changed */
#define	NOTE_LINK	0x0010			/* link count changed */
#define	NOTE_RENAME	0x0020			/* vnode was renamed */
#define	NOTE_REVOKE	0x0040			/* vnode access was revoked */

/*
 * data/hint flags for EVFILT_PROC, shared with userspace
 */
#define	NOTE_EXIT	0x80000000		/* process exited */
#define	NOTE_FORK	0x40000000		/* process forked */
#define	NOTE_EXEC	0x20000000		/* process exec'd */
#define	NOTE_PCTRLMASK	0xf0000000		/* mask for hint bits */
#define	NOTE_PDATAMASK	0x000fffff		/* mask for pid */

/* additional flags for EVFILT_PROC */
#define	NOTE_TRACK	0x00000001		/* follow across forks */
#define	NOTE_TRACKERR	0x00000002		/* could not track child */
#define	NOTE_CHILD	0x00000004		/* am a child process */

#if defined(_KERNEL) || defined(_KERNEL_STRUCTURES)

#define KEV_FILTOP_NOTMPSAFE    0x0001  /* if the filter is NOT MPSAFE */

struct kev_filter_note;

/*
 *
 */
struct kev_filter_op {
	boolean_t	(*fo_event)	(struct kev_filter_note *fn, long hint, caddr_t hook);
	u_int		fo_flags;
};

/*
 *
 */
struct kev_filter_ops {
	struct kev_filter_op	fop_read;
	struct kev_filter_op	fop_write;

	/*
	 * fop_special is overloaded for aio, vnode, proc, signal, timer and
	 * except.
	 */
	struct kev_filter_op	fop_special;
};


struct kev_filter_entry;
TAILQ_HEAD(kev_filter_entry_list, kev_filter_entry);

/*
 * Used to maintain information about processes that wish to be
 * notified when I/O becomes possible.
 */
struct kev_filter {
	struct  kev_filter_entry_list	*kf_entry;
	struct  kev_filter_ops		kf_ops;
	caddr_t				kf_hook;
};
#endif

#ifdef _KERNEL

/*
 * Global token for kqueue subsystem
 */
extern struct lwkt_token kq_token;

#ifdef MALLOC_DECLARE
MALLOC_DECLARE(M_KQUEUE);
#endif

/*
 * Flag indicating hint is a signal.  Used by EVFILT_SIGNAL, and also
 * shared by EVFILT_PROC  (all knotes attached to p->p_klist)
 *
 * NOTE_OLDAPI is used to signal that standard filters are being called
 * from the select/poll wrapper.
 */
#define NOTE_SIGNAL	0x08000000
#define NOTE_OLDAPI	0x04000000	/* select/poll note */

struct kev_filter_note {
	struct			kev_filter_entry *fn_entry;	/* parent */

	short			fn_filter;	/* EVFILT_* filter type */

	u_int			fn_ufflags;	/* flags from userland */
	intptr_t		fn_udata;	/* data from userland */

	/*
	 * Set by an event filter and returned to userland inside
	 * struct kevent or optionally acted on by select/poll.
	 */
	u_short			fn_flags;
	u_int			fn_fflags;
	intptr_t		fn_data;
};

struct kev_filter_entry {
	TAILQ_ENTRY(kev_filter_entry)	fe_link;	/* proc */
	TAILQ_ENTRY(kev_filter_entry)	fe_kqlink;	/* parent (struct kqueue) */
	TAILQ_ENTRY(kev_filter_entry)	fe_pending;
	TAILQ_ENTRY(kev_filter_entry)	fe_entry;	/* kq_head?, cdev or specially embedded */

	/*
         * Identifier (typically a file descriptor)
         * fe_link is indexed via this field
         */
	uintptr_t		fe_ident;
	boolean_t		fe_fd;		/* represents a file descriptor */

	int			fe_status;	/* flags, KFE_* */
	struct			kqueue *fe_kq;	/* parent */

	union {
		struct		file *p_fp;
		struct		proc *p_proc;
	} fe_ptr;

	struct 			kev_filter_note	*fe_notes[EVFILT_SYSCOUNT];
	struct			kev_filter	*fe_filter;

	intptr_t		fn_idata;	/* opaque data for select/poll */
};

#define KFE_ACTIVE	0x0001			/* event has been triggered */
#define KFE_QUEUED	0x0002			/* event is on queue */
#define KFE_DISABLED	0x0004			/* event is disabled */
#define KFE_DETACHED	0x0008			/* knote is detached */
#define KFE_REPROCESS	0x0010			/* force reprocessing race */
#define KFE_DELETING	0x0020			/* deletion in progress */
#define KFE_PROCESSING	0x0040			/* event processing in prog */
#define KFE_WAITING	0x0080			/* waiting on processing */
#define KFE_MARKER	0x0100			/* scan marker */

struct proc;
struct thread;
struct filedesc;
struct kevent_args;

typedef int	(*k_copyout_fn)(void *arg, struct kevent *kevp, int count,
    int *res);
typedef int	(*k_copyin_fn)(void *arg, struct kevent *kevp, int max,
    int *events);
int kern_kevent(struct kqueue *kq, int nevents, int *res, void *uap,
    k_copyin_fn kevent_copyin, k_copyout_fn kevent_copyout,
    struct timespec *tsp);

extern void	kev_dev_filter_init(cdev_t cdev, struct kev_filter_ops *fops,
    caddr_t hook);
extern void	kev_filter_init(struct kev_filter *filter,
    struct kev_filter_ops *fops, caddr_t hook);
extern void	kev_dev_filter_destroy(cdev_t cdev);
extern void	kev_filter_destroy(struct kev_filter *filter);
extern void	kev_filter(struct kev_filter *filter, long hint);

extern void	kev_filter_entry_fdclose(struct file *fp, struct filedesc *fdp,
    int fd);

extern void	kqueue_init(struct kqueue *kq, struct filedesc *fdp);
extern void	kqueue_terminate(struct kqueue *kq);
extern int 	kqueue_register(struct kqueue *kq, struct kevent *kev);

#endif 	/* _KERNEL */

#if !defined(_KERNEL) || defined(_KERNEL_VIRTUAL)

#include <sys/cdefs.h>
struct timespec;

__BEGIN_DECLS
int     kqueue (void);
int     kevent (int, const struct kevent *, int, struct kevent *,
		int, const struct timespec *);
__END_DECLS
#endif /* !_KERNEL */

#endif /* !_SYS_EVENT_H_ */
