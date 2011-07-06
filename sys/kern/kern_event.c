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
 * $FreeBSD: src/sys/kern/kern_event.c,v 1.2.2.10 2004/04/04 07:03:14 cperciva Exp $
 * $DragonFly: src/sys/kern/kern_event.c,v 1.33 2007/02/03 17:05:57 corecode Exp $
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/malloc.h> 
#include <sys/unistd.h>
#include <sys/file.h>
#include <sys/lock.h>
#include <sys/fcntl.h>
#include <sys/queue.h>
#include <sys/event.h>
#include <sys/eventvar.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/sysproto.h>
#include <sys/thread.h>
#include <sys/uio.h>
#include <sys/signalvar.h>
#include <sys/filio.h>
#include <sys/ktr.h>
#include <sys/conf.h>			/* struct cdev */

#include <sys/thread2.h>
#include <sys/file2.h>
#include <sys/mplock2.h>

/*
 * Global token for kqueue subsystem
 */
struct lwkt_token kq_token = LWKT_TOKEN_INITIALIZER(kq_token);
SYSCTL_LONG(_lwkt, OID_AUTO, kq_collisions,
    CTLFLAG_RW, &kq_token.t_collisions, 0,
    "Collision counter of kq_token");

MALLOC_DEFINE(M_KQUEUE, "kqueue", "memory for kqueue system");

struct kevent_copyin_args {
	struct kevent_args	*ka;
	int			pchanges;
};

static int	kqueue_sleep(struct kqueue *kq, struct timespec *tsp);
static int	kqueue_scan(struct kqueue *kq, struct kevent *kevp, int count,
		    struct kev_filter_entry *marker);
static int 	kqueue_read(struct file *fp, struct uio *uio,
		    struct ucred *cred, int flags);
static int	kqueue_write(struct file *fp, struct uio *uio,
		    struct ucred *cred, int flags);
static int	kqueue_ioctl(struct file *fp, u_long com, caddr_t data,
		    struct ucred *cred, struct sysmsg *msg);
//static int 	kqueue_kqfilter(struct file *fp, struct knote *kn);
static int 	kqueue_stat(struct file *fp, struct stat *st,
		    struct ucred *cred);
static int 	kqueue_close(struct file *fp);
static void	kqueue_wakeup(struct kqueue *kq);
static int	poll_filter_entry(struct kev_filter_entry *fe,
		    short filter_type, long hint);

/*
 * MPSAFE
 */
static struct fileops kqueueops = {
	.fo_read = kqueue_read,
	.fo_write = kqueue_write,
	.fo_ioctl = kqueue_ioctl,
	.fo_stat = kqueue_stat,
	.fo_close = kqueue_close,
	.fo_shutdown = nofo_shutdown
};

static void	kev_filter_entry_drop(struct kev_filter_entry *fe);
static void	kev_filter_entry_enqueue(struct kev_filter_entry *fe);
static struct 	kev_filter_entry *kev_filter_entry_alloc(void);
static void	kev_filter_entry_free(struct kev_filter_entry *fe);
static struct 	kev_filter_note *kev_filter_note_alloc(void);
static void	kev_filter_note_free(struct kev_filter_note *fn);

//static int 		kq_ncallouts = 0;
static int 		kq_calloutmax = (4 * 1024);
SYSCTL_INT(_kern, OID_AUTO, kq_calloutmax, CTLFLAG_RW,
    &kq_calloutmax, 0, "Maximum number of callouts allocated for kqueue");
static int		kq_checkloop = 1000000;
SYSCTL_INT(_kern, OID_AUTO, kq_checkloop, CTLFLAG_RW,
    &kq_checkloop, 0, "Maximum number of callouts allocated for kqueue");

#define KEV_FILTER_ENTRY_ACTIVATE(fe) do { 				\
	fe->fe_status |= KFE_ACTIVE;					\
	if ((fe->fe_status & (KFE_QUEUED | KFE_DISABLED)) == 0)		\
		kev_filter_entry_enqueue(fe);				\
} while(0)

#define	KFE_HASHSIZE		64		/* XXX should be tunable */
#define KFE_HASH(val, mask)	(((val) ^ (val >> 8)) & (mask))


/*
 *
 */
static
int
file_vector_lookup(struct kev_filter **filt, struct kev_filter_note *fn, void *arg)
{
	struct file *fp = (struct file *)arg;

	return (fo_kev_filter(fp, filt));
}

/* filt_procattach (formerly) */
static
int
proc_vector_lookup(struct kev_filter **filt, struct kev_filter_note *fn, void *arg)
{
	return (EOPNOTSUPP);
}

static
int
signal_vector_lookup(struct kev_filter **filt, struct kev_filter_note *fn, void *arg)
{
	return (EOPNOTSUPP);
}

/* filt_timerattach (formerly) */
static
int
timer_vector_lookup(struct kev_filter **filt, struct kev_filter_note *fn, void *arg)
{
	return (EOPNOTSUPP);
}

/*
 * Acquire a filter event, return non-zero on success, 0 on failure.
 *
 * If we cannot acquire the fevent we sleep and return 0.  The fevent
 * may be stale on return in this case and the caller must restart
 * whatever loop they are in.
 */
static __inline
int
kev_filter_entry_acquire(struct kev_filter_entry *fe)
{
	if (fe->fe_status & KFE_PROCESSING) {
		fe->fe_status |= KFE_WAITING | KFE_REPROCESS;
		tsleep(fe, 0, "kqepts", hz);
		/* filter entry may be stale now */
		return (0);
	}
	fe->fe_status |= KFE_PROCESSING;
	return (1);
}

/*
 * Release an acquired filter entry, clearing KFE_PROCESSING and handling
 * any KFE_REPROCESS events.
 *
 * Non-zero is returned if the filter entry is destroyed.
 */
static __inline
int
kev_filter_entry_release(struct kev_filter_entry *fe)
{
	while (fe->fe_status & KFE_REPROCESS) {
		fe->fe_status &= ~KFE_REPROCESS;
		if (fe->fe_status & KFE_WAITING) {
			fe->fe_status &= ~KFE_WAITING;
			wakeup(fe);
		}
		if (fe->fe_status & KFE_DELETING) {
			kev_filter_entry_drop(fe);
			return (1);
			/* NOT REACHED */
		}
		if (poll_filter_entry(fe, 0, 0))
			KEV_FILTER_ENTRY_ACTIVATE(fe);
	}
	fe->fe_status &= ~KFE_PROCESSING;
	return (0);
}

/*
 * Initialize a kqueue.
 *
 * NOTE: The lwp/proc code initializes a kqueue for select/poll ops.
 */
void
kqueue_init(struct kqueue *kq, struct filedesc *fdp)
{
	TAILQ_INIT(&kq->kq_fepending);
	TAILQ_INIT(&kq->kq_felist);
	kq->kq_count = 0;
	kq->kq_fdp = fdp;

/* XXX,SJG
   We need to re-implement kqueue support for kqueue itself
	SLIST_INIT(&kq->kq_kqinfo.ki_note); */
}

/*
 * Terminate a kqueue.  Freeing the actual kq itself is left up to the
 * caller (it might be embedded in a lwp so we don't do it here).
 *
 * The kq's felist must be completely eradicated so block on any
 * processing races.
 */
void
kqueue_terminate(struct kqueue *kq)
{
	struct kev_filter_entry *fe;

	lwkt_gettoken(&kq_token);
	while ((fe = TAILQ_FIRST(&kq->kq_felist)) != NULL) {
		if (kev_filter_entry_acquire(fe))
			kev_filter_entry_drop(fe);
	}
	if (kq->kq_fehash) {
		kfree(kq->kq_fehash, M_KQUEUE);
		kq->kq_fehash = NULL;
		kq->kq_fehashmask = 0;
	}
	lwkt_reltoken(&kq_token);
}

/*
 * MPSAFE
 */
int
sys_kqueue(struct kqueue_args *uap)
{
	struct thread *td = curthread;
	struct kqueue *kq;
	struct file *fp;
	int fd, error;

	error = falloc(td->td_lwp, &fp, &fd);
	if (error)
		return (error);
	fp->f_flag = FREAD | FWRITE;
	fp->f_type = DTYPE_KQUEUE;
	fp->f_ops = &kqueueops;

	kq = kmalloc(sizeof(struct kqueue), M_KQUEUE, M_WAITOK | M_ZERO);
	kqueue_init(kq, td->td_proc->p_fd);
	fp->f_data = kq;

	fsetfd(kq->kq_fdp, fp, fd);
	uap->sysmsg_result = fd;
	fdrop(fp);
	return (error);
}

/*
 * Copy 'count' items into the destination list pointed to by uap->eventlist.
 */
static int
kevent_copyout(void *arg, struct kevent *kevp, int count, int *res)
{
	struct kevent_copyin_args *kap;
	int error;

	kap = (struct kevent_copyin_args *)arg;

	error = copyout(kevp, kap->ka->eventlist, count * sizeof(*kevp));
	if (error == 0) {
		kap->ka->eventlist += count;
		*res += count;
	} else {
		*res = -1;
	}

	return (error);
}

/*
 * Copy at most 'max' items from the list pointed to by kap->changelist,
 * return number of items in 'events'.
 */
static int
kevent_copyin(void *arg, struct kevent *kevp, int max, int *events)
{
	struct kevent_copyin_args *kap;
	int error, count;

	kap = (struct kevent_copyin_args *)arg;

	count = min(kap->ka->nchanges - kap->pchanges, max);
	error = copyin(kap->ka->changelist, kevp, count * sizeof *kevp);
	if (error == 0) {
		kap->ka->changelist += count;
		kap->pchanges += count;
		*events = count;
	}

	return (error);
}

/*
 * MPSAFE
 */
int
kern_kevent(struct kqueue *kq, int nevents, int *res, void *uap,
	    k_copyin_fn kevent_copyinfn, k_copyout_fn kevent_copyoutfn,
	    struct timespec *tsp_in)
{
	struct kevent *kevp;
	struct timespec *tsp;
	int i, n, total, error, nerrors = 0;
	int lres;
	int limit = kq_checkloop;
	struct kevent kev[KQ_NEVENTS];
	struct kev_filter_entry marker;
	struct kev_filter_note *fn;

	tsp = tsp_in;
	*res = 0;

	lwkt_gettoken(&kq_token);
	for ( ;; ) {
		n = 0;
		error = kevent_copyinfn(uap, kev, KQ_NEVENTS, &n);
		if (error)
			goto done;
		if (n == 0)
			break;
		for (i = 0; i < n; i++) {
			kevp = &kev[i];
			kevp->flags &= ~EV_SYSFLAGS;

			fn = kev_filter_note_alloc();
			if (fn == NULL) {
				error = ENOMEM;
			} else {
				fn->fn_filter = kevp->filter;
				fn->fn_ufflags = kevp->fflags;
				fn->fn_udata = (intptr_t)kevp->udata;
				error = kqueue_register_filter_note(kq,
				    kevp->ident, fn);
			}

			/*
			 * If a registration returns an error we
			 * immediately post the error.  The kevent()
			 * call itself will fail with the error if
			 * no space is available for posting.
			 *
			 * Such errors normally bypass the timeout/blocking
			 * code.  However, if the copyoutfn function refuses
			 * to post the error (see sys_poll()), then we
			 * ignore it too.
			 */
			if (error) {
				kev_filter_note_free(fn);
				kevp->flags = EV_ERROR;
				kevp->data = error;
				lres = *res;
				kevent_copyoutfn(uap, kevp, 1, res);
				if (lres != *res) {
					nevents--;
					nerrors++;
				}
			}
		}
	}
	if (nerrors) {
		error = 0;
		goto done;
	}

	/*
	 * Acquire/wait for events - setup timeout
	 */
	if (tsp != NULL) {
		struct timespec ats;

		if (tsp->tv_sec || tsp->tv_nsec) {
			nanouptime(&ats);
			timespecadd(tsp, &ats);		/* tsp = target time */
		}
	}

	/*
	 * Loop as required.
	 *
	 * Collect as many events as we can. Sleeping on successive
	 * loops is disabled if copyoutfn has incremented (*res).
	 *
	 * The loop stops if an error occurs, all events have been
	 * scanned (the marker has been reached), or fewer than the
	 * maximum number of events is found.
	 *
	 * The copyoutfn function does not have to increment (*res) in
	 * order for the loop to continue.
	 *
	 * NOTE: doselect() usually passes 0x7FFFFFFF for nevents.
	 */
	total = 0;
	error = 0;
	marker.fe_status = KFE_PROCESSING | KFE_MARKER;
	TAILQ_INSERT_TAIL(&kq->kq_fepending, &marker, fe_entry);
	while ((n = nevents - total) > 0) {
		if (n > KQ_NEVENTS)
			n = KQ_NEVENTS;

		/*
		 * If no events are pending sleep until timeout (if any)
		 * or an event occurs.
		 *
		 * After the sleep completes the marker is moved to the
		 * end of the list, making any received events available
		 * to our scan.
		 */
		if (kq->kq_count == 0 && *res == 0) {
			error = kqueue_sleep(kq, tsp);
			if (error)
				break;

			TAILQ_REMOVE(&kq->kq_fepending, &marker, fe_entry);
			TAILQ_INSERT_TAIL(&kq->kq_fepending, &marker, fe_entry);
		}

		/*
		 * Process all received events
		 * Account for all non-spurious events in our total
		 */
		i = kqueue_scan(kq, kev, n, &marker);
		if (i) {
			lres = *res;
			error = kevent_copyoutfn(uap, kev, i, res);
			total += *res - lres;
			if (error)
				break;
		}
		if (limit && --limit == 0)
			panic("kqueue: checkloop failed i=%d", i);

		/*
		 * Normally when fewer events are returned than requested
		 * we can stop.  However, if only spurious events were
		 * collected the copyout will not bump (*res) and we have
		 * to continue.
		 */
		if (i < n && *res)
			break;

		/*
		 * Deal with an edge case where spurious events can cause
		 * a loop to occur without moving the marker.  This can
		 * prevent kqueue_scan() from picking up new events which
		 * race us.  We must be sure to move the marker for this
		 * case.
		 *
		 * NOTE: We do not want to move the marker if events
		 *	 were scanned because normal kqueue operations
		 *	 may reactivate events.  Moving the marker in
		 *	 that case could result in duplicates for the
		 *	 same event.
		 */
		if (i == 0) {
			TAILQ_REMOVE(&kq->kq_fepending, &marker, fe_entry);
			TAILQ_INSERT_TAIL(&kq->kq_fepending, &marker, fe_entry);
		}
	}
	TAILQ_REMOVE(&kq->kq_fepending, &marker, fe_entry);

	/* Timeouts do not return EWOULDBLOCK. */
	if (error == EWOULDBLOCK)
		error = 0;

done:
	lwkt_reltoken(&kq_token);
	return (error);
}

/*
 * MPALMOSTSAFE
 */
int
sys_kevent(struct kevent_args *uap)
{
	struct thread *td = curthread;
	struct proc *p = td->td_proc;
	struct timespec ts, *tsp;
	struct kqueue *kq;
	struct file *fp = NULL;
	struct kevent_copyin_args *kap, ka;
	int error;

	if (uap->timeout) {
		error = copyin(uap->timeout, &ts, sizeof(ts));
		if (error)
			return (error);
		tsp = &ts;
	} else {
		tsp = NULL;
	}

	fp = holdfp(p->p_fd, uap->fd, -1);
	if (fp == NULL)
		return (EBADF);
	if (fp->f_type != DTYPE_KQUEUE) {
		fdrop(fp);
		return (EBADF);
	}

	kq = (struct kqueue *)fp->f_data;

	kap = &ka;
	kap->ka = uap;
	kap->pchanges = 0;

	error = kern_kevent(kq, uap->nevents, &uap->sysmsg_result, kap,
			    kevent_copyin, kevent_copyout, tsp);

	fdrop(fp);

	return (error);
}

/*
 * Convert EVFILT_* filter to 0-base index and return the proper note
 * reference.
 */
/*
static
struct kev_filter_note *
kev_filter_entry_get_note(struct kev_filter_entry *fe, short filter)
{
	return (fe->fe_notes[~filter]);
}
*/

/*
 * ...
 */
//static
//struct kev_filter_op *
//kev_filter_entry_get_vector(struct kev_filter_entry *fe, short filter)
//{
//	struct kev_filter_op *ops[EVFILT_SYSCOUNT] = {
//	    &fe->fe_filter->kf_ops->fop_read,		/* EVFILT_READ */
//	    &fe->fe_filter->kf_ops->fop_write,		/* EVFILT_WRITE */
//	    NULL,					/* EVFILT_AIO */
//	    &fe->fe_filter->kf_ops->fop_special,	/* EVFILT_VNODE */
//	    &fe->fe_filter->kf_ops->fop_special,	/* EVFILT_PROC */
//	    &fe->fe_filter->kf_ops->fop_special,	/* EVFILT_SIGNAL */
//	    &fe->fe_filter->kf_ops->fop_special,	/* EVFILT_TIMER */
//	    &fe->fe_filter->kf_ops->fop_special		/* EVFILT_EXCEPT */
//	};
//
//	return (ops[~filter]);
//}

/*
 * Look up a filter event and acquire it, caller is responsible for releasing
 * the filter event with kev_filter_entry_release().
 */
struct kev_filter_entry *
kqueue_lookup_filter_entry(struct kqueue *kq, uintptr_t ident, struct file *fp)
{
	struct kev_filter_entry *fe = NULL;

	lwkt_gettoken(&kq_token);
	if (fp != NULL) {
again1:
		TAILQ_FOREACH(fe, &fp->f_kflist, fe_link) {
			if (fe->fe_kq == kq &&
			    fe->fe_ident == ident) {
				if (kev_filter_entry_acquire(fe) == 0)
					goto again1;
				break;
			}
		}
	} else {
		if (kq->kq_fehashmask) {
			struct kev_filter_entry_list *list;

			list = &kq->kq_fehash[
			    KFE_HASH((u_long)ident, kq->kq_fehashmask)];
again2:
			TAILQ_FOREACH(fe, list, fe_link) {
				if (fe->fe_ident ==ident) {
					if (kev_filter_entry_acquire(fe) == 0)
						goto again2;
					break;
				}
			}
		}
	}
	lwkt_reltoken(&kq_token);

	return (fe);
}

int
kqueue_register_filter_note(struct kqueue *kq, uintptr_t ident,
    struct kev_filter_note *fn)
{
	struct filedesc *fdp = kq->kq_fdp;
	struct kev_filter_entry *fe;
	struct file *fp = NULL;
	struct kev_filter *filter;
	u_int filter_idx;
	int error = 0;

	int (*vector_lookup)(struct kev_filter **, struct kev_filter_note *, void *);
	void *vector_lookup_arg;
	boolean_t isfd;


	if (fn->fn_filter > 0 || fn->fn_filter + EVFILT_SYSCOUNT <= 0)
		return (EINVAL);	/* unknown or invalid filter */
	filter_idx = ~fn->fn_filter;	

	/*
	 * Set up some defaults to minimize redundancy in the following switch.
	 */
	vector_lookup = file_vector_lookup;
	isfd = FALSE;			/* does not represent an fd */

	/*
	 * Set up the correct vector lookup for the filter note and
	 * determine if we will be representing a file descriptor or not,
	 */
	switch (fn->fn_filter) {
	case EVFILT_READ:
		isfd = TRUE;
		break;
	case EVFILT_WRITE:
		isfd = TRUE;
		break;
	case EVFILT_VNODE:
	case EVFILT_EXCEPT:
		isfd = TRUE;
		break;
	case EVFILT_PROC:
		vector_lookup = proc_vector_lookup;
		break;
	case EVFILT_SIGNAL:
		vector_lookup = signal_vector_lookup;
		break;
	case EVFILT_TIMER:
		vector_lookup = timer_vector_lookup;
		break;
	case EVFILT_AIO:
		return (ENXIO);		/* not implemented */
		/* NOT REACHED */
	}

	/*
	 * Validate descriptor
	 */
	if (isfd) {
		fp = holdfp(fdp, ident, -1);
		if (fp == NULL)
			return (EBADF);
	}

	fe = kqueue_lookup_filter_entry(kq, ident, fp);

	/*
	 * NOTE: At this point if fe is non-NULL we will have acquired
	 *	 it and set KFE_PROCESSING.
	 */
	if (fe == NULL && ((fn->fn_ufflags & EV_ADD) == 0)) {
		error = ENOENT;
		goto done;
	}

	/*
	 * fe now contains the matching filter_entry, or NULL if no match
	 */
	if (fn->fn_ufflags & EV_ADD) {
		if (fe == NULL) {
			if (isfd)
				vector_lookup_arg = fp;
			else
				vector_lookup_arg = NULL;

			/*
			 * Look up the vector and validate that it supports
			 * the operations we need.
			 */
			error = vector_lookup(&filter, fn, vector_lookup_arg);
			if (error != 0)
				goto done;

			fe = kev_filter_entry_alloc();
			if (fe == NULL) {
				error = ENOMEM;
				goto done;
			}

			/*
			 * Initialize the filter event
			 */
			fe->fe_ident = ident;
			fe->fe_fd = isfd;
			fe->fe_kq = kq;
			fe->fe_filter = filter;

			/*
			 * Apply reference count to knote structure and
			 * do not release it at the end of this routine.
			 */
			fe->fe_ptr.p_fp = fp;
			fp = NULL;

			/*
			 * Slot in the filter note
			 */
			fe->fe_notes[filter_idx] = fn;

			/*
			 * KFE_PROCESSING prevents the knote from getting
			 * ripped out from under us while we are trying
			 * to attach it, in case the attach blocks.
			 */
			fe->fe_status = KFE_PROCESSING;

/* We already know whether it is an fd or not below, it is set in the kev_filter_entry (fe_fd) */
/*
        struct klist *list;
        struct kqueue *kq = kn->kn_kq;

        if (isfd) {
                KKASSERT(kn->kn_fp);
                list = &kn->kn_fp->f_klist;
        } else {
                if (kq->kq_fehashmask == 0)
                        kq->kq_fehash = hashinit(KFE_HASHSIZE, M_KQUEUE,
                                                 &kq->kq_fehashmask);
                list = &kq->kq_fehash[KFE_HASH(kn->kn_id, kq->kq_fehashmask)];
        }
        SLIST_INSERT_HEAD(list, kn, kn_link);
        TAILQ_INSERT_HEAD(&kq->kq_knlist, kn, kn_kqlink);
*/

			/*
			 * Interlock against close races which we may have
			 * missed, we do not want to end up with a filter event
			 * hanging from a closed descriptor.
			 */
			if ((isfd) && checkfdclosed(fdp, ident, fe->fe_ptr.p_fp)) {
				fe->fe_status |= KFE_DELETING | KFE_REPROCESS;
			}
		} else {
			/*
			 * Handle changing various filter values after the
			 * initial EV_ADD, but doing so will not reset any
			 * filter which have already been triggered.
			 */
/* ??? */		KKASSERT(fe->fe_status & KFE_PROCESSING);

			fe->fe_notes[filter_idx]->fn_ufflags = fn->fn_ufflags;
			fe->fe_notes[filter_idx]->fn_udata = fn->fn_udata;

			/*
			 * We no longer need the note allocated in the calling
			 * function, we updated the existing note.
			 */
                        kev_filter_note_free(fn);
		}

		/*
		 * Execute the filter event to immediately activate the
		 * knote if necessary.  If reprocessing events are pending
		 * due to blocking above we do not run the filter here
		 * but instead let kev_filter_entry_release() do it.  Otherwise
		 * we might run the filter on a deleted event.
		 */
		if ((fe->fe_status & KFE_REPROCESS) == 0) {
			if (poll_filter_entry(fe, 0, 0))
				KEV_FILTER_ENTRY_ACTIVATE(fe);
		}
	} else if (fn->fn_ufflags & EV_DELETE) {
		/*
		 * Delete existing kev_filter_entry and associated
		 * kev_filter_note's.
		 */
		kev_filter_entry_drop(fe);
		goto done;
	}



/* XXX, SJG: REWRITE ... */

	/*
	 * Disablement does not deactivate a knote here.
	 */
/*	if ((kev->flags & EV_DISABLE) &&
	    ((kn->kn_status & KN_DISABLED) == 0)) {
		kn->kn_status |= KN_DISABLED;
	}
*/
	/*
	 * Re-enablement may have to immediately enqueue an active knote.
	 */
/*	if ((kev->flags & EV_ENABLE) && (kn->kn_status & KN_DISABLED)) {
		kn->kn_status &= ~KN_DISABLED;
		if ((kn->kn_status & KN_ACTIVE) &&
		    ((kn->kn_status & KN_QUEUED) == 0)) {
			knote_enqueue(kn);
		}
	}
*/

	/*
	 * Handle any required reprocessing
	 */
	kev_filter_entry_release(fe);
	/* kn may be invalid now */

done:
	lwkt_reltoken(&kq_token);
	if (fp != NULL)
		fdrop(fp);
	return (error);
}

/*
 * Block as necessary until the target time is reached.
 * If tsp is NULL we block indefinitely.  If tsp->ts_secs/nsecs are both
 * 0 we do not block at all.
 */
static int
kqueue_sleep(struct kqueue *kq, struct timespec *tsp)
{
	int error = 0;

	if (tsp == NULL) {
		kq->kq_state |= KQ_SLEEP;
		error = tsleep(kq, PCATCH, "kqread", 0);
	} else if (tsp->tv_sec == 0 && tsp->tv_nsec == 0) {
		error = EWOULDBLOCK;
	} else {
		struct timespec ats;
		struct timespec atx = *tsp;
		int timeout;

		nanouptime(&ats);
		timespecsub(&atx, &ats);
		if (ats.tv_sec < 0) {
			error = EWOULDBLOCK;
		} else {
			timeout = atx.tv_sec > 24 * 60 * 60 ?
				24 * 60 * 60 * hz : tstohz_high(&atx);
			kq->kq_state |= KQ_SLEEP;
			error = tsleep(kq, PCATCH, "kqread", timeout);
		}
	}

	/* don't restart after signals... */
	if (error == ERESTART)
		return (EINTR);

	return (error);
}

/*
 * Scan the kqueue, return the number of active events placed in kevp up
 * to count.
 *
 * Continuous mode events may get recycled, do not continue scanning past
 * marker unless no events have been collected.
 */
static int
kqueue_scan(struct kqueue *kq, struct kevent *kevp, int count,
            struct kev_filter_entry *marker)
{
        struct kev_filter_entry *fe, local_marker;
	struct kev_filter_note *fn;
        int total, i;

        total = 0;
	local_marker.fe_status = KFE_PROCESSING | KFE_MARKER;

	/*
	 * Collect events.
	 */
	TAILQ_INSERT_HEAD(&kq->kq_fepending, &local_marker, fe_entry);
	while (count) {
		fe = TAILQ_NEXT(&local_marker, fe_entry);
		if (fe->fe_status & KFE_MARKER) {
			/* Marker reached, we are done */
			if (fe == marker)
				break;

			/* Move local marker past some other threads marker */
			fe = TAILQ_NEXT(fe, fe_entry);
			TAILQ_REMOVE(&kq->kq_fepending, &local_marker, fe_entry);
			TAILQ_INSERT_BEFORE(fe, &local_marker, fe_entry);
			continue;
		}

		/*
		 * We can't skip a knote undergoing processing, otherwise
		 * we risk not returning it when the user process expects
		 * it should be returned.  Sleep and retry.
		 */
		if (kev_filter_entry_acquire(fe) == 0)
			continue;

		/*
		 * Remove the event for processing.
		 *
		 * WARNING!  We must leave KN_QUEUED set to prevent the
		 *	     event from being KNOTE_ACTIVATE()d while
		 *	     the queue state is in limbo, in case we
		 *	     block.
		 *
		 * WARNING!  We must set KN_PROCESSING to avoid races
		 *	     against deletion or another thread's
		 *	     processing.
		 */
		TAILQ_REMOVE(&kq->kq_fepending, fe, fe_entry);
		kq->kq_count--;

		/*
		 * We have to deal with an extremely important race against
		 * file descriptor close()s here.  The file descriptor can
		 * disappear MPSAFE, and there is a small window of
		 * opportunity between that and the call to
		 * kev_filter_entry_fdclose().
		 *
		 * If we hit that window here while doselect or dopoll is
		 * trying to delete a spurious event they will not be able
		 * to match up the event against a knote and will go haywire.
		 */
		if ((fe->fe_fd) &&
		    checkfdclosed(kq->kq_fdp, fe->fe_ident, fe->fe_ptr.p_fp)) {
			fe->fe_status |= KFE_DELETING | KFE_REPROCESS;
		}

		if (fe->fe_status & KFE_DISABLED) {
			/*
			 * If disabled we ensure the event is not queued
			 * but leave its active bit set.  On re-enablement
			 * the event may be immediately triggered.
			 */
			fe->fe_status &= ~KFE_QUEUED;
/* XXX, SJG: kn_flags! */

		} else {
			for (i = 0; i < EVFILT_SYSCOUNT; ++i) {
				if (fe->fe_notes[i] != NULL) {
					fn = fe->fe_notes[i];

					if ((fn->fn_flags & EV_ONESHOT) == 0 &&
					    (fe->fe_status & KFE_DELETING) == 0 &&
					    poll_filter_entry(fe, 0, 0) == 0) {
						/*
						 * If not running in one-shot mode and
						 * the event is no longer present we
						 * ensure it is removed from the queue
						 * and ignore it.
						 */
//						fe->fe_status &= ~(KFE_QUEUED | KFE_ACTIVE);
/*
XXX, SJG:
Might have to filter these out soemwhere else?
*/
					} else {
						/*
						 * Post the event(s)
						 */
						kevp->ident = fe->fe_ident;
						kevp->filter = fn->fn_filter;
						kevp->flags = fn->fn_flags;
						kevp->fflags = fn->fn_fflags;
						kevp->data = fn->fn_data;
						kevp->udata = (void *)fn->fn_udata;
						kevp++;
						++total;
						--count;

						if (fn->fn_flags & EV_ONESHOT) {
//							fe->fe_status &= ~KFE_QUEUED;
//							fe->fe_status |= KFE_DELETING | KFE_REPROCESS;
/*
XXX, SJG:
Can't nuke the whole event for a single note ...
move oneshot into the note..?
*/
						} else if (fn->fn_flags & EV_CLEAR) {
							fn->fn_data = 0;
							fn->fn_fflags = 0;
							fe->fe_status &= ~(KFE_QUEUED | KFE_ACTIVE);
						} else {
							TAILQ_INSERT_TAIL(&kq->kq_fepending, fe, fe_entry);
							kq->kq_count++;
						}
					}
				}
			}
		}


		/*
		 * Handle any post-processing states
		 */
		kev_filter_entry_release(fe);
	}
	TAILQ_REMOVE(&kq->kq_fepending, &local_marker, fe_entry);

	return (total);
}

/*
 * XXX
 * This could be expanded to call kqueue_scan, if desired.
 *
 * MPSAFE
 */
static int
kqueue_read(struct file *fp, struct uio *uio, struct ucred *cred, int flags)
{
	return (ENXIO);
}

/*
 * MPSAFE
 */
static int
kqueue_write(struct file *fp, struct uio *uio, struct ucred *cred, int flags)
{
	return (ENXIO);
}

/*
 * MPALMOSTSAFE
 */
static int
kqueue_ioctl(struct file *fp, u_long com, caddr_t data,
	     struct ucred *cred, struct sysmsg *msg)
{
	struct kqueue *kq;
	int error;

	lwkt_gettoken(&kq_token);
	kq = (struct kqueue *)fp->f_data;

	switch(com) {
	case FIOASYNC:
		if (*(int *)data)
			kq->kq_state |= KQ_ASYNC;
		else
			kq->kq_state &= ~KQ_ASYNC;
		error = 0;
		break;
	case FIOSETOWN:
		error = fsetown(*(int *)data, &kq->kq_sigio);
		break;
	default:
		error = ENOTTY;
		break;
	}
	lwkt_reltoken(&kq_token);
	return (error);
}

/*
 * MPSAFE
 */
static int
kqueue_stat(struct file *fp, struct stat *st, struct ucred *cred)
{
	struct kqueue *kq = (struct kqueue *)fp->f_data;

	bzero((void *)st, sizeof(*st));
	st->st_size = kq->kq_count;
	st->st_blksize = sizeof(struct kevent);
	st->st_mode = S_IFIFO;
	return (0);
}

/*
 * MPSAFE
 */
static int
kqueue_close(struct file *fp)
{
	struct kqueue *kq = (struct kqueue *)fp->f_data;

	kqueue_terminate(kq);

	fp->f_data = NULL;
	funsetown(&kq->kq_sigio);

	kfree(kq, M_KQUEUE);
	return (0);
}

static void
kqueue_wakeup(struct kqueue *kq)
{
	if (kq->kq_state & KQ_SLEEP) {
		kq->kq_state &= ~KQ_SLEEP;
		wakeup(kq);
	}
	kev_filter(&kq->kq_kev_filter, 0, 0);
}

/*
 *
 */
static int
poll_filter_entry(struct kev_filter_entry *fe, short filter_type, long hint)
{
	struct kev_filter_note *notes[EVFILT_SYSCOUNT];
	struct kev_filter_note *fn;
	struct kev_filter_op *fop;
	int note_count, i, error;

	if (filter_type) {
		notes[0] = fe->fe_notes[~filter_type];
		note_count = 1;
	} else {
		for (i = 0, note_count = 0; i < EVFILT_SYSCOUNT; ++i) {
			if (fe->fe_notes[~i] != NULL) {
				notes[note_count] = fe->fe_notes[~i];
				++note_count;
			}
		}
	}

	for (i = 0; i < note_count; ++i) {
		fn = notes[i];

		switch (fn->fn_filter) {
		case EVFILT_READ:
			fop = &fe->fe_filter->kf_ops->fop_read;
			break;
		case EVFILT_WRITE:
			fop = &fe->fe_filter->kf_ops->fop_write;
			break;
		default:
			fop = &fe->fe_filter->kf_ops->fop_special;
			break;
		}

		if (fop->fo_flags & KEV_FILTOP_NOTMPSAFE) {
			get_mplock();
			fop->fo_event(notes[i], hint, fe->fe_filter->kf_hook);
			rel_mplock();
		} else {
			fop->fo_event(notes[i], hint, fe->fe_filter->kf_hook);
		}

		/* XXX, SJG:
			Accumulate the return values from fop()
			calls and return ...
		*/

	}	

/* XXX, SJG: */	error = 0;

	return (error);
}

void
kev_dev_filter_init(cdev_t cdev, struct kev_filter_ops *fops, caddr_t hook)
{
	kev_filter_init(cdev->si_filter, fops, hook);
}

void
kev_filter_init(struct kev_filter *filter, struct kev_filter_ops *fops,
	caddr_t hook)
{
	TAILQ_INIT(filter->kf_entry);
	filter->kf_ops = fops;
	filter->kf_hook = hook;
}

/*
 * Walk down a list of kev_filter_entry's, activating them if their event
 * has triggered.
 *
 * If we encounter any filter entries which are undergoing processing we just
 * mark them for reprocessing and do not try to [re]activate them.  However,
 * if a hint is being passed we have to wait and that makes things a bit
 * sticky.
 */
void
kev_filter(struct kev_filter *filter, short filter_type, long hint)
{
	struct kev_filter_entry *fe;

	lwkt_gettoken(&kq_token);
restart:
	TAILQ_FOREACH(fe, filter->kf_entry, fe_link) {
		if (fe->fe_status & KFE_PROCESSING) {
			/*
			 * Someone else is processing the filter event, ask
			 * the other thread to reprocess it and don't mess
			 * with it otherwise.
			 */
			if (hint == 0) {
				fe->fe_status |= KFE_REPROCESS;
				continue;
			}

			/*
			 * If the hint is non-zero we have to wait or risk
			 * losing the state the caller is trying to update.
			 *
			 * XXX This is a real problem, certain process
			 *     and signal filters will bump kn_data for
			 *     already-processed notes more than once if
			 *     we restart the list scan.  FIXME.
			 */
			fe->fe_status |= KFE_WAITING | KFE_REPROCESS;
			tsleep(fe, 0, "kfnc", hz);
			goto restart;
		}

		/*
		 * Become the reprocessing master ourselves.
		 *
		 * If hint is non-zero running the event is mandatory
		 * when not deleting so do it whether reprocessing is
		 * set or not.
		 */
		fe->fe_status |= KFE_PROCESSING;
		if ((fe->fe_status & KFE_DELETING) == 0) {

/* XXX: SJG, implement kev_filter_entry_activate */

			if (poll_filter_entry(fe, filter_type, hint))
				KEV_FILTER_ENTRY_ACTIVATE(fe);
		}
		if (kev_filter_entry_release(fe))
			goto restart;
	}
	lwkt_reltoken(&kq_token);
}

/*
 * Remove all filter events referencing a specified fd
 *
 * XXX: This only seems to be used from the descriptor code, perhaps
 * this could be made visible or implemented in a cleaner (in terms of
 * cross-subsystem calls) fashion.
 */
void
kev_filter_entry_fdclose(struct file *fp, struct filedesc *fdp, int fd)
{
	struct kev_filter_entry *fe;

	lwkt_gettoken(&kq_token);
restart:
	TAILQ_FOREACH(fe, &fp->f_kflist, fe_link) {
		if (fe->fe_kq->kq_fdp == fdp && fe->fe_ident == fd) {
			if (kev_filter_entry_acquire(fe))
				kev_filter_entry_drop(fe);
			goto restart;
		}
	}
	lwkt_reltoken(&kq_token);
}

/*
 *
 */
static void
kev_filter_entry_drop(struct kev_filter_entry *fe)
{
	struct kqueue *kq = fe->fe_kq;
	struct kev_filter_entry_list *list;
	int i;

/* XXX, SJG: this is a carryover -- why are we doing this immediately before free'ing? */
	fe->fe_status |= KFE_DELETING | KFE_REPROCESS;

	if (fe->fe_fd == TRUE)
		list = &fe->fe_ptr.p_fp->f_kflist;
	else
		list = &kq->kq_fehash[KFE_HASH(fe->fe_ident, kq->kq_fehashmask)];

	TAILQ_REMOVE(list, fe, fe_link);
	TAILQ_REMOVE(&kq->kq_felist, fe, fe_kqlink);
	if (fe->fe_status & KFE_QUEUED) {
		TAILQ_REMOVE(&kq->kq_fepending, fe, fe_entry);
		fe->fe_status &= ~KFE_QUEUED;
		fe->fe_kq->kq_count--;
	}
	if (fe->fe_fd == TRUE) {
		fdrop(fe->fe_ptr.p_fp);
		fe->fe_ptr.p_fp = NULL;
	}

	for (i = 0; i < EVFILT_SYSCOUNT; ++i)
		if (fe->fe_notes[i] != NULL)
			kev_filter_note_free(fe->fe_notes[i]);

	kev_filter_entry_free(fe);
}

/*
 *
 */
static void
kev_filter_entry_enqueue(struct kev_filter_entry *fe)
{
	struct kqueue *kq = fe->fe_kq;

	KASSERT((fe->fe_status & KFE_QUEUED) == 0, ("filter event already queued"));
	TAILQ_INSERT_TAIL(&kq->kq_fepending, fe, fe_entry);
	fe->fe_status |= KFE_QUEUED;
	++kq->kq_count;

	/*
	 * Send SIGIO on request (typically set up as a mailbox signal)
	 */
	if (kq->kq_sigio && (kq->kq_state & KQ_ASYNC) && kq->kq_count == 1)
		pgsigio(kq->kq_sigio, SIGIO, 0);

	kqueue_wakeup(kq);
}

static struct kev_filter_entry *
kev_filter_entry_alloc(void)
{
	return kmalloc(sizeof(struct kev_filter_entry), M_KQUEUE, M_WAITOK);
}

static void
kev_filter_entry_free(struct kev_filter_entry *fe)
{
	kfree(fe, M_KQUEUE);
}

static struct kev_filter_note *
kev_filter_note_alloc(void)
{
	return kmalloc(sizeof(struct kev_filter_note), M_KQUEUE, M_WAITOK);
}

static void
kev_filter_note_free(struct kev_filter_note *fn)
{
	kfree(fn, M_KQUEUE);
}

