/*
 * SYS/MPLOCK2.H
 *
 * Implement the MP lock.  Note that debug operations
 */
#ifndef _SYS_MPLOCK2_H_
#define _SYS_MPLOCK2_H_

#ifndef _MACHINE_ATOMIC_H_
#include <machine/atomic.h>
#endif
#ifndef _SYS_THREAD_H_
#include <sys/thread.h>
#endif
#ifndef _SYS_GLOBALDATA_H_
#include <sys/globaldata.h>
#endif

#ifdef SMP

#define get_mplock()		get_mplock_debug(__FILE__, __LINE__)
#define try_mplock()		try_mplock_debug(__FILE__, __LINE__)
#define cpu_try_mplock()	cpu_try_mplock_debug(__FILE__, __LINE__)

void _get_mplock_contested(const char *file, int line);
void _try_mplock_contested(const char *file, int line);
void _cpu_try_mplock_contested(const char *file, int line);
void _rel_mplock_contested(void);
void cpu_get_initial_mplock(void);
void cpu_mplock_contested(void);
void yield_mplock(struct thread *td);

extern int mp_lock;
extern int mp_lock_contention_mask;
extern const char *mp_lock_holder_file;
extern int mp_lock_holder_line;

/*
 * Acquire the MP lock, block until we get it.
 *
 * In order to acquire the MP lock we must first pre-dispose td_mpcount
 * for the acquisition and then get the actual lock.
 *
 * The contested function is called only if we do not have or are unable
 * to acquire the actual lock.  It will not return until the lock has
 * been acquired.
 */
static __inline
void
get_mplock_debug(const char *file, int line)
{
	globaldata_t gd = mycpu;
	thread_t td = gd->gd_curthread;

	++td->td_mpcount;
	if (mp_lock != gd->gd_cpuid) {
		if (atomic_cmpset_int(&mp_lock, -1, gd->gd_cpuid) == 0)
			_get_mplock_contested(file, line);
#ifdef INVARIANTS
		mp_lock_holder_file = file;
		mp_lock_holder_line = line;
#endif
	}
}

/*
 * Release the MP lock
 *
 * In order to release the MP lock we must first pre-dispose td_mpcount
 * for the release and then, if it is 0, release the actual lock.
 *
 * The contested function is called only if we are unable to release the
 * Actual lock.  This can occur if we raced an interrupt after decrementing
 * td_mpcount to 0 and the interrupt acquired and released the lock.
 *
 * The function also catches the td_mpcount underflow case because the
 * lock will be in a released state and thus fail the subsequent release.
 */
static __inline
void
rel_mplock(void)
{
	globaldata_t gd = mycpu;
	thread_t td = gd->gd_curthread;
	int n;

	n = --td->td_mpcount;
	if (n <= 0 && atomic_cmpset_int(&mp_lock, gd->gd_cpuid, -1) == 0)
		_rel_mplock_contested();
}

/*
 * Attempt to acquire the MP lock, returning 0 on failure and 1 on success.
 *
 * The contested function is called on failure and typically serves simply
 * to log the attempt (if debugging enabled).
 */
static __inline
int
try_mplock_debug(const char *file, int line)
{
	globaldata_t gd = mycpu;
	thread_t td = gd->gd_curthread;

	++td->td_mpcount;
	if (mp_lock != gd->gd_cpuid &&
	    atomic_cmpset_int(&mp_lock, -1, gd->gd_cpuid) == 0) {
		_try_mplock_contested(file, line);
		return(0);
	}
#ifdef INVARIANTS
	mp_lock_holder_file = file;
	mp_lock_holder_line = line;
#endif
	return(1);
}

/*
 * Low level acquisition of the MP lock ignoring curthred->td_mpcount
 *
 * This version of try_mplock() is used when the caller has already
 * predisposed td->td_mpcount.
 *
 * Returns non-zero on success, 0 on failure.
 *
 * WARNING: Must be called from within a critical section if td_mpcount is
 *	    zero, otherwise an itnerrupt race can cause the lock to be lost.
 */
static __inline
int
cpu_try_mplock_debug(const char *file, int line)
{
	globaldata_t gd = mycpu;

	if (mp_lock != gd->gd_cpuid &&
	    atomic_cmpset_int(&mp_lock, -1, gd->gd_cpuid) == 0) {
		_cpu_try_mplock_contested(file, line);
		return(0);
	}
#ifdef INVARIANTS
	mp_lock_holder_file = file;
	mp_lock_holder_line = line;
#endif
	return(1);
}

/*
 * A cpu wanted the MP lock but could not get it.  This function is also
 * called directly from the LWKT scheduler.
 *
 * Reentrant, may be called even if the cpu is already contending the MP
 * lock.
 */
static __inline
void
set_mplock_contention_mask(globaldata_t gd)
{
	atomic_set_int(&mp_lock_contention_mask, gd->gd_cpumask);
}

/*
 * A cpu is no longer contending for the MP lock after previously contending
 * for it.
 *
 * Reentrant, may be called even if the cpu was not previously contending
 * the MP lock.
 */
static __inline
void
clr_mplock_contention_mask(globaldata_t gd)
{
	atomic_clear_int(&mp_lock_contention_mask, gd->gd_cpumask);
}

static __inline
int
owner_mplock(void)
{
	return (mp_lock);
}

/*
 * Low level release of the MP lock ignoring curthread->td_mpcount
 *
 * WARNING: Caller must be in a critical section, otherwise the
 *	    mp_lock can be lost from an interrupt race and we would
 *	    end up clearing someone else's lock.
 */
static __inline void
cpu_rel_mplock(void)
{
	mp_lock = -1;
}

#define MP_LOCK_HELD()		\
	(mp_lock == mycpu->gd_cpuid)
#define ASSERT_MP_LOCK_HELD(td)	\
	KASSERT(MP_LOCK_HELD(), ("MP_LOCK_HELD: Not held thread %p", td))

#else

/*
 * UNI-PROCESSOR BUILD - Degenerate case macros
 */
#define	get_mplock()
#define	rel_mplock()
#define try_mplock()		1
#define owner_mplock()		0
#define MP_LOCK_HELD()		(!0)
#define ASSERT_MP_LOCK_HELD(td)

#endif

#endif