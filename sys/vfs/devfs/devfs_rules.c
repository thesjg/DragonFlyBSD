/*
 * Copyright (c) 2009 The DragonFly Project.  All rights reserved.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Alex Hornung <ahornung@gmail.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of The DragonFly Project nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific, prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/ioccom.h>
#include <sys/fcntl.h>
#include <sys/device.h>
#include <sys/mount.h>
#include <vfs/devfs/devfs.h>
#include <vfs/devfs/devfs_rules.h>

MALLOC_DECLARE(M_DEVFS);


static int WildCmp(const char *w, const char *s);
static int WildCaseCmp(const char *w, const char *s);
static int wildCmp(const char **mary, int d, const char *w, const char *s);
static int wildCaseCmp(const char **mary, int d, const char *w, const char *s);

static d_open_t      devfs_dev_open;
static d_close_t     devfs_dev_close;
static d_ioctl_t     devfs_dev_ioctl;

static struct devfs_rule *devfs_rule_alloc(struct devfs_rule *);
static void devfs_rule_free(struct devfs_rule *);
static void devfs_rule_insert(struct devfs_rule *);
static void devfs_rule_remove(struct devfs_rule *);
static void devfs_rule_clear(struct devfs_rule *);

static int devfs_rule_checkname(struct devfs_rule *, struct devfs_node *);

static struct objcache	*devfs_rule_cache;
static struct lock 		devfs_rule_lock;

static struct objcache_malloc_args devfs_rule_malloc_args = {
	sizeof(struct devfs_rule), M_DEVFS };

static cdev_t devfs_dev;
static struct devfs_rule_head devfs_rule_list = TAILQ_HEAD_INITIALIZER(devfs_rule_list);

static struct dev_ops devfs_dev_ops = {
	{ "devfs", 0, 0 },
	.d_open = devfs_dev_open,
	.d_close = devfs_dev_close,
	.d_ioctl = devfs_dev_ioctl
};


static struct devfs_rule *
devfs_rule_alloc(struct devfs_rule *templ)
{
	struct devfs_rule *rule = objcache_get(devfs_rule_cache, M_WAITOK);

	memcpy(rule, templ, sizeof(struct devfs_rule));
	return rule;
}


static void
devfs_rule_free(struct devfs_rule *rule)
{
	objcache_put(devfs_rule_cache, rule);
}


static void
devfs_rule_insert(struct devfs_rule *templ)
{
	struct devfs_rule *rule = devfs_rule_alloc(templ);
	lockmgr(&devfs_rule_lock, LK_EXCLUSIVE);
	rule->mntpointlen = strlen(rule->mntpoint);
	TAILQ_INSERT_TAIL(&devfs_rule_list, rule, link);
	lockmgr(&devfs_rule_lock, LK_RELEASE);
}


static void
devfs_rule_remove(struct devfs_rule *rule)
{
	TAILQ_REMOVE(&devfs_rule_list, rule, link);
	devfs_rule_free(rule);
}


static void
devfs_rule_clear(struct devfs_rule *rule)
{
	struct devfs_rule *rule1, *rule2;
	rule->mntpointlen = strlen(rule->mntpoint);

	lockmgr(&devfs_rule_lock, LK_EXCLUSIVE);
	TAILQ_FOREACH_MUTABLE(rule1, &devfs_rule_list, link, rule2) {
		if ((rule->mntpoint[0] == '*') ||
			( (rule->mntpointlen == rule1->mntpointlen) &&
			  (!memcmp(rule->mntpoint, rule1->mntpoint, rule->mntpointlen)) )) {
			devfs_rule_remove(rule1);
		}
	}
	lockmgr(&devfs_rule_lock, LK_RELEASE);
}


int
devfs_rule_reset_node(struct devfs_node *node)
{
	node->flags &= ~DEVFS_HIDDEN;

	if ((node->node_type == Pdev) && (node->d_dev)) {
		node->uid = node->d_dev->si_uid;
		node->gid = node->d_dev->si_gid;
		node->mode = node->d_dev->si_perms;
	}

	return 0;
}


int
devfs_rule_check_apply(struct devfs_node *node)
{
	struct devfs_rule *rule;
	struct mount *mp = node->mp;
	int applies = 0;

	lockmgr(&devfs_rule_lock, LK_EXCLUSIVE);
	TAILQ_FOREACH(rule, &devfs_rule_list, link) {

		/*
		 * Skip this rule if it is only intended for jailed mount points
		 * and the current mount point isn't jailed
		 */
		if ((rule->rule_type & DEVFS_RULE_JAIL) &&
			(!(DEVFS_MNTDATA(mp)->jailed)) )
			continue;

		/*
		 * Skip this rule if the mount point specified in the rule doesn't
		 * match the mount point of the node
		 */
		if ((rule->mntpoint[0] != '*') &&
			((rule->mntpointlen != DEVFS_MNTDATA(mp)->mntonnamelen) ||
			(memcmp(rule->mntpoint, mp->mnt_stat.f_mntonname, rule->mntpointlen))))
			continue;

		/*
		 * Skip this rule if this is a by-type rule and the device flags
		 * don't match the specified device type in the rule
		 */
		if ((rule->rule_type & DEVFS_RULE_TYPE) &&
			( (rule->dev_type == 0) || (!dev_is_good(node->d_dev)) ||
			  (!dev_dflags(node->d_dev) & rule->dev_type)) )
			continue;

		/*
		 * Skip this rule if this is a by-name rule and the node name
		 * doesn't match the wildcard string in the rule
		 */
		if ((rule->rule_type & DEVFS_RULE_NAME) &&
			(!devfs_rule_checkname(rule, node)) )
			continue;


		if (rule->rule_type & DEVFS_RULE_HIDE) {
			/*
			 * If we should hide the device, we just apply the relevant
			 * hide flag to the node and let devfs do the rest in the
			 * vnops
			 */
			node->flags |= DEVFS_HIDDEN;
			applies = 1;
		} else if (rule->rule_type & DEVFS_RULE_SHOW) {
			/*
			 * Show rule just means that the node should not be hidden, so
			 * what we do is clear the hide flag from the node.
			 */
			node->flags &= ~DEVFS_HIDDEN;
			applies = 1;
		} else if ((rule->rule_type & DEVFS_RULE_LINK) && (node->node_type != Plink)) {
			/*
			 * This is a LINK rule, so we tell devfs to create
			 * a link with the correct name to this node.
			 */
			devfs_alias_create(rule->linkname, node);
			applies = 1;
		} else {
			/*
			 * This is a normal ownership/permission rule. We
			 * just apply the permissions and ownership and
			 * we are done.
			 */
			node->mode = rule->mode;
			node->uid = rule->uid;
			node->gid = rule->gid;
			applies = 1;
		}
	}
	lockmgr(&devfs_rule_lock, LK_RELEASE);
	return applies;
}


static int
devfs_rule_checkname(struct devfs_rule *rule, struct devfs_node *node)
{
	struct devfs_node *parent = DEVFS_MNTDATA(node->mp)->root_node;
	char *path = NULL;
	char *name, name_buf[PATH_MAX];
	int no_match = 0;

	devfs_resolve_name_path(rule->name, name_buf, &path, &name);
	parent = devfs_resolve_or_create_path(parent, path, 0);

	if (parent == NULL)
		return 0; /* no match */

	/* Check if node is a child of the parent we found */
	if (node->parent != parent)
		return 0; /* no match */

	if (rule->rule_type & DEVFS_RULE_LINK)
		no_match = memcmp(name, node->d_dir.d_name, strlen(name));
	else
		no_match = WildCaseCmp(name, node->d_dir.d_name);

	return !no_match;
}


static int
devfs_dev_open(struct dev_open_args *ap)
{
	/*
	 * Only allow read-write access.
	 */
	if (((ap->a_oflags & FWRITE) == 0) || ((ap->a_oflags & FREAD) == 0))
		return(EPERM);

	/*
	 * We don't allow nonblocking access.
	 */
	if ((ap->a_oflags & O_NONBLOCK) != 0) {
		devfs_debug(DEVFS_DEBUG_DEBUG, "devfs_dev: can't do nonblocking access\n");
		return(ENODEV);
	}

	return 0;
}


static int
devfs_dev_close(struct dev_close_args *ap)
{
	return 0;
}


static int
devfs_dev_ioctl(struct dev_ioctl_args *ap)
{
	int error;
	struct devfs_rule *rule;

	error = 0;
	rule = (struct devfs_rule *)ap->a_data;

	switch(ap->a_cmd) {
	case DEVFS_RULE_ADD:
		devfs_rule_insert(rule);
		break;

	case DEVFS_RULE_APPLY:
		devfs_apply_rules(rule->mntpoint);
		break;

	case DEVFS_RULE_CLEAR:
		devfs_rule_clear(rule);
		break;

	case DEVFS_RULE_RESET:
		devfs_reset_rules(rule->mntpoint);
		break;

	default:
		error = ENOTTY; /* Inappropriate ioctl for device */
		break;
	}

	return(error);
}


static void
devfs_dev_init(void *unused)
{
	lockinit(&devfs_rule_lock, "devfs_rule lock", 0, 0);

    devfs_rule_cache = objcache_create("devfs-rule-cache", 0, 0,
			NULL, NULL, NULL,
			objcache_malloc_alloc,
			objcache_malloc_free,
			&devfs_rule_malloc_args );

    devfs_dev = make_dev(&devfs_dev_ops,
            0,
            UID_ROOT,
            GID_WHEEL,
            0600,
            "devfs");
}


static void
devfs_dev_uninit(void *unused)
{
	//XXX: destroy all rules first
    destroy_dev(devfs_dev);
	objcache_destroy(devfs_rule_cache);
}


SYSINIT(devfsdev,SI_SUB_DRIVERS,SI_ORDER_FIRST,devfs_dev_init,NULL)
SYSUNINIT(devfsdev, SI_SUB_DRIVERS,SI_ORDER_FIRST,devfs_dev_uninit, NULL);



static int
WildCmp(const char *w, const char *s)
{
    int i;
    int c;
    int slen = strlen(s);
    const char **mary;

    for (i = c = 0; w[i]; ++i) {
	if (w[i] == '*')
	    ++c;
    }
    mary = kmalloc(sizeof(char *) * (c + 1), M_DEVFS, M_WAITOK);
    for (i = 0; i < c; ++i)
	mary[i] = s + slen;
    i = wildCmp(mary, 0, w, s);
    kfree(mary, M_DEVFS);
    return(i);
}

static int
WildCaseCmp(const char *w, const char *s)
{
    int i;
    int c;
    int slen = strlen(s);
    const char **mary;

    for (i = c = 0; w[i]; ++i) {
	if (w[i] == '*')
	    ++c;
    }
    mary = kmalloc(sizeof(char *) * (c + 1), M_DEVFS, M_WAITOK);
    for (i = 0; i < c; ++i)
	mary[i] = s + slen;
    i = wildCaseCmp(mary, 0, w, s);
    kfree(mary, M_DEVFS);
    return(i);
}

/*
 * WildCmp() - compare wild string to sane string
 *
 *	Returns 0 on success, -1 on failure.
 */
static int
wildCmp(const char **mary, int d, const char *w, const char *s)
{
    int i;

    /*
     * skip fixed portion
     */
    for (;;) {
	switch(*w) {
	case '*':
	    /*
	     * optimize terminator
	     */
	    if (w[1] == 0)
		return(0);
	    if (w[1] != '?' && w[1] != '*') {
		/*
		 * optimize * followed by non-wild
		 */
		for (i = 0; s + i < mary[d]; ++i) {
		    if (s[i] == w[1] && wildCmp(mary, d + 1, w + 1, s + i) == 0)
			return(0);
		}
	    } else {
		/*
		 * less-optimal
		 */
		for (i = 0; s + i < mary[d]; ++i) {
		    if (wildCmp(mary, d + 1, w + 1, s + i) == 0)
			return(0);
		}
	    }
	    mary[d] = s;
	    return(-1);
	case '?':
	    if (*s == 0)
		return(-1);
	    ++w;
	    ++s;
	    break;
	default:
	    if (*w != *s)
		return(-1);
	    if (*w == 0)	/* terminator */
		return(0);
	    ++w;
	    ++s;
	    break;
	}
    }
    /* not reached */
    return(-1);
}


/*
 * WildCaseCmp() - compare wild string to sane string, case insensitive
 *
 *	Returns 0 on success, -1 on failure.
 */
static int
wildCaseCmp(const char **mary, int d, const char *w, const char *s)
{
    int i;

    /*
     * skip fixed portion
     */
    for (;;) {
	switch(*w) {
	case '*':
	    /*
	     * optimize terminator
	     */
	    if (w[1] == 0)
		return(0);
	    if (w[1] != '?' && w[1] != '*') {
		/*
		 * optimize * followed by non-wild
		 */
		for (i = 0; s + i < mary[d]; ++i) {
		    if (s[i] == w[1] && wildCaseCmp(mary, d + 1, w + 1, s + i) == 0)
			return(0);
		}
	    } else {
		/*
		 * less-optimal
		 */
		for (i = 0; s + i < mary[d]; ++i) {
		    if (wildCaseCmp(mary, d + 1, w + 1, s + i) == 0)
			return(0);
		}
	    }
	    mary[d] = s;
	    return(-1);
	case '?':
	    if (*s == 0)
		return(-1);
	    ++w;
	    ++s;
	    break;
	default:
	    if (*w != *s) {
#define tolower(x)	((x >= 'A' && x <= 'Z')?(x+('a'-'A')):(x))
		if (tolower(*w) != tolower(*s))
		    return(-1);
	    }
	    if (*w == 0)	/* terminator */
		return(0);
	    ++w;
	    ++s;
	    break;
	}
    }
    /* not reached */
    return(-1);
}