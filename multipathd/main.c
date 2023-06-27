/*
 * Copyright (c) 2004, 2005 Christophe Varoqui
 * Copyright (c) 2005 Kiyoshi Ueda, NEC
 * Copyright (c) 2005 Benjamin Marzinski, Redhat
 * Copyright (c) 2005 Edward Goggin, EMC
 */
#include <unistd.h>
#include <sys/stat.h>
#include <libdevmapper.h>
#include <wait.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <linux/oom.h>
#include <libudev.h>
#include <semaphore.h>
#include <stdbool.h>
#include <mpath_persist.h>
#include "prioritizers/alua_rtpg.h"

/*
 * libcheckers
 */
#include <checkers.h>

/*
 * libmultipath
 */
#include <parser.h>
#include <vector.h>
#include <memory.h>
#include <config.h>
#include <util.h>
#include <hwtable.h>
#include <defaults.h>
#include <structs.h>
#include <blacklist.h>
#include <structs_vec.h>
#include <dmparser.h>
#include <devmapper.h>
#include <sysfs.h>
#include <dict.h>
#include <discovery.h>
#include <debug.h>
#include <propsel.h>
#include <uevent.h>
#include <switchgroup.h>
#include <print.h>
#include <configure.h>
#include <prio.h>
#include <wwids.h>
#include <pgpolicies.h>
#include <uevent.h>
#include <log.h>
#include <file.h>
#include <prkey.h>
#include <io_err_stat.h>

#include "main.h"
#include "pidfile.h"
#include "uxlsnr.h"
#include "uxclnt.h"
#include "cli.h"
#include "cli_handlers.h"
#include "lock.h"
#include "waiter.h"

#define FILE_NAME_SIZE 256
#define CMDSIZE 160

#define LOG_MSG(a, b) \
do { \
	if (pp->offline) \
		condlog(a, "%s: %s - path offline", pp->mpp->alias, pp->dev); \
	else if (strlen(b)) \
		condlog(a, "%s: %s - %s", pp->mpp->alias, pp->dev, b); \
} while(0)

struct mpath_event_param
{
	char * devname;
	struct multipath *mpp;
};

unsigned int mpath_mx_alloc_len;

int logsink;
enum daemon_status running_state;
pid_t daemon_pid;
pid_t parent_pid = -1;

static sem_t exit_sem;
/*
 * global copy of vecs for use in sig handlers
 */
struct vectors * gvecs;

struct udev * udev;

static int
need_switch_pathgroup (struct multipath * mpp, int refresh)
{
	struct pathgroup * pgp;
	struct path * pp;
	unsigned int i, j;

	if (!mpp || mpp->pgfailback == -FAILBACK_MANUAL)
		return 0;

	/*
	 * Refresh path priority values
	 */
	if (refresh)
		vector_foreach_slot (mpp->pg, pgp, i)
			vector_foreach_slot (pgp->paths, pp, j)
				pathinfo(pp, conf->hwtable, DI_PRIO);

	mpp->bestpg = select_path_group(mpp);

	if (mpp->bestpg != mpp->nextpg)
		return 1;

	return 0;
}

static void
switch_pathgroup (struct multipath * mpp)
{
	mpp->stat_switchgroup++;
	dm_switchgroup(mpp->alias, mpp->bestpg);
	condlog(2, "%s: switch to path group #%i",
		 mpp->alias, mpp->bestpg);
}

static int
coalesce_maps(struct vectors *vecs, vector nmpv)
{
	struct multipath * ompp;
	vector ompv = vecs->mpvec;
	unsigned int i;

	vector_foreach_slot (ompv, ompp, i) {
		if (!find_mp_by_wwid(nmpv, ompp->wwid)) {
			/*
			 * remove all current maps not allowed by the
			 * current configuration
			 */
			if (dm_flush_map(ompp->alias)) {
				condlog(0, "%s: unable to flush devmap",
					ompp->alias);
				/*
				 * may be just because the device is open
				 */
				if (setup_multipath(vecs, ompp) != 0) {
					i--;
					continue;
				}
				if (!vector_alloc_slot(nmpv))
					return 1;

				vector_set_slot(nmpv, ompp);

				vector_del_slot(ompv, i);
				i--;
			}
			else {
				dm_lib_release();
				condlog(2, "%s devmap removed", ompp->alias);
			}
		} else if (conf->reassign_maps) {
			condlog(3, "%s: Reassign existing device-mapper"
				" devices", ompp->alias);
			dm_reassign(ompp->alias);
		}
	}
	return 0;
}

void
sync_map_state(struct multipath *mpp)
{
	struct pathgroup *pgp;
	struct path *pp;
	unsigned int i, j;

	if (!mpp->pg)
		return;

	vector_foreach_slot (mpp->pg, pgp, i){
		vector_foreach_slot (pgp->paths, pp, j){
			if (pp->state == PATH_UNCHECKED || 
			    pp->state == PATH_WILD ||
			    pp->state == PATH_DELAYED)
				continue;
			if (mpp->ghost_delay_tick > 0)
				continue;
			if ((pp->dmstate == PSTATE_FAILED ||
			     pp->dmstate == PSTATE_UNDEF) &&
			    (pp->state == PATH_UP || pp->state == PATH_GHOST))
				dm_reinstate_path(mpp->alias, pp->dev_t);
			else if ((pp->dmstate == PSTATE_ACTIVE ||
				  pp->dmstate == PSTATE_UNDEF) &&
				 (pp->state == PATH_DOWN ||
				  pp->state == PATH_SHAKY))
				dm_fail_path(mpp->alias, pp->dev_t);
		}
	}
}

static void
sync_maps_state(vector mpvec)
{
	unsigned int i;
	struct multipath *mpp;

	vector_foreach_slot (mpvec, mpp, i)
		sync_map_state(mpp);
}

static int
flush_map(struct multipath * mpp, struct vectors * vecs, int nopaths)
{
	int r;

	if (nopaths)
		r = dm_flush_map_nopaths(mpp->alias, mpp->deferred_remove);
	else
		r = dm_flush_map(mpp->alias);
	/*
	 * clear references to this map before flushing so we can ignore
	 * the spurious uevent we may generate with the dm_flush_map call below
	 */
	if (r) {
		/*
		 * May not really be an error -- if the map was already flushed
		 * from the device mapper by dmsetup(8) for instance.
		 */
		if (r == 1)
			condlog(0, "%s: can't flush", mpp->alias);
		else {
			condlog(2, "%s: devmap deferred remove", mpp->alias);
			mpp->deferred_remove = DEFERRED_REMOVE_IN_PROGRESS;
		}
		return r;
	}
	else {
		dm_lib_release();
		condlog(2, "%s: devmap removed", mpp->alias);
	}

	orphan_paths(vecs->pathvec, mpp);
	remove_map_and_stop_waiter(mpp, vecs, 1);

	return 0;
}

int
update_map (struct multipath *mpp, struct vectors *vecs)
{
	int retries = 3;
	char params[PARAMS_SIZE] = {0};

retry:
	condlog(4, "%s: updating new map", mpp->alias);
	if (adopt_paths(vecs->pathvec, mpp, 1)) {
		condlog(0, "%s: failed to adopt paths for new map update",
			mpp->alias);
		retries = -1;
		goto fail;
	}
	verify_paths(mpp, vecs, NULL);
	mpp->flush_on_last_del = FLUSH_UNDEF;
	mpp->action = ACT_RELOAD;

	extract_hwe_from_path(mpp);
	if (setup_map(mpp, params, PARAMS_SIZE, vecs)) {
		condlog(0, "%s: failed to setup new map in update", mpp->alias);
		retries = -1;
		goto fail;
	}
	if (domap(mpp, params) <= 0 && retries-- > 0) {
		condlog(0, "%s: map_udate sleep", mpp->alias);
		sleep(1);
		goto retry;
	}
	dm_lib_release();

fail:
	if (setup_multipath(vecs, mpp))
		return 1;

	sync_map_state(mpp);

	if (retries < 0)
		condlog(0, "%s: failed reload in new map update", mpp->alias);
	return 0;
}

static struct multipath *
add_map_without_path (struct vectors * vecs, char * alias)
{
	struct multipath * mpp = alloc_multipath();

	if (!mpp)
		return NULL;
	if (!alias) {
		FREE(mpp);
		return NULL;
	}

	mpp->alias = STRDUP(alias);

	if (dm_get_info(mpp->alias, &mpp->dmi)) {
		condlog(3, "%s: cannot access table", mpp->alias);
		goto out;
	}
	set_multipath_wwid(mpp);
	mpp->mpe = find_mpe(mpp->wwid);

	if (update_multipath_table(mpp, vecs->pathvec))
		 goto out;
	if (update_multipath_status(mpp))
		goto out;

	if (!vector_alloc_slot(vecs->mpvec))
		goto out;

	vector_set_slot(vecs->mpvec, mpp);

	if (update_map(mpp, vecs) != 0) /* map removed */
		return NULL;

	if (start_waiter_thread(mpp, vecs))
		goto out;

	return mpp;
out:
	remove_map(mpp, vecs, 1);
	return NULL;
}

static int
uev_add_map (struct uevent * uev, struct vectors * vecs)
{
	char *alias;
	int major = -1, minor = -1, rc;

	condlog(3, "%s: add map (uevent)", uev->kernel);
	alias = uevent_get_dm_name(uev);
	if (!alias) {
		condlog(3, "%s: No DM_NAME in uevent", uev->kernel);
		major = uevent_get_major(uev);
		minor = uevent_get_minor(uev);
		alias = dm_mapname(major, minor);
		if (!alias) {
			condlog(2, "%s: mapname not found for %d:%d",
				uev->kernel, major, minor);
			return 1;
		}
	}
	rc = ev_add_map(uev->kernel, alias, vecs);
	FREE(alias);
	return rc;
}

int
ev_add_map (char * dev, char * alias, struct vectors * vecs)
{
	char * refwwid;
	struct multipath * mpp;
	int map_present;
	int r = 1;

	map_present = dm_map_present(alias);

	if (map_present && !dm_is_mpath(alias)) {
		condlog(4, "%s: not a multipath map", alias);
		return 0;
	}

	mpp = find_mp_by_alias(vecs->mpvec, alias);

	if (mpp) {
		if (mpp->wait_for_udev > 1) {
			condlog(2, "%s: performing delayed actions", mpp->alias);
			if (update_map(mpp, vecs))
			/* setup multipathd removed the map */
				return 1;
		}
		if (mpp->wait_for_udev) {
			mpp->wait_for_udev = 0;
			if (conf->delayed_reconfig &&
			    !need_to_delay_reconfig(vecs)) {
				condlog(2, "reconfigure (delayed)");
				reconfigure(vecs);
				return 0;
			}
		}
		/*
		 * Not really an error -- we generate our own uevent
		 * if we create a multipath mapped device as a result
		 * of uev_add_path
		 */
		if (conf->reassign_maps) {
			condlog(3, "%s: Reassign existing device-mapper devices",
				alias);
			dm_reassign(alias);
		}
		return 0;
	}
	condlog(2, "%s: adding map", alias);

	/*
	 * now we can register the map
	 */
	if (map_present) {
		if ((mpp = add_map_without_path(vecs, alias))) {
			sync_map_state(mpp);
			condlog(2, "%s: devmap %s registered", alias, dev);
			return 0;
		} else {
			condlog(2, "%s: uev_add_map failed", dev);
			return 1;
		}
	}
	r = get_refwwid(dev, DEV_DEVMAP, vecs->pathvec, &refwwid);

	if (refwwid) {
		r = coalesce_paths(vecs, NULL, refwwid, 0);
		dm_lib_release();
	}

	if (!r)
		condlog(2, "%s: devmap %s added", alias, dev);
	else if (r == 2)
		condlog(2, "%s: uev_add_map %s blacklisted", alias, dev);
	else
		condlog(0, "%s: uev_add_map %s failed", alias, dev);

	FREE(refwwid);
	return r;
}

static int
uev_remove_map (struct uevent * uev, struct vectors * vecs)
{
	char *alias;
	int minor;
	struct multipath *mpp;

	condlog(2, "%s: remove map (uevent)", uev->kernel);
	alias = uevent_get_dm_name(uev);
	if (!alias) {
		condlog(3, "%s: No DM_NAME in uevent, ignoring", uev->kernel);
		return 0;
	}
	minor = uevent_get_minor(uev);
	mpp = find_mp_by_minor(vecs->mpvec, minor);

	if (!mpp) {
		condlog(2, "%s: devmap not registered, can't remove",
			uev->kernel);
		goto out;
	}
	if (strcmp(mpp->alias, alias)) {
		condlog(2, "%s: minor number mismatch (map %d, event %d)",
			mpp->alias, mpp->dmi->minor, minor);
		goto out;
	}

	orphan_paths(vecs->pathvec, mpp);
	remove_map_and_stop_waiter(mpp, vecs, 1);
out:
	FREE(alias);
	return 0;
}

int
ev_remove_map (char * devname, char * alias, int minor, struct vectors * vecs)
{
	struct multipath * mpp;

	mpp = find_mp_by_minor(vecs->mpvec, minor);

	if (!mpp) {
		condlog(2, "%s: devmap not registered, can't remove",
			devname);
		return 1;
	}
	if (strcmp(mpp->alias, alias)) {
		condlog(2, "%s: minor number mismatch (map %d, event %d)",
			mpp->alias, mpp->dmi->minor, minor);
		return 1;
	}
	return flush_map(mpp, vecs, 0);
}

static int
uev_add_path (struct uevent *uev, struct vectors * vecs)
{
	struct path *pp;
	int ret, i;

	condlog(2, "%s: add path (uevent)", uev->kernel);
	if (strstr(uev->kernel, "..") != NULL) {
		/*
		 * Don't allow relative device names in the pathvec
		 */
		condlog(0, "%s: path name is invalid", uev->kernel);
		return 1;
	}

	pp = find_path_by_dev(vecs->pathvec, uev->kernel);
	if (pp) {
		condlog(2, "%s: spurious uevent, path already in pathvec",
			uev->kernel);
		if (pp->mpp)
			return 0;
		if (!strlen(pp->wwid)) {
			udev_device_unref(pp->udev);
			pp->udev = udev_device_ref(uev->udev);
			ret = pathinfo(pp, conf->hwtable,
				       DI_ALL | DI_BLACKLIST);
			if (ret == 2) {
				i = find_slot(vecs->pathvec, (void *)pp);
				if (i != -1)
					vector_del_slot(vecs->pathvec, i);
				free_path(pp);
				return 0;
			} else if (ret == 1) {
				condlog(0, "%s: failed to reinitialize path",
					uev->kernel);
				return 1;
			}
		}
	} else {
		/*
		 * get path vital state
		 */
		ret = store_pathinfo(vecs->pathvec, conf->hwtable,
				     uev->udev, DI_ALL, &pp);
		if (!pp) {
			if (ret == 2)
				return 0;
			condlog(0, "%s: failed to store path info",
				uev->kernel);
			return 1;
		}
		pp->checkint = conf->checkint;
	}

	return ev_add_path(pp, vecs);
}

/*
 * returns:
 * 0: added
 * 1: error
 */
int
ev_add_path (struct path * pp, struct vectors * vecs)
{
	struct multipath * mpp;
	char empty_buff[WWID_SIZE] = {0};
	char params[PARAMS_SIZE] = {0};
	int retries = 3;
	int start_waiter = 0;
	int ret;

	/*
	 * need path UID to go any further
	 */
	if (memcmp(empty_buff, pp->wwid, WWID_SIZE) == 0) {
		condlog(0, "%s: failed to get path uid", pp->dev);
		goto fail; /* leave path added to pathvec */
	}
	mpp = find_mp_by_wwid(vecs->mpvec, pp->wwid);
	if (mpp && mpp->wait_for_udev) {
		if (pathcount(mpp, PATH_UP) == 0 &&
		    (pathcount(mpp, PATH_GHOST) == 0 ||
		     mpp->ghost_delay_tick > 0 || pp->tpgs == TPGS_IMPLICIT))
			mpp->force_udev_reload = 1;
		else {
			condlog(2, "%s [%s]: delaying path addition until %s is fully initialized", pp->dev, pp->dev_t, mpp->alias);
			mpp->wait_for_udev = 2;
			orphan_path(pp);
			return 0;
		}
	}

	pp->mpp = mpp;
rescan:
	if (mpp) {
		if (pp->size && mpp->size != pp->size) {
			condlog(0, "%s: failed to add new path %s, "
				"device size mismatch",
				mpp->alias, pp->dev);
			int i = find_slot(vecs->pathvec, (void *)pp);
			if (i != -1)
				vector_del_slot(vecs->pathvec, i);
			free_path(pp);
			return 1;
		}

		condlog(4,"%s: adopting all paths for path %s",
			mpp->alias, pp->dev);
		if (pathcount(mpp, PATH_WILD) == 0)
			mpp->force_udev_reload = 1;
		if (adopt_paths(vecs->pathvec, mpp, 1))
			goto fail; /* leave path added to pathvec */

		verify_paths(mpp, vecs, NULL);
		mpp->flush_on_last_del = FLUSH_UNDEF;
		mpp->action = ACT_RELOAD;
		extract_hwe_from_path(mpp);
	} else {
		if (!should_multipath(pp, vecs->pathvec)) {
			orphan_path(pp);
			return 0;
		}
		condlog(4,"%s: creating new map", pp->dev);
		if ((mpp = add_map_with_path(vecs, pp, 1))) {
			mpp->action = ACT_CREATE;
			/*
			 * We don't depend on ACT_CREATE, as domap will
			 * set it to ACT_NOTHING when complete.
			 */
			start_waiter = 1;
		}
		else
			goto fail; /* leave path added to pathvec */
	}

	/* persistent reseravtion check*/
	mpath_pr_event_handle(pp);	

	/*
	 * push the map to the device-mapper
	 */
	if (setup_map(mpp, params, PARAMS_SIZE, vecs)) {
		condlog(0, "%s: failed to setup map for addition of new "
			"path %s", mpp->alias, pp->dev);
		goto fail_map;
	}
	/*
	 * reload the map for the multipath mapped device
	 */
retry:
	ret = domap(mpp, params);
	if (ret <= 0) {
		if (ret < 0 && retries-- > 0) {
			condlog(0, "%s: retry domap for addition of new "
				"path %s", mpp->alias, pp->dev);
			sleep(1);
			goto retry;
		}
		condlog(0, "%s: failed in domap for addition of new "
			"path %s", mpp->alias, pp->dev);
		/*
		 * deal with asynchronous uevents :((
		 */
		if (mpp->action == ACT_RELOAD && retries-- > 0) {
			condlog(0, "%s: uev_add_path sleep", mpp->alias);
			sleep(1);
			update_mpp_paths(mpp, vecs->pathvec);
			goto rescan;
		}
		else if (mpp->action == ACT_RELOAD)
			condlog(0, "%s: giving up reload", mpp->alias);
		else
			goto fail_map;
	}
	dm_lib_release();

	/*
	 * update our state from kernel regardless of create or reload
	 */
	if (setup_multipath(vecs, mpp))
		goto fail; /* if setup_multipath fails, it removes the map */

	sync_map_state(mpp);

	if ((mpp->action == ACT_CREATE ||
	     (mpp->action == ACT_NOTHING && start_waiter && !mpp->waiter)) &&
	    start_waiter_thread(mpp, vecs))
			goto fail_map;

	if (retries >= 0) {
		condlog(2, "%s [%s]: path added to devmap %s",
			pp->dev, pp->dev_t, mpp->alias);
		return 0;
	}
	else
		goto fail;

fail_map:
	remove_map(mpp, vecs, 1);
fail:
	orphan_path(pp);
	return 1;
}

static int
uev_remove_path (struct uevent *uev, struct vectors * vecs)
{
	struct path *pp;

	condlog(2, "%s: remove path (uevent)", uev->kernel);
	pp = find_path_by_dev(vecs->pathvec, uev->kernel);

	if (!pp) {
		/* Not an error; path might have been purged earlier */
		condlog(0, "%s: path already removed", uev->kernel);
		return 0;
	}

	return ev_remove_path(pp, vecs);
}

int
ev_remove_path (struct path *pp, struct vectors * vecs)
{
	struct multipath * mpp;
	int i, retval = 0;
	char params[PARAMS_SIZE] = {0};

	/*
	 * avoid referring to the map of an orphaned path
	 */
	if ((mpp = pp->mpp)) {
		/*
		 * transform the mp->pg vector of vectors of paths
		 * into a mp->params string to feed the device-mapper
		 */
		if (update_mpp_paths(mpp, vecs->pathvec)) {
			condlog(0, "%s: failed to update paths",
				mpp->alias);
			goto fail;
		}
		if ((i = find_slot(mpp->paths, (void *)pp)) != -1)
			vector_del_slot(mpp->paths, i);

		/*
		 * remove the map IFF removing the last path
		 */
		if (VECTOR_SIZE(mpp->paths) == 0) {
			char alias[WWID_SIZE];

			/*
			 * flush_map will fail if the device is open
			 */
			strncpy(alias, mpp->alias, WWID_SIZE);
			if (mpp->flush_on_last_del == FLUSH_ENABLED) {
				condlog(2, "%s Last path deleted, disabling queueing", mpp->alias);
				mpp->retry_tick = 0;
				mpp->no_path_retry = NO_PATH_RETRY_FAIL;
				mpp->flush_on_last_del = FLUSH_IN_PROGRESS;
				mpp->stat_map_failures++;
				dm_queue_if_no_path(mpp->alias, 0);
			}
			if (!flush_map(mpp, vecs, 1)) {
				condlog(2, "%s: removed map after"
					" removing all paths",
					alias);
				retval = 0;
				goto out;
			}
			/*
			 * Not an error, continue
			 */
		}

		if (setup_map(mpp, params, PARAMS_SIZE, vecs)) {
			condlog(0, "%s: failed to setup map for"
				" removal of path %s", mpp->alias, pp->dev);
			goto fail;
		}

		if (mpp->wait_for_udev) {
			mpp->wait_for_udev = 2;
			goto out;
		}

		/*
		 * reload the map
		 */
		mpp->action = ACT_RELOAD;
		if (domap(mpp, params) <= 0) {
			condlog(0, "%s: failed in domap for "
				"removal of path %s",
				mpp->alias, pp->dev);
			retval = 1;
		} else {
			/*
			 * update our state from kernel
			 */
			if (setup_multipath(vecs, mpp))
				return 1;
			sync_map_state(mpp);

			condlog(2, "%s [%s]: path removed from map %s",
				pp->dev, pp->dev_t, mpp->alias);
		}
	}

out:
	if ((i = find_slot(vecs->pathvec, (void *)pp)) != -1)
		vector_del_slot(vecs->pathvec, i);

	free_path(pp);

	return retval;

fail:
	remove_map_and_stop_waiter(mpp, vecs, 1);
	return 1;
}

static int
uev_update_path (struct uevent *uev, struct vectors * vecs)
{
	int ro, retval = 0;
	struct path * pp;

	pp = find_path_by_dev(vecs->pathvec, uev->kernel);
	if (!pp) {
		/* If the path is blacklisted, print a debug/non-default verbosity message. */
		if (uev->udev) {
			int flag = DI_SYSFS | DI_WWID;

			if (store_pathinfo(NULL, conf->hwtable, uev->udev, flag, NULL) == PATHINFO_SKIPPED) {
				condlog(3, "%s: spurious uevent, path is blacklisted", uev->kernel);
				return 0;
			}
		}

		condlog(0, "%s: spurious uevent, path not found",
			uev->kernel);
		return 1;
	}

	if (pp->missing_udev_info == INFO_REQUESTED)
		return uev_add_path(uev, vecs);

	if (conf->disable_changed_wwids &&
	    (strlen(pp->wwid) || pp->wwid_changed)) {
		char wwid[WWID_SIZE];

		strcpy(wwid, pp->wwid);
		get_uid(pp, uev->udev);
		if (strcmp(wwid, pp->wwid) != 0) {
			condlog(0, "%s: path wwid changed from '%s' to '%s'. disallowing", uev->kernel, wwid, pp->wwid);
			strcpy(pp->wwid, wwid);
			if (!pp->wwid_changed) {
				pp->wwid_changed = 1;
				pp->tick = 1;
				if (pp->mpp)
					dm_fail_path(pp->mpp->alias, pp->dev_t);
			}
		}
		else {
			pp->wwid_changed = 0;
		}
	}

	/* reinit the prio values on change event, in case something is
	 * different */
	prio_init(&pp->prio);

	ro = uevent_get_disk_ro(uev);

	if (ro >= 0) {
		condlog(2, "%s: update path write_protect to '%d' (uevent)",
			uev->kernel, ro);
		if (pp->mpp) {
			if (pp->mpp->wait_for_udev) {
				pp->mpp->wait_for_udev = 2;
				return 0;
			}
			if (ro == 1)
				pp->mpp->force_readonly = 1;
			retval = reload_map(vecs, pp->mpp, 0);
			pp->mpp->force_readonly = 0;
			condlog(2, "%s: map %s reloaded (retval %d)",
				uev->kernel, pp->mpp->alias, retval);
		}

	}

	return retval;
}

static int
uev_pathfail_check(struct uevent *uev, struct vectors *vecs)
{
	char *action = NULL, *devt = NULL;
	struct path *pp;
	int r = 1;

	action = uevent_get_dm_action(uev);
	if (!action)
		return 1;
	if (strncmp(action, "PATH_FAILED", 11))
		goto out;
	devt = uevent_get_dm_path(uev);
	if (!devt) {
		condlog(3, "%s: No DM_PATH in uevent", uev->kernel);
		goto out;
	}

	pp = find_path_by_devt(vecs->pathvec, devt);
	if (!pp)
		goto out_devt;
	r = io_err_stat_handle_pathfail(pp);

	if (r)
		condlog(3, "io_err_stat: %s: cannot handle pathfail uevent",
			pp->dev);
out_devt:
	FREE(devt);
	FREE(action);
	return r;
out:
	FREE(action);
	return 1;
}

static int
map_discovery (struct vectors * vecs)
{
	struct multipath * mpp;
	unsigned int i;

	if (dm_get_maps(vecs->mpvec))
		return 1;

	vector_foreach_slot (vecs->mpvec, mpp, i)
		if (update_multipath_table(mpp, vecs->pathvec) ||
		    update_multipath_status(mpp)) {
			remove_map(mpp, vecs, 1);
			i--;
		}

	return 0;
}

int
uxsock_trigger (char * str, char ** reply, int * len, bool is_root,
		void * trigger_data)
{
	struct vectors * vecs;
	int r;

	*reply = NULL;
	*len = 0;
	vecs = (struct vectors *)trigger_data;

	pthread_cleanup_push(cleanup_lock, &vecs->lock);
	lock(vecs->lock);
	pthread_testcancel();

	if ((str != NULL) && (is_root == false) &&
	    (strncmp(str, "list", strlen("list")) != 0) &&
	    (strncmp(str, "show", strlen("show")) != 0)) {
		*reply = STRDUP("permission deny: need to be root");
		if (*reply)
			*len = strlen(*reply) + 1;
		r = 1;
		goto out;
	}

	r = parse_cmd(str, reply, len, vecs);

	if (r > 0) {
		*reply = STRDUP("fail\n");
		if (*reply)
			*len = strlen(*reply) + 1;
		r = 1;
	}
	else if (!r && *len == 0) {
		*reply = STRDUP("ok\n");
		if (*reply)
			*len = strlen(*reply) + 1;
		r = 0;
	}
	/* else if (r < 0) leave *reply alone */
out:
	lock_cleanup_pop(vecs->lock);
	return r;
}

int
uev_trigger (struct uevent * uev, void * trigger_data)
{
	int r = 0;
	struct vectors * vecs;

	vecs = (struct vectors *)trigger_data;

	pthread_cleanup_push(cleanup_lock, &vecs->lock);
	lock(vecs->lock);
	pthread_testcancel();

	/*
	 * device map event
	 * Add events are ignored here as the tables
	 * are not fully initialised then.
	 */
	if (!strncmp(uev->kernel, "dm-", 3)) {
		if (!strncmp(uev->action, "change", 6)) {
			r = uev_add_map(uev, vecs);

			/*
			 * the kernel-side dm-mpath issues a PATH_FAILED event
			 * when it encounters a path IO error. It is reason-
			 * able be the entry of path IO error accounting pro-
			 * cess.
			 */
			uev_pathfail_check(uev, vecs);
			goto out;
		}
		if (!strncmp(uev->action, "remove", 6)) {
			r = uev_remove_map(uev, vecs);
			goto out;
		}
		goto out;
	}

	/*
	 * path add/remove event
	 */
	if (filter_devnode(conf->blist_devnode, conf->elist_devnode,
			   uev->kernel) > 0)
		goto out;

	if (!strncmp(uev->action, "add", 3)) {
		r = uev_add_path(uev, vecs);
		goto out;
	}
	if (!strncmp(uev->action, "remove", 6)) {
		r = uev_remove_path(uev, vecs);
		goto out;
	}
	if (!strncmp(uev->action, "change", 6)) {
		r = uev_update_path(uev, vecs);
		goto out;
	}

out:
	lock_cleanup_pop(vecs->lock);
	return r;
}

static void *
ueventloop (void * ap)
{
	if (uevent_listen(udev))
		condlog(0, "error starting uevent listener");

	return NULL;
}

static void *
uevqloop (void * ap)
{
	if (uevent_dispatch(&uev_trigger, ap))
		condlog(0, "error starting uevent dispatcher");

	return NULL;
}
static void *
uxlsnrloop (void * ap)
{
	if (cli_init())
		return NULL;

	set_handler_callback(LIST|PATHS, cli_list_paths);
	set_handler_callback(LIST|PATHS|FMT, cli_list_paths_fmt);
	set_handler_callback(LIST|PATHS|RAW|FMT, cli_list_paths_raw);
	set_handler_callback(LIST|MAPS, cli_list_maps);
	set_handler_callback(LIST|STATUS, cli_list_status);
	set_handler_callback(LIST|DAEMON, cli_list_daemon);
	set_handler_callback(LIST|MAPS|STATUS, cli_list_maps_status);
	set_handler_callback(LIST|MAPS|STATS, cli_list_maps_stats);
	set_handler_callback(LIST|MAPS|FMT, cli_list_maps_fmt);
	set_handler_callback(LIST|MAPS|RAW|FMT, cli_list_maps_raw);
	set_handler_callback(LIST|MAPS|TOPOLOGY, cli_list_maps_topology);
	set_handler_callback(LIST|TOPOLOGY, cli_list_maps_topology);
	set_handler_callback(LIST|MAPS|JSON, cli_list_maps_json);
	set_handler_callback(LIST|MAP|TOPOLOGY, cli_list_map_topology);
	set_handler_callback(LIST|MAP|JSON, cli_list_map_json);
	set_handler_callback(LIST|CONFIG, cli_list_config);
	set_handler_callback(LIST|BLACKLIST, cli_list_blacklist);
	set_handler_callback(LIST|DEVICES, cli_list_devices);
	set_handler_callback(LIST|WILDCARDS, cli_list_wildcards);
	set_handler_callback(RESET|MAPS|STATS, cli_reset_maps_stats);
	set_handler_callback(RESET|MAP|STATS, cli_reset_map_stats);
	set_handler_callback(ADD|PATH, cli_add_path);
	set_handler_callback(DEL|PATH, cli_del_path);
	set_handler_callback(ADD|MAP, cli_add_map);
	set_handler_callback(DEL|MAP, cli_del_map);
	set_handler_callback(SWITCH|MAP|GROUP, cli_switch_group);
	set_handler_callback(RECONFIGURE, cli_reconfigure);
	set_handler_callback(SUSPEND|MAP, cli_suspend);
	set_handler_callback(RESUME|MAP, cli_resume);
	set_handler_callback(RESIZE|MAP, cli_resize);
	set_handler_callback(RELOAD|MAP, cli_reload);
	set_handler_callback(RESET|MAP, cli_reassign);
	set_handler_callback(REINSTATE|PATH, cli_reinstate);
	set_handler_callback(FAIL|PATH, cli_fail);
	set_handler_callback(DISABLEQ|MAP, cli_disable_queueing);
	set_handler_callback(RESTOREQ|MAP, cli_restore_queueing);
	set_handler_callback(DISABLEQ|MAPS, cli_disable_all_queueing);
	set_handler_callback(RESTOREQ|MAPS, cli_restore_all_queueing);
	set_handler_callback(QUIT, cli_quit);
	set_handler_callback(SHUTDOWN, cli_shutdown);
	set_handler_callback(GETPRSTATUS|MAP, cli_getprstatus);
	set_handler_callback(SETPRSTATUS|MAP, cli_setprstatus);
	set_handler_callback(UNSETPRSTATUS|MAP, cli_unsetprstatus);
	set_handler_callback(GETPRKEY|MAP, cli_getprkey);
	set_handler_callback(SETPRKEY|MAP|KEY, cli_setprkey);
	set_handler_callback(UNSETPRKEY|MAP, cli_unsetprkey);
	set_handler_callback(FORCEQ|DAEMON, cli_force_no_daemon_q);
	set_handler_callback(RESTOREQ|DAEMON, cli_restore_no_daemon_q);

	umask(077);
	uxsock_listen(&uxsock_trigger, ap);

	return NULL;
}

void
exit_daemon (void)
{
	sem_post(&exit_sem);
}

const char *
daemon_status(void)
{
	switch (running_state) {
	case DAEMON_INIT:
		return "init";
	case DAEMON_START:
		return "startup";
	case DAEMON_CONFIGURE:
		return "configure";
	case DAEMON_RUNNING:
		return "running";
	case DAEMON_SHUTDOWN:
		return "shutdown";
	}
	return NULL;
}

static void
fail_path (struct path * pp, int del_active)
{
	if (!pp->mpp)
		return;

	condlog(2, "checker failed path %s in map %s",
		 pp->dev_t, pp->mpp->alias);

	dm_fail_path(pp->mpp->alias, pp->dev_t);
	if (del_active)
		update_queue_mode_del_path(pp->mpp);
}

/*
 * caller must have locked the path list before calling that function
 */
static void
reinstate_path (struct path * pp, int add_active)
{
	if (!pp->mpp)
		return;

	if (dm_reinstate_path(pp->mpp->alias, pp->dev_t))
		condlog(0, "%s: reinstate failed", pp->dev_t);
	else {
		condlog(2, "%s: reinstated", pp->dev_t);
		if (add_active)
			update_queue_mode_add_path(pp->mpp);
	}
}

static void
enable_group(struct path * pp)
{
	struct pathgroup * pgp;

	/*
	 * if path is added through uev_add_path, pgindex can be unset.
	 * next update_strings() will set it, upon map reload event.
	 *
	 * we can safely return here, because upon map reload, all
	 * PG will be enabled.
	 */
	if (!pp->mpp->pg || !pp->pgindex)
		return;

	pgp = VECTOR_SLOT(pp->mpp->pg, pp->pgindex - 1);

	if (pgp->status == PGSTATE_DISABLED) {
		condlog(2, "%s: enable group #%i", pp->mpp->alias, pp->pgindex);
		dm_enablegroup(pp->mpp->alias, pp->pgindex);
	}
}

static void
mpvec_garbage_collector (struct vectors * vecs)
{
	struct multipath * mpp;
	unsigned int i;

	if (!vecs->mpvec)
		return;

	vector_foreach_slot (vecs->mpvec, mpp, i) {
		if (mpp && mpp->alias && !dm_map_present(mpp->alias) &&
		    errno != ENOMEM) {
			condlog(2, "%s: remove dead map", mpp->alias);
			remove_map_and_stop_waiter(mpp, vecs, 1);
			i--;
		}
	}
}

/* This is called after a path has started working again. It the multipath
 * device for this path uses the followover failback type, and this is the
 * best pathgroup, and this is the first path in the pathgroup to come back
 * up, then switch to this pathgroup */
static int
followover_should_failback(struct path * pp)
{
	struct pathgroup * pgp;
	struct path *pp1;
	int i;

	if (pp->mpp->pgfailback != -FAILBACK_FOLLOWOVER ||
	    !pp->mpp->pg || !pp->pgindex ||
	    pp->pgindex != pp->mpp->bestpg)
		return 0;

	pgp = VECTOR_SLOT(pp->mpp->pg, pp->pgindex - 1);
	vector_foreach_slot(pgp->paths, pp1, i) {
		if (pp1 == pp)
			continue;
		if (pp1->chkrstate != PATH_DOWN && pp1->chkrstate != PATH_SHAKY)
			return 0;
	}
	return 1;
}

static void
missing_uev_wait_tick(struct vectors *vecs)
{
	struct multipath * mpp;
	unsigned int i;
	int timed_out = 0;

	vector_foreach_slot (vecs->mpvec, mpp, i) {
		if (mpp->wait_for_udev && --mpp->uev_wait_tick <= 0) {
			timed_out = 1;
			condlog(0, "%s: timeout waiting on creation uevent. enabling reloads", mpp->alias);
			if (mpp->wait_for_udev > 1 && update_map(mpp, vecs)) {
				/* update_map removed map */
				i--;
				continue;
			}
			mpp->wait_for_udev = 0;
		}
	}

	if (timed_out && conf->delayed_reconfig &&
	    !need_to_delay_reconfig(vecs)) {
		condlog(2, "reconfigure (delayed)");
		reconfigure(vecs);
	}
}

static void
ghost_delay_tick(struct vectors *vecs)
{
	struct multipath * mpp;
	unsigned int i;

	vector_foreach_slot (vecs->mpvec, mpp, i) {
		if (mpp->ghost_delay_tick <= 0)
			continue;
		if (--mpp->ghost_delay_tick <= 0) {
			condlog(0, "%s: timed out waiting for active path",
				mpp->alias);
			if (update_map(mpp, vecs) != 0) {
				/* update_map removed map */
				i--;
				continue;
			}
			mpp->ghost_delay = mpp->ghost_delay_tick = 0;
		}
	}
}

static void
defered_failback_tick (vector mpvec)
{
	struct multipath * mpp;
	unsigned int i;

	vector_foreach_slot (mpvec, mpp, i) {
		/*
		 * defered failback getting sooner
		 */
		if (mpp->pgfailback > 0 && mpp->failback_tick > 0) {
			mpp->failback_tick--;

			if (!mpp->failback_tick && need_switch_pathgroup(mpp, 1))
				switch_pathgroup(mpp);
		}
	}
}

static void
retry_count_tick(vector mpvec)
{
	struct multipath *mpp;
	unsigned int i;

	vector_foreach_slot (mpvec, mpp, i) {
		if (mpp->retry_tick) {
			mpp->stat_total_queueing_time++;
			condlog(4, "%s: Retrying.. No active path", mpp->alias);
			if(--mpp->retry_tick == 0) {
				mpp->stat_map_failures++;
				dm_queue_if_no_path(mpp->alias, 0);
				condlog(2, "%s: Disable queueing", mpp->alias);
			}
		}
	}
}

int update_prio(struct path *pp, int refresh_all)
{
	int oldpriority;
	struct path *pp1;
	struct pathgroup * pgp;
	int i, j, changed = 0;

	if (refresh_all) {
		vector_foreach_slot (pp->mpp->pg, pgp, i) {
			vector_foreach_slot (pgp->paths, pp1, j) {
				oldpriority = pp1->priority;
				pathinfo(pp1, conf->hwtable, DI_PRIO);
				if (pp1->priority != oldpriority)
					changed = 1;
			}
		}
		return changed;
	}
	oldpriority = pp->priority;
	if (pp->state != PATH_DOWN)
		pathinfo(pp, conf->hwtable, DI_PRIO);

	if (pp->priority == oldpriority)
		return 0;
	return 1;
}

int update_path_groups(struct multipath *mpp, struct vectors *vecs, int refresh)
{
	condlog(2, "%s: updating path groups %d", mpp->alias, refresh);
	if (reload_map(vecs, mpp, refresh))
		return 1;

	dm_lib_release();
	if (setup_multipath(vecs, mpp) != 0)
		return 1;
	sync_map_state(mpp);

	return 0;
}

int
check_path (struct vectors * vecs, struct path * pp)
{
	int newstate;
	int new_path_up = 0;
	int chkr_new_path_up = 0;
	int disable_reinstate = 0;
	int oldchkrstate = pp->chkrstate;

	if (!pp->mpp && pp->missing_udev_info != INFO_REINIT &&
	    (pp->missing_udev_info != INFO_MISSING ||
	     pp->retriggers >= conf->retrigger_tries))
		return 0;

	if (pp->tick && --pp->tick)
		return 0; /* don't check this path yet */

	if (!pp->mpp && pp->missing_udev_info == INFO_MISSING) {
		pp->missing_udev_info = INFO_REQUESTED;
		pp->retriggers++;
		sysfs_attr_set_value(pp->udev, "uevent", "change",
				     strlen("change"));
		return 0;
	}

	/*
	 * provision a next check soonest,
	 * in case we exit abnormaly from here
	 */
	pp->tick = conf->checkint;

	newstate = path_offline(pp);
	if (!pp->mpp) {
		if (newstate == PATH_UP &&
		    pp->missing_udev_info == INFO_REINIT) {
			int ret;
			condlog(3, "%s: add missing path", pp->dev);
			ret = pathinfo(pp, conf->hwtable,
				       DI_ALL | DI_BLACKLIST);
			if (ret == PATHINFO_OK && strlen(pp->wwid)) {
				ev_add_path(pp, vecs);
				pp->tick = 1;
			} else if (ret == PATHINFO_SKIPPED)
				return -1;
		}
		return 0;
	}
	if (newstate == PATH_UP)
		newstate = get_state(pp, 1, newstate);
	else
		checker_clear_message(&pp->checker);

	if (pp->wwid_changed) {
		condlog(2, "%s: path wwid has changed. Refusing to use",
			pp->dev);
		newstate = PATH_DOWN;
	}

	if (newstate == PATH_WILD || newstate == PATH_UNCHECKED) {
		condlog(2, "%s: unusable path", pp->dev);
		pathinfo(pp, conf->hwtable, 0);
		return 0;
	}
	/*
	 * Async IO in flight. Keep the previous path state
	 * and reschedule as soon as possible
	 */
	if (newstate == PATH_PENDING) {
		pp->tick = 1;
		return 0;
	}
	/*
	 * Synchronize with kernel state
	 */
	if (update_multipath_strings(pp->mpp, vecs->pathvec)) {
		condlog(1, "%s: Could not synchronize with kernel state",
			pp->dev);
		pp->dmstate = PSTATE_UNDEF;
	}
	/* if update_multipath_strings orphaned the path, quit early */
	if (!pp->mpp)
		return 0;

	set_no_path_retry(pp->mpp);

	if ((newstate == PATH_UP || newstate == PATH_GHOST) &&
	    pp->io_err_disable_reinstate && need_io_err_check(pp)) {
		pp->state = PATH_SHAKY;
		/*
		 * to reschedule as soon as possible,so that this path can
		 * be recoverd in time
		 */
		pp->tick = 1;
		return 0;
	}

	if ((newstate == PATH_UP || newstate == PATH_GHOST) &&
	     pp->wait_checks > 0) {
		if (pp->mpp && pp->mpp->nr_active > 0) {
			pp->state = PATH_DELAYED;
			pp->wait_checks--;
			return 0;
		} else
			pp->wait_checks = 0;
	}

	/*
	 * don't reinstate failed path, if its in stand-by
	 * and if target supports only implicit tpgs mode.
	 * this will prevent unnecessary i/o by dm on stand-by
	 * paths if there are no other active paths in map.
	 */
	disable_reinstate = (newstate == PATH_GHOST &&
			    pp->mpp->nr_active == 0 &&
			    pp->tpgs == TPGS_IMPLICIT) ? 1 : 0;

	pp->chkrstate = newstate;
	if (newstate != pp->state) {
		int oldstate = pp->state;
		pp->state = newstate;
		LOG_MSG(1, checker_message(&pp->checker));

		/*
		 * upon state change, reset the checkint
		 * to the shortest delay
		 */
		pp->checkint = conf->checkint;

		if (newstate == PATH_DOWN || newstate == PATH_SHAKY) {
			/*
			 * proactively fail path in the DM
			 */
			if (oldstate == PATH_UP ||
			    oldstate == PATH_GHOST) {
				fail_path(pp, 1);
				if (pp->mpp->delay_wait_checks > 0 &&
				    pp->watch_checks > 0) {
					pp->wait_checks = pp->mpp->delay_wait_checks;
					pp->watch_checks = 0;
				}
			}else
				fail_path(pp, 0);

			/*
			 * cancel scheduled failback
			 */
			pp->mpp->failback_tick = 0;

			pp->mpp->stat_path_failures++;
			return 0;
		}

		if(newstate == PATH_UP || newstate == PATH_GHOST){
		 	/*
			 * Reinitialize the prioritizer, in case something
		 	 * changed.
		 	 */
			prio_init(&pp->prio);
			if ( pp->mpp && pp->mpp->prflag ){
				/*
				 * Check Persistent Reservation.
				 */
			condlog(2, "%s: checking persistent reservation "
				"registration", pp->dev);
			mpath_pr_event_handle(pp);
			}
		}

		/*
		 * reinstate this path
		 */
		if (!disable_reinstate) {
			if (oldstate != PATH_UP &&
			    oldstate != PATH_GHOST) {
				if (pp->mpp->delay_watch_checks > 0)
					pp->watch_checks = pp->mpp->delay_watch_checks;
				reinstate_path(pp, 1);
			} else {
				if (pp->watch_checks > 0)
					pp->watch_checks--;
				reinstate_path(pp, 0);
			}
		}
		new_path_up = 1;

		if (oldchkrstate != PATH_UP && oldchkrstate != PATH_GHOST)
			chkr_new_path_up = 1;

		/*
		 * if at least one path is up in a group, and
		 * the group is disabled, re-enable it
		 */
		if (newstate == PATH_UP)
			enable_group(pp);
	}
	else if (newstate == PATH_UP || newstate == PATH_GHOST) {
		if ((pp->dmstate == PSTATE_FAILED ||
		    pp->dmstate == PSTATE_UNDEF) &&
		    !disable_reinstate) {
			/* Clear IO errors */
			reinstate_path(pp, 0);
		} else {
			LOG_MSG(4, checker_message(&pp->checker));
			if (pp->checkint != conf->max_checkint) {
				/*
				 * double the next check delay.
				 * max at conf->max_checkint
				 */
				if (pp->checkint < (conf->max_checkint / 2))
					pp->checkint = 2 * pp->checkint;
				else
					pp->checkint = conf->max_checkint;
			}
			if (pp->watch_checks > 0)
				pp->watch_checks--;
			pp->tick = pp->checkint;
			condlog(4, "%s: delay next check %is",
				pp->dev_t, pp->tick);
		}
	}
	else if (newstate == PATH_DOWN) {
		if (conf->log_checker_err == LOG_CHKR_ERR_ONCE)
			LOG_MSG(3, checker_message(&pp->checker));
		else
			LOG_MSG(2, checker_message(&pp->checker));
	}

	pp->state = newstate;


	if (pp->mpp->wait_for_udev)
		return 0;
	/*
	 * path prio refreshing
	 */
	condlog(4, "path prio refresh");

	if (update_prio(pp, new_path_up) &&
	    (pp->mpp->pgpolicyfn == (pgpolicyfn *)group_by_prio) &&
	     pp->mpp->pgfailback == -FAILBACK_IMMEDIATE)
		update_path_groups(pp->mpp, vecs, !new_path_up);
	else if (need_switch_pathgroup(pp->mpp, 0)) {
		if (pp->mpp->pgfailback > 0 &&
		    (new_path_up || pp->mpp->failback_tick <= 0))
			pp->mpp->failback_tick =
				pp->mpp->pgfailback + 1;
		else if (pp->mpp->pgfailback == -FAILBACK_IMMEDIATE ||
			 (chkr_new_path_up && followover_should_failback(pp)))
			switch_pathgroup(pp->mpp);
	}
	return 0;
}

static void *
checkerloop (void *ap)
{
	struct vectors *vecs;
	struct path *pp;
	int count = 0;
	unsigned int i;

	mlockall(MCL_CURRENT | MCL_FUTURE);
	vecs = (struct vectors *)ap;
	condlog(2, "path checkers start up");

	/*
	 * init the path check interval
	 */
	vector_foreach_slot (vecs->pathvec, pp, i) {
		pp->checkint = conf->checkint;
	}

	while (1) {
		pthread_cleanup_push(cleanup_lock, &vecs->lock);
		lock(vecs->lock);
		pthread_testcancel();
		condlog(4, "tick");

		if (vecs->pathvec) {
			vector_foreach_slot (vecs->pathvec, pp, i) {
				int rc = check_path(vecs, pp);
				if (rc < 0) {
					vector_del_slot(vecs->pathvec, i);
					free_path(pp);
					i--;
				}
			}
		}
		if (vecs->mpvec) {
			defered_failback_tick(vecs->mpvec);
			retry_count_tick(vecs->mpvec);
			missing_uev_wait_tick(vecs);
			ghost_delay_tick(vecs);
		}
		if (count)
			count--;
		else {
			condlog(4, "map garbage collection");
			mpvec_garbage_collector(vecs);
			count = MAPGCINT;
		}

		lock_cleanup_pop(vecs->lock);
		sleep(1);
	}
	return NULL;
}

int
configure (struct vectors * vecs, int start_waiters)
{
	struct multipath * mpp;
	struct path * pp;
	vector mpvec;
	int i, ret;

	if (!vecs->pathvec && !(vecs->pathvec = vector_alloc())) {
		condlog(0, "couldn't allocate path vec in configure");
		return 1;
	}

	if (!vecs->mpvec && !(vecs->mpvec = vector_alloc())) {
		condlog(0, "couldn't allocate multipath vec in configure");
		return 1;
	}

	if (!(mpvec = vector_alloc())) {
		condlog(0, "couldn't allocate new maps vec in configure");
		return 1;
	}

	/*
	 * probe for current path (from sysfs) and map (from dm) sets
	 */
	ret = path_discovery(vecs->pathvec, conf, DI_ALL);
	if (ret < 0) {
		condlog(0, "configure failed at path discovery");
		return 1;
	}

	vector_foreach_slot (vecs->pathvec, pp, i){
		if (filter_path(conf, pp) > 0){
			vector_del_slot(vecs->pathvec, i);
			free_path(pp);
			i--;
		}
		else
			pp->checkint = conf->checkint;
	}
	if (map_discovery(vecs)) {
		condlog(0, "configure failed at map discovery");
		return 1;
	}

	/*
	 * create new set of maps & push changed ones into dm
	 */
	if (coalesce_paths(vecs, mpvec, NULL, 1)) {
		condlog(0, "configure failed while coalescing paths");
		return 1;
	}

	/*
	 * may need to remove some maps which are no longer relevant
	 * e.g., due to blacklist changes in conf file
	 */
	if (coalesce_maps(vecs, mpvec)) {
		condlog(0, "configure failed while coalescing maps");
		return 1;
	}

	dm_lib_release();

	sync_maps_state(mpvec);
	vector_foreach_slot(mpvec, mpp, i){
		if (remember_wwid(mpp->wwid) > 0)
			trigger_uevents(mpp);
		update_map_pr(mpp);
	}

	/*
	 * purge dm of old maps
	 */
	remove_maps(vecs);

	/*
	 * save new set of maps formed by considering current path state
	 */
	vector_free(vecs->mpvec);
	vecs->mpvec = mpvec;

	/*
	 * start dm event waiter threads for these new maps
	 */
	vector_foreach_slot(vecs->mpvec, mpp, i) {
		if (setup_multipath(vecs, mpp)) {
			i--;
			continue;
		}
		if (start_waiters)
			if (start_waiter_thread(mpp, vecs)) {
				remove_map(mpp, vecs, 1);
				i--;
			}
	}
	return 0;
}

int
need_to_delay_reconfig(struct vectors * vecs)
{
	struct multipath *mpp;
	int i;

	if (!VECTOR_SIZE(vecs->mpvec))
		return 0;

	vector_foreach_slot(vecs->mpvec, mpp, i) {
		if (mpp->wait_for_udev)
			return 1;
	}
	return 0;
}

int
reconfigure (struct vectors * vecs)
{
	struct config * old = conf;
	int retval = 1;

	/*
	 * free old map and path vectors ... they use old conf state
	 */
	if (VECTOR_SIZE(vecs->mpvec))
		remove_maps_and_stop_waiters(vecs);

	if (VECTOR_SIZE(vecs->pathvec))
		free_pathvec(vecs->pathvec, FREE_PATHS);

	vecs->pathvec = NULL;
	conf = NULL;

	if (!load_config(DEFAULT_CONFIGFILE, udev)) {
		conf->verbosity = old->verbosity;
		conf->daemon = 1;
		configure(vecs, 1);
		free_config(old);
		retval = 0;
	}
	update_timestamp(0);

	return retval;
}

static struct vectors *
init_vecs (void)
{
	struct vectors * vecs;

	vecs = (struct vectors *)MALLOC(sizeof(struct vectors));

	if (!vecs)
		return NULL;

	vecs->lock.mutex =
		(pthread_mutex_t *)MALLOC(sizeof(pthread_mutex_t));

	if (!vecs->lock.mutex)
		goto out;

	pthread_mutex_init(vecs->lock.mutex, NULL);
	vecs->lock.depth = 0;

	return vecs;

out:
	FREE(vecs);
	condlog(0, "failed to init paths");
	return NULL;
}

static void *
signal_set(int signo, void (*func) (int))
{
	int r;
	struct sigaction sig;
	struct sigaction osig;

	sig.sa_handler = func;
	sigemptyset(&sig.sa_mask);
	sig.sa_flags = 0;

	r = sigaction(signo, &sig, &osig);

	if (r < 0)
		return (SIG_ERR);
	else
		return (osig.sa_handler);
}

void
handle_signals(void)
{
	if (reconfig_sig && running_state == DAEMON_RUNNING) {
		pthread_cleanup_push(cleanup_lock,
				&gvecs->lock);
		lock(gvecs->lock);
		pthread_testcancel();
		if (need_to_delay_reconfig(gvecs)) {
			conf->delayed_reconfig = 1;
			condlog(2, "delaying reconfigure (signal)");
		}
		else {
			condlog(2, "reconfigure (signal)");
			reconfigure(gvecs);
		}
		lock_cleanup_pop(gvecs->lock);
	}
	if (log_reset_sig) {
		condlog(2, "reset log (signal)");
		pthread_mutex_lock(&logq_lock);
		log_reset("multipathd");
		pthread_mutex_unlock(&logq_lock);
	}
	reconfig_sig = 0;
	log_reset_sig = 0;
}

static void
sighup (int sig)
{
	reconfig_sig = 1;
}

static void
sigend (int sig)
{
	exit_daemon();
}

static void
sigusr1 (int sig)
{
	log_reset_sig = 1;
}

static void
sigusr2 (int sig)
{
	condlog(3, "SIGUSR2 received");
}

static void
sigalrm (int sig)
{
	exit(0);
}

static void
signal_init(void)
{
	sigset_t set;

	sigemptyset(&set);
	sigaddset(&set, SIGHUP);
	sigaddset(&set, SIGUSR1);
	sigaddset(&set, SIGUSR2);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	signal_set(SIGHUP, sighup);
	signal_set(SIGUSR1, sigusr1);
	signal_set(SIGUSR2, sigusr2);
	signal_set(SIGINT, sigend);
	signal_set(SIGTERM, sigend);
	signal(SIGPIPE, SIG_IGN);
}

static void
setscheduler (void)
{
	int res;
	static struct sched_param sched_param = {
		.sched_priority = 99
	};

	res = sched_setscheduler (0, SCHED_RR, &sched_param);

	if (res == -1)
		condlog(LOG_WARNING, "Could not set SCHED_RR at priority 99");
	return;
}

static void
set_oom_adj (void)
{
#ifdef OOM_SCORE_ADJ_MIN
	int retry = 1;
	char *file = "/proc/self/oom_score_adj";
	int score = OOM_SCORE_ADJ_MIN;
#else
	int retry = 0;
	char *file = "/proc/self/oom_adj";
	int score = OOM_ADJUST_MIN;
#endif
	FILE *fp;
	struct stat st;

	do {
		if (stat(file, &st) == 0){
			fp = fopen(file, "w");
			if (!fp) {
				condlog(0, "couldn't fopen %s : %s", file,
					strerror(errno));
				return;
			}
			fprintf(fp, "%i", score);
			fclose(fp);
			return;
		}
		if (errno != ENOENT) {
			condlog(0, "couldn't stat %s : %s", file,
				strerror(errno));
			return;
		}
#ifdef OOM_ADJUST_MIN
		file = "/proc/self/oom_adj";
		score = OOM_ADJUST_MIN;
#else
		retry = 0;
#endif
	} while (retry--);
	condlog(0, "couldn't adjust oom score");
}

static int
child (void * param)
{
	pthread_t check_thr, uevent_thr, uxlsnr_thr, uevq_thr;
	pthread_attr_t log_attr, misc_attr, uevent_attr;
	struct vectors * vecs;
	struct multipath * mpp;
	int i;
	int rc, pid_rc;

	mlockall(MCL_CURRENT | MCL_FUTURE);
	sem_init(&exit_sem, 0, 0);
	signal_init();

	udev = udev_new();

	setup_thread_attr(&misc_attr, 64 * 1024, 1);
	setup_thread_attr(&uevent_attr, 128 * 1024, 1);
	setup_thread_attr(&waiter_attr, 32 * 1024, 1);
	setup_thread_attr(&io_err_stat_attr, 32 * 1024, 0);

	if (logsink) {
		setup_thread_attr(&log_attr, 64 * 1024, 0);
		log_thread_start(&log_attr);
		pthread_attr_destroy(&log_attr);
	}

	running_state = DAEMON_START;
	pid_rc = pidfile_create(DEFAULT_PIDFILE, daemon_pid);
	if (parent_pid > 0)
		kill(parent_pid, SIGALRM);

	condlog(2, "--------start up--------");
	condlog(2, "read " DEFAULT_CONFIGFILE);

	if (load_config(DEFAULT_CONFIGFILE, udev)) {
		condlog(0, "failed to load config");
		if (logsink)
			log_thread_stop();
		exit(1);
	}

	if (init_checkers()) {
		condlog(0, "failed to initialize checkers");
		if (logsink)
			log_thread_stop();
		exit(1);
	}
	if (init_prio()) {
		condlog(0, "failed to initialize prioritizers");
		if (logsink)
			log_thread_stop();
		exit(1);
	}

	setlogmask(LOG_UPTO(conf->verbosity + 3));

	set_max_fds(conf->max_fds);

	vecs = gvecs = init_vecs();
	if (!vecs) {
		condlog(0, "failed to create vecs");
		if (logsink)
			log_thread_stop();
		exit(1);
	}

	setscheduler();
	set_oom_adj();

	conf->daemon = 1;
	udev_set_sync_support(0);
	/*
	 * Start uevent listener early to catch events
	 */
	if ((rc = pthread_create(&uevent_thr, &uevent_attr, ueventloop, udev))) {
		condlog(0, "failed to create uevent thread: %d", rc);
		if (logsink)
			log_thread_stop();
		exit(1);
	}
	pthread_attr_destroy(&uevent_attr);
	if ((rc = pthread_create(&uxlsnr_thr, &misc_attr, uxlsnrloop, vecs))) {
		condlog(0, "failed to create cli listener: %d", rc);
		if (logsink)
			log_thread_stop();
		exit(1);
	}
	/*
	 * fetch and configure both paths and multipaths
	 */
	running_state = DAEMON_CONFIGURE;

	lock(vecs->lock);
	if (configure(vecs, 1)) {
		unlock(vecs->lock);
		condlog(0, "failure during configuration");
		if (logsink)
			log_thread_stop();
		exit(1);
	}
	unlock(vecs->lock);

	/*
	 * start threads
	 */
	if ((rc = pthread_create(&check_thr, &misc_attr, checkerloop, vecs))) {
		condlog(0,"failed to create checker loop thread: %d", rc);
		if (logsink)
			log_thread_stop();
		exit(1);
	}
	if ((rc = pthread_create(&uevq_thr, &misc_attr, uevqloop, vecs))) {
		condlog(0, "failed to create uevent dispatcher: %d", rc);
		if (logsink)
			log_thread_stop();
		exit(1);
	}
	pthread_attr_destroy(&misc_attr);

	update_timestamp(1);
	/* Ignore errors, we can live without */

	running_state = DAEMON_RUNNING;

	/*
	 * exit path
	 */
	while(sem_wait(&exit_sem) != 0); /* Do nothing */
	running_state = DAEMON_SHUTDOWN;
	lock(vecs->lock);
	if (conf->queue_without_daemon == QUE_NO_DAEMON_OFF)
		vector_foreach_slot(vecs->mpvec, mpp, i)
			dm_queue_if_no_path(mpp->alias, 0);
	remove_maps_and_stop_waiters(vecs);
	unlock(vecs->lock);

	pthread_cancel(check_thr);
	pthread_cancel(uevent_thr);
	pthread_cancel(uxlsnr_thr);
	pthread_cancel(uevq_thr);

	lock(vecs->lock);
	free_pathvec(vecs->pathvec, FREE_PATHS);
	vecs->pathvec = NULL;
	unlock(vecs->lock);
	/* Now all the waitevent threads will start rushing in. */
	/* freeing vecs isn't worth the races
	while (vecs->lock.depth > 0) {
		sleep (1);
		condlog(3, "Have %d wait event checkers threads to de-alloc,"
			" waiting...", vecs->lock.depth);
	}
	pthread_mutex_destroy(vecs->lock.mutex);
	FREE(vecs->lock.mutex);
	vecs->lock.depth = 0;
	vecs->lock.mutex = NULL;
	FREE(vecs);
	vecs = NULL;
	*/
	cleanup_checkers();
	cleanup_prio();
	stop_io_err_stat_thread();
	pthread_attr_destroy(&io_err_stat_attr);

	dm_lib_release();
	dm_lib_exit();

	/* We're done here */
	if (!pid_rc) {
		condlog(3, "unlink pidfile");
		unlink(DEFAULT_PIDFILE);
		unlink(DEFAULT_TIMESTAMP_FILE);
	}

	condlog(2, "--------shut down-------");

	if (logsink)
		log_thread_stop();

	/*
	 * Freeing config must be done after condlog() and dm_lib_exit(),
	 * because logging functions like dlog() and dm_write_log()
	 * reference the config.
	 */
	free_config(conf);
	conf = NULL;
	udev_unref(udev);
	udev = NULL;
#ifdef _DEBUG_
	dbg_free_final(NULL);
#endif

	exit(0);
}

static int
daemonize(void)
{
	int pid;
	int dev_null_fd;
	struct sigaction oldsig;

	oldsig.sa_handler = signal_set(SIGALRM, sigalrm);
	parent_pid = getpid();
	if( (pid = fork()) < 0){
		fprintf(stderr, "Failed first fork : %s\n", strerror(errno));
		return -1;
	}
	else if (pid != 0)
		return pid;

	signal_set(SIGALRM, oldsig.sa_handler);
	setsid();

	if ( (pid = fork()) < 0) {
		fprintf(stderr, "Failed second fork : %s\n", strerror(errno));
		goto fail;
	}
	else if (pid != 0)
		_exit(0);

	if (chdir("/") < 0)
		fprintf(stderr, "cannot chdir to '/', continuing\n");

	dev_null_fd = open("/dev/null", O_RDWR);
	if (dev_null_fd < 0){
		fprintf(stderr, "cannot open /dev/null for input & output : %s\n",
			strerror(errno));
		goto fail;
	}

	close(STDIN_FILENO);
	if (dup(dev_null_fd) < 0) {
		fprintf(stderr, "cannot dup /dev/null to stdin : %s\n",
			strerror(errno));
		goto fail;
	}
	close(STDOUT_FILENO);
	if (dup(dev_null_fd) < 0) {
		fprintf(stderr, "cannot dup /dev/null to stdout : %s\n",
			strerror(errno));
		goto fail;
	}
	close(STDERR_FILENO);
	if (dup(dev_null_fd) < 0) {
		fprintf(stderr, "cannot dup /dev/null to stderr : %s\n",
			strerror(errno));
		goto fail;
	}
	close(dev_null_fd);
	daemon_pid = getpid();
	return 0;

fail:
	kill(parent_pid, SIGALRM);
	_exit(0);
}

int
main (int argc, char *argv[])
{
	extern char *optarg;
	extern int optind;
	int arg;
	int err;

	logsink = 1;
	running_state = DAEMON_INIT;
	dm_init();

	if (getuid() != 0) {
		fprintf(stderr, "need to be root\n");
		exit(1);
	}

	/* make sure we don't lock any path */
	if (chdir("/") < 0)
		fprintf(stderr, "can't chdir to root directory : %s\n",
			strerror(errno));
	umask(umask(077) | 022);

	conf = alloc_config();

	if (!conf)
		exit(1);

	while ((arg = getopt(argc, argv, ":dv:k::B")) != EOF ) {
	switch(arg) {
		case 'd':
			logsink = 0;
			//debug=1; /* ### comment me out ### */
			break;
		case 'v':
			if (sizeof(optarg) > sizeof(char *) ||
			    !isdigit(optarg[0]))
				exit(1);

			conf->verbosity = atoi(optarg);
			break;
		case 'k':
			return(uxclnt(optarg));
		case 'B':
			conf->bindings_read_only = 1;
			break;
		default:
			;
		}
	}
	if (optind < argc) {
		char cmd[CMDSIZE];
		char * s = cmd;
		char * c = s;

		while (optind < argc) {
			if (strchr(argv[optind], ' '))
				c += snprintf(c, s + CMDSIZE - c, "\"%s\" ", argv[optind]);
			else
				c += snprintf(c, s + CMDSIZE - c, "%s ", argv[optind]);
			optind++;
		}
		c += snprintf(c, s + CMDSIZE - c, "\n");
		return(uxclnt(s));
	}

	if (!logsink)
		err = 0;
	else
		err = daemonize();

	if (err < 0)
		/* error */
		exit(1);
	else if (err > 0) {
		/* wait up to 3 seconds for the child to start */
		sleep(3);
		/* parent dies */
		exit(0);
	} else
		/* child lives */
		return (child(NULL));
}

void *  mpath_pr_event_handler_fn (void * pathp )
{
	struct multipath * mpp;
	int i, ret, isFound;
	struct path * pp = (struct path *)pathp;
	struct prout_param_descriptor *param;
	struct prin_resp *resp;

	mpp = pp->mpp;

	resp = mpath_alloc_prin_response(MPATH_PRIN_RKEY_SA);
	if (!resp){
		condlog(0,"%s Alloc failed for prin response", pp->dev);
		return NULL;
	}

	ret = prin_do_scsi_ioctl(pp->dev, MPATH_PRIN_RKEY_SA, resp, 0);
	if (ret != MPATH_PR_SUCCESS )
	{
		condlog(0,"%s : pr in read keys service action failed. Error=%d", pp->dev, ret);
		goto out;
	}

	condlog(3, " event pr=%d addlen=%d",resp->prin_descriptor.prin_readkeys.prgeneration,
			resp->prin_descriptor.prin_readkeys.additional_length );

	if (resp->prin_descriptor.prin_readkeys.additional_length == 0 )
	{
		condlog(1, "%s: No key found. Device may not be registered.", pp->dev);
		ret = MPATH_PR_SUCCESS;
		goto out;
	}
	condlog(2, "Multipath  reservation_key: 0x%" PRIx64 " ",
		get_be64(mpp->reservation_key));

	isFound =0;
	for (i = 0; i < resp->prin_descriptor.prin_readkeys.additional_length/8; i++ )
	{
		condlog(2, "PR IN READKEYS[%d]  reservation key:",i);
		dumpHex((char *)&resp->prin_descriptor.prin_readkeys.key_list[i*8], 8 , -1);
		if (!memcmp(&mpp->reservation_key, &resp->prin_descriptor.prin_readkeys.key_list[i*8], 8))
		{
			condlog(2, "%s: pr key found in prin readkeys response", mpp->alias);
			isFound =1;
			break;
		}
	}
	if (!isFound)
	{
		condlog(0, "%s: Either device not registered or ", pp->dev);
		condlog(0, "host is not authorised for registration. Skip path");
		ret = MPATH_PR_OTHER;
		goto out;
	}

	param= malloc(sizeof(struct prout_param_descriptor));
	memset(param, 0 , sizeof(struct prout_param_descriptor));
	param->sa_flags = mpp->sa_flags;
	memcpy(param->sa_key, &mpp->reservation_key, 8);
	param->num_transportid = 0;

	condlog(3, "device %s:%s", pp->dev, pp->mpp->wwid);

	ret = prout_do_scsi_ioctl(pp->dev, MPATH_PROUT_REG_IGN_SA, 0, 0, param, 0);
	if (ret != MPATH_PR_SUCCESS )
	{
		condlog(0,"%s: Reservation registration failed. Error: %d", pp->dev, ret);
	}
	mpp->prflag = 1;

	free(param);
out:
	free(resp);
	return NULL;
}

int mpath_pr_event_handle(struct path *pp)
{
	pthread_t thread;
	int rc;
	pthread_attr_t attr;
	struct multipath * mpp;

	mpp = pp->mpp;

	if (!get_be64(mpp->reservation_key))
		return -1;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	rc = pthread_create(&thread, NULL , mpath_pr_event_handler_fn, pp);
	if (rc) {
		condlog(0, "%s: ERROR; return code from pthread_create() is %d", pp->dev, rc);
		return -1;
	}
	pthread_attr_destroy(&attr);
	rc = pthread_join(thread, NULL);
	return 0;
}

