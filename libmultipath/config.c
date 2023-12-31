/*
 * Copyright (c) 2004, 2005 Christophe Varoqui
 * Copyright (c) 2005 Benjamin Marzinski, Redhat
 * Copyright (c) 2005 Edward Goggin, EMC
 */
#include <stdio.h>
#include <string.h>
#include <libudev.h>
#include <dirent.h>
#include <limits.h>
#include <errno.h>

#include "checkers.h"
#include "memory.h"
#include "util.h"
#include "debug.h"
#include "parser.h"
#include "dict.h"
#include "hwtable.h"
#include "vector.h"
#include "structs.h"
#include "config.h"
#include "blacklist.h"
#include "defaults.h"
#include "prio.h"
#include "devmapper.h"
#include "version.h"
#include "mpath_cmd.h"

static int
hwe_strmatch (struct hwentry *hwe1, struct hwentry *hwe2)
{
	if ((hwe2->vendor && !hwe1->vendor) ||
	    (hwe1->vendor && (!hwe2->vendor ||
			      strcmp(hwe1->vendor, hwe2->vendor))))
		return 1;

	if ((hwe2->product && !hwe1->product) ||
	    (hwe1->product && (!hwe2->product ||
			      strcmp(hwe1->product, hwe2->product))))
		return 1;

	if ((hwe2->revision && !hwe1->revision) ||
	    (hwe1->revision && (!hwe2->revision ||
			      strcmp(hwe1->revision, hwe2->revision))))
		return 1;

	return 0;
}

static struct hwentry *
find_hwe_strmatch (vector hwtable, struct hwentry *hwe)
{
	int i;
	struct hwentry *tmp, *ret = NULL;

	vector_foreach_slot (hwtable, tmp, i) {
		if (hwe_strmatch(tmp, hwe))
			continue;
		ret = tmp;
		break;
	}
	return ret;
}

static int
hwe_regmatch (struct hwentry *hwe1, struct hwentry *hwe2)
{
	regex_t vre, pre, rre;
	int retval = 1;

	if (hwe1->vendor &&
	    regcomp(&vre, hwe1->vendor, REG_EXTENDED|REG_NOSUB))
		goto out;

	if (hwe1->product &&
	    regcomp(&pre, hwe1->product, REG_EXTENDED|REG_NOSUB))
		goto out_vre;

	if (hwe1->revision &&
	    regcomp(&rre, hwe1->revision, REG_EXTENDED|REG_NOSUB))
		goto out_pre;

	if ((!hwe1->vendor || !hwe2->vendor ||
	     !regexec(&vre, hwe2->vendor, 0, NULL, 0)) &&
	    (!hwe1->product || !hwe2->product ||
	     !regexec(&pre, hwe2->product, 0, NULL, 0)) &&
	    (!hwe1->revision || !hwe2->revision ||
	     !regexec(&rre, hwe2->revision, 0, NULL, 0)))
		retval = 0;

	if (hwe1->revision)
		regfree(&rre);
out_pre:
	if (hwe1->product)
		regfree(&pre);
out_vre:
	if (hwe1->vendor)
		regfree(&vre);
out:
	return retval;
}

struct hwentry *
find_hwe (vector hwtable, char * vendor, char * product, char * revision)
{
	int i;
	struct hwentry hwe, *tmp, *ret = NULL;

	hwe.vendor = vendor;
	hwe.product = product;
	hwe.revision = revision;
	/*
	 * Search backwards here.
	 * User modified entries are attached at the end of
	 * the list, so we have to check them first before
	 * continuing to the generic entries
	 */
	vector_foreach_slot_backwards (hwtable, tmp, i) {
		if (tmp->all_devs == 1)
			continue;
		if (hwe_regmatch(tmp, &hwe))
			continue;
		ret = tmp;
		break;
	}
	return ret;
}

extern struct mpentry *
find_mpe (char * wwid)
{
	int i;
	struct mpentry * mpe;

	if (!wwid)
		return NULL;

	vector_foreach_slot (conf->mptable, mpe, i)
		if (mpe->wwid && !strcmp(mpe->wwid, wwid))
			return mpe;

	return NULL;
}

extern char *
get_mpe_wwid (char * alias)
{
	int i;
	struct mpentry * mpe;

	if (!alias)
		return NULL;

	vector_foreach_slot (conf->mptable, mpe, i)
		if (mpe->alias && strcmp(mpe->alias, alias) == 0)
			return mpe->wwid;

	return NULL;
}

void
free_hwe (struct hwentry * hwe)
{
	if (!hwe)
		return;

	if (hwe->vendor)
		FREE(hwe->vendor);

	if (hwe->product)
		FREE(hwe->product);

	if (hwe->revision)
		FREE(hwe->revision);

	if (hwe->uid_attribute)
		FREE(hwe->uid_attribute);

	if (hwe->features)
		FREE(hwe->features);

	if (hwe->hwhandler)
		FREE(hwe->hwhandler);

	if (hwe->selector)
		FREE(hwe->selector);

	if (hwe->checker_name)
		FREE(hwe->checker_name);

	if (hwe->prio_name)
		FREE(hwe->prio_name);

	if (hwe->prio_args)
		FREE(hwe->prio_args);

	if (hwe->alias_prefix)
		FREE(hwe->alias_prefix);

	if (hwe->bl_product)
		FREE(hwe->bl_product);

	FREE(hwe);
}

void
free_hwtable (vector hwtable)
{
	int i;
	struct hwentry * hwe;

	if (!hwtable)
		return;

	vector_foreach_slot (hwtable, hwe, i)
		free_hwe(hwe);

	vector_free(hwtable);
}

void
free_mpe (struct mpentry * mpe)
{
	if (!mpe)
		return;

	if (mpe->wwid)
		FREE(mpe->wwid);

	if (mpe->selector)
		FREE(mpe->selector);

	if (mpe->uid_attribute)
		FREE(mpe->uid_attribute);

	if (mpe->alias)
		FREE(mpe->alias);

	if (mpe->prio_name)
		FREE(mpe->prio_name);

	if (mpe->prio_args)
		FREE(mpe->prio_args);

	FREE(mpe);
}

void
free_mptable (vector mptable)
{
	int i;
	struct mpentry * mpe;

	if (!mptable)
		return;

	vector_foreach_slot (mptable, mpe, i)
		free_mpe(mpe);

	vector_free(mptable);
}

struct mpentry *
alloc_mpe (void)
{
	struct mpentry * mpe = (struct mpentry *)
				MALLOC(sizeof(struct mpentry));

	return mpe;
}

struct hwentry *
alloc_hwe (void)
{
	struct hwentry * hwe = (struct hwentry *)
				MALLOC(sizeof(struct hwentry));

	return hwe;
}

static char *
set_param_str(char * str)
{
	char * dst;
	int len;

	if (!str)
		return NULL;

	len = strlen(str);

	if (!len)
		return NULL;

	dst = (char *)MALLOC(len + 1);

	if (!dst)
		return NULL;

	strcpy(dst, str);
	return dst;
}

#define merge_str(s) \
	if (!dst->s && src->s) { \
		if (!(dst->s = set_param_str(src->s))) \
			return 1; \
	}

#define merge_num(s) \
	if (!dst->s && src->s) \
		dst->s = src->s


static int
merge_hwe (struct hwentry * dst, struct hwentry * src)
{
	merge_str(vendor);
	merge_str(product);
	merge_str(revision);
	merge_str(uid_attribute);
	merge_str(features);
	merge_str(hwhandler);
	merge_str(selector);
	merge_str(checker_name);
	merge_str(prio_name);
	merge_str(prio_args);
	merge_str(alias_prefix);
	merge_str(bl_product);
	merge_num(pgpolicy);
	merge_num(pgfailback);
	merge_num(rr_weight);
	merge_num(no_path_retry);
	merge_num(minio);
	merge_num(minio_rq);
	merge_num(pg_timeout);
	merge_num(flush_on_last_del);
	merge_num(fast_io_fail);
	merge_num(dev_loss);
	merge_num(user_friendly_names);
	merge_num(retain_hwhandler);
	merge_num(detect_prio);
	merge_num(detect_checker);
	merge_num(deferred_remove);
	merge_num(delay_watch_checks);
	merge_num(delay_wait_checks);
	merge_num(skip_kpartx);
	merge_num(max_sectors_kb);
	merge_num(unpriv_sgio);
	merge_num(ghost_delay);
	merge_num(all_tg_pt);

	/*
	 * Make sure features is consistent with
	 * no_path_retry
	 */
	if (dst->no_path_retry == NO_PATH_RETRY_FAIL)
		remove_feature(&dst->features, "queue_if_no_path");
	else if (dst->no_path_retry != NO_PATH_RETRY_UNDEF)
		add_feature(&dst->features, "queue_if_no_path");

	return 0;
}

#define overwrite_str(s) \
do { \
	if (src->s) { \
		if (dst->s) \
			FREE(dst->s); \
		if (!(dst->s = set_param_str(src->s))) \
			return 1; \
	} \
} while(0)

#define overwrite_num(s) \
do { \
	if (src->s) \
		dst->s = src->s; \
} while(0)

static int
overwrite_hwe (struct hwentry * dst, struct hwentry * src)
{
	overwrite_str(vendor);
	overwrite_str(product);
	overwrite_str(revision);
	overwrite_str(uid_attribute);
	overwrite_str(features);
	overwrite_str(hwhandler);
	overwrite_str(selector);
	overwrite_str(checker_name);
	overwrite_str(prio_name);
	overwrite_str(prio_args);
	overwrite_str(alias_prefix);
	overwrite_str(bl_product);
	overwrite_num(pgpolicy);
	overwrite_num(pgfailback);
	overwrite_num(rr_weight);
	overwrite_num(no_path_retry);
	overwrite_num(minio);
	overwrite_num(minio_rq);
	overwrite_num(pg_timeout);
	overwrite_num(flush_on_last_del);
	overwrite_num(fast_io_fail);
	overwrite_num(dev_loss);
	overwrite_num(user_friendly_names);
	overwrite_num(retain_hwhandler);
	overwrite_num(detect_prio);
	overwrite_num(detect_checker);
	overwrite_num(deferred_remove);
	overwrite_num(delay_watch_checks);
	overwrite_num(delay_wait_checks);
	overwrite_num(skip_kpartx);
	overwrite_num(max_sectors_kb);
	overwrite_num(unpriv_sgio);
	overwrite_num(ghost_delay);
	overwrite_num(all_tg_pt);

	/*
	 * Make sure features is consistent with
	 * no_path_retry
	 */
	if (dst->no_path_retry == NO_PATH_RETRY_FAIL)
		remove_feature(&dst->features, "queue_if_no_path");
	else if (dst->no_path_retry != NO_PATH_RETRY_UNDEF)
		add_feature(&dst->features, "queue_if_no_path");
	return 0;
}

int
store_hwe (vector hwtable, struct hwentry * dhwe)
{
	struct hwentry * hwe;

	if (find_hwe_strmatch(hwtable, dhwe))
		return 0;

	if (!(hwe = alloc_hwe()))
		return 1;

	if (!dhwe->vendor || !(hwe->vendor = set_param_str(dhwe->vendor)))
		goto out;

	if (!dhwe->product || !(hwe->product = set_param_str(dhwe->product)))
		goto out;

	if (dhwe->revision && !(hwe->revision = set_param_str(dhwe->revision)))
		goto out;

	if (dhwe->uid_attribute && !(hwe->uid_attribute = set_param_str(dhwe->uid_attribute)))
		goto out;

	if (dhwe->features && !(hwe->features = set_param_str(dhwe->features)))
		goto out;

	if (dhwe->hwhandler && !(hwe->hwhandler = set_param_str(dhwe->hwhandler)))
		goto out;

	if (dhwe->selector && !(hwe->selector = set_param_str(dhwe->selector)))
		goto out;

	if (dhwe->checker_name && !(hwe->checker_name = set_param_str(dhwe->checker_name)))
		goto out;

	if (dhwe->prio_name && !(hwe->prio_name = set_param_str(dhwe->prio_name)))
		goto out;

	if (dhwe->prio_args && !(hwe->prio_args = set_param_str(dhwe->prio_args)))
		goto out;

	if (dhwe->alias_prefix && !(hwe->alias_prefix = set_param_str(dhwe->alias_prefix)))
		goto out;

	hwe->pgpolicy = dhwe->pgpolicy;
	hwe->pgfailback = dhwe->pgfailback;
	hwe->rr_weight = dhwe->rr_weight;
	hwe->no_path_retry = dhwe->no_path_retry;
	hwe->minio = dhwe->minio;
	hwe->minio_rq = dhwe->minio_rq;
	hwe->pg_timeout = dhwe->pg_timeout;
	hwe->flush_on_last_del = dhwe->flush_on_last_del;
	hwe->fast_io_fail = dhwe->fast_io_fail;
	hwe->dev_loss = dhwe->dev_loss;
	hwe->user_friendly_names = dhwe->user_friendly_names;
	hwe->retain_hwhandler = dhwe->retain_hwhandler;
	hwe->detect_prio = dhwe->detect_prio;
	hwe->detect_checker = dhwe->detect_checker;
	hwe->ghost_delay = dhwe->ghost_delay;

	if (dhwe->bl_product && !(hwe->bl_product = set_param_str(dhwe->bl_product)))
		goto out;

	if (!vector_alloc_slot(hwtable))
		goto out;

	vector_set_slot(hwtable, hwe);
	return 0;
out:
	free_hwe(hwe);
	return 1;
}

static void
factorize_hwtable (vector hw, int n)
{
	struct hwentry *hwe1, *hwe2;
	int i, j;

restart:
	vector_foreach_slot(hw, hwe1, i) {
		if (i == n)
			break;
		j = n;
		vector_foreach_slot_after(hw, hwe2, j) {
			if (hwe2->all_devs == 1) {
				overwrite_hwe(hwe1, hwe2);
				continue;
			}
			else if (conf->hw_strmatch) {
				if (hwe_strmatch(hwe2, hwe1))
					continue;
			}
			else if (hwe_regmatch(hwe1, hwe2))
				continue;
			/* dup */
			merge_hwe(hwe2, hwe1);
			if (conf->hw_strmatch ||
			    hwe_strmatch(hwe2, hwe1) == 0) {
				vector_del_slot(hw, i);
				free_hwe(hwe1);
				n -= 1;
				/*
				 * Play safe here; we have modified
				 * the original vector so the outer
				 * vector_foreach_slot() might
				 * become confused.
				 */
				goto restart;
			}
		}
	}
	return;
}

struct config *
alloc_config (void)
{
	return (struct config *)MALLOC(sizeof(struct config));
}

void
free_config (struct config * conf)
{
	if (!conf)
		return;

	if (conf->dev)
		FREE(conf->dev);

	if (conf->multipath_dir)
		FREE(conf->multipath_dir);

	if (conf->selector)
		FREE(conf->selector);

	if (conf->uid_attribute)
		FREE(conf->uid_attribute);

	if (conf->features)
		FREE(conf->features);

	if (conf->hwhandler)
		FREE(conf->hwhandler);

	if (conf->bindings_file)
		FREE(conf->bindings_file);

	if (conf->wwids_file)
		FREE(conf->wwids_file);

	if (conf->prkeys_file)
		FREE(conf->prkeys_file);

	if (conf->prio_name)
		FREE(conf->prio_name);

	if (conf->alias_prefix)
		FREE(conf->alias_prefix);

	if (conf->prio_args)
		FREE(conf->prio_args);

	if (conf->checker_name)
		FREE(conf->checker_name);

	if (conf->config_dir)
		FREE(conf->config_dir);

	free_blacklist(conf->blist_devnode);
	free_blacklist(conf->blist_wwid);
	free_blacklist(conf->blist_property);
	free_blacklist(conf->blist_protocol);
	free_blacklist_device(conf->blist_device);

	free_blacklist(conf->elist_devnode);
	free_blacklist(conf->elist_wwid);
	free_blacklist(conf->elist_property);
	free_blacklist(conf->elist_protocol);
	free_blacklist_device(conf->elist_device);

	free_mptable(conf->mptable);
	free_hwtable(conf->hwtable);
	free_keywords(conf->keywords);
	FREE(conf);
}

/* if multipath fails to process the config directory, it should continue,
 * with just a warning message */
static void
process_config_dir(vector keywords, char *dir)
{
	struct dirent **namelist;
	int i, n;
	char path[LINE_MAX];
	int old_hwtable_size;

	if (dir[0] != '/') {
		condlog(1, "config_dir '%s' must be a fully qualified path",
			dir);
		return;
	}
	n = scandir(dir, &namelist, NULL, alphasort);
	if (n < 0) {
		if (errno == ENOENT)
			condlog(3, "No configuration dir '%s'", dir);
		else
			condlog(0, "couldn't open configuration dir '%s': %s",
				dir, strerror(errno));
		return;
	}
	for (i = 0; i < n; i++) {
		if (!strstr(namelist[i]->d_name, ".conf"))
			continue;
		old_hwtable_size = VECTOR_SIZE(conf->hwtable);
		snprintf(path, LINE_MAX, "%s/%s", dir, namelist[i]->d_name);
		path[LINE_MAX-1] = '\0';
		process_file(path);
		if (VECTOR_SIZE(conf->hwtable) > old_hwtable_size)
			factorize_hwtable(conf->hwtable, old_hwtable_size);

	}
}

int
load_config (char * file, struct udev *udev)
{
	if (!conf)
		conf = alloc_config();

	if (!conf || !udev)
		return 1;

	/*
	 * internal defaults
	 */
	if (!conf->verbosity)
		conf->verbosity = DEFAULT_VERBOSITY;

	conf->udev = udev;
	dm_drv_version(conf->version, TGT_MPATH);
	conf->dev_type = DEV_NONE;
	conf->minio = DEFAULT_MINIO;
	conf->minio_rq = DEFAULT_MINIO_RQ;
	get_sys_max_fds(&conf->max_fds);
	conf->bindings_file = set_default(DEFAULT_BINDINGS_FILE);
	conf->wwids_file = set_default(DEFAULT_WWIDS_FILE);
	conf->prkeys_file = set_default(DEFAULT_PRKEYS_FILE);
	conf->bindings_read_only = 0;
	conf->multipath_dir = set_default(DEFAULT_MULTIPATHDIR);
	conf->features = set_default(DEFAULT_FEATURES);
	conf->flush_on_last_del = 0;
	conf->attribute_flags = 0;
	conf->reassign_maps = DEFAULT_REASSIGN_MAPS;
	conf->checkint = DEFAULT_CHECKINT;
	conf->max_checkint = MAX_CHECKINT(conf->checkint);
	conf->find_multipaths = DEFAULT_FIND_MULTIPATHS;
	conf->fast_io_fail = DEFAULT_FAST_IO_FAIL;
	conf->retain_hwhandler = DEFAULT_RETAIN_HWHANDLER;
	conf->detect_prio = DEFAULT_DETECT_PRIO;
	conf->detect_checker = DEFAULT_DETECT_CHECKER;
	conf->deferred_remove = DEFAULT_DEFERRED_REMOVE;
	conf->hw_strmatch = 0;
	conf->force_sync = 0;
	conf->ignore_new_boot_devs = 0;
	conf->processed_main_config = 0;
	conf->retrigger_tries = DEFAULT_RETRIGGER_TRIES;
	conf->retrigger_delay = DEFAULT_RETRIGGER_DELAY;
	conf->new_bindings_in_boot = 0;
	conf->uev_wait_timeout = DEFAULT_UEV_WAIT_TIMEOUT;
	conf->skip_kpartx = DEFAULT_SKIP_KPARTX;
	conf->remove_retries = 0;
	conf->disable_changed_wwids = 0;
	conf->max_sectors_kb = DEFAULT_MAX_SECTORS_KB;
	conf->unpriv_sgio = DEFAULT_UNPRIV_SGIO;
	conf->ghost_delay = DEFAULT_GHOST_DELAY;
	conf->all_tg_pt = DEFAULT_ALL_TG_PT;

	/*
	 * preload default hwtable
	 */
	if (conf->hwtable == NULL) {
		conf->hwtable = vector_alloc();

		if (!conf->hwtable)
			goto out;
	}
	if (setup_default_hwtable(conf->hwtable))
		goto out;

	/*
	 * read the config file
	 */
	set_current_keywords(&conf->keywords);
	alloc_keywords();
	init_keywords();
	if (filepresent(file)) {
		int builtin_hwtable_size;

		builtin_hwtable_size = VECTOR_SIZE(conf->hwtable);
		if (process_file(file)) {
			condlog(0, "error parsing config file");
			goto out;
		}
		if (VECTOR_SIZE(conf->hwtable) > builtin_hwtable_size) {
			/*
			 * remove duplica in hwtable. config file
			 * takes precedence over build-in hwtable
			 */
			factorize_hwtable(conf->hwtable, builtin_hwtable_size);
		}

	} else {
		condlog(0, "/etc/multipath.conf does not exist, blacklisting all devices.");
		condlog(0, "A default multipath.conf file is located at");
		condlog(0, "/usr/share/doc/device-mapper-multipath-%d.%d.%d/multipath.conf", MULTIPATH_VERSION(VERSION_CODE));
		condlog(0, "You can run /sbin/mpathconf --enable to create");
		condlog(0, "/etc/multipath.conf. See man mpathconf(8) for more details");
		if (conf->blist_devnode == NULL) {
			conf->blist_devnode = vector_alloc();
			if (!conf->blist_devnode) {
				condlog(0, "cannot allocate blacklist\n");
				goto out;
			}
		}
		if (store_ble(conf->blist_devnode, strdup(".*"),
		              ORIGIN_NO_CONFIG)) {
			condlog(0, "cannot store default no-config blacklist\n");
			goto out;
		}
	}

	conf->processed_main_config = 1;
	if (conf->config_dir == NULL)
		conf->config_dir = set_default(DEFAULT_CONFIG_DIR);
	if (conf->config_dir && conf->config_dir[0] != '\0')
		process_config_dir(conf->keywords, conf->config_dir);

	/*
	 * fill the voids left in the config file
	 */
	if (conf->blist_devnode == NULL) {
		conf->blist_devnode = vector_alloc();

		if (!conf->blist_devnode)
			goto out;
	}
	if (conf->blist_wwid == NULL) {
		conf->blist_wwid = vector_alloc();

		if (!conf->blist_wwid)
			goto out;
	}
	if (conf->blist_device == NULL) {
		conf->blist_device = vector_alloc();

		if (!conf->blist_device)
			goto out;
	}
	if (conf->blist_property == NULL) {
		conf->blist_property = vector_alloc();

		if (!conf->blist_property)
			goto out;
	}

	if (conf->blist_protocol == NULL) {
		conf->blist_protocol = vector_alloc();

		if (!conf->blist_protocol)
			goto out;
	}

	if (conf->elist_devnode == NULL) {
		conf->elist_devnode = vector_alloc();

		if (!conf->elist_devnode)
			goto out;
	}
	if (conf->elist_wwid == NULL) {
		conf->elist_wwid = vector_alloc();

		if (!conf->elist_wwid)
			goto out;
	}

	if (conf->elist_device == NULL) {
		conf->elist_device = vector_alloc();

		if (!conf->elist_device)
			goto out;
	}

	if (conf->elist_property == NULL) {
		conf->elist_property = vector_alloc();

		if (!conf->elist_property)
			goto out;
	}

	if (conf->elist_protocol == NULL) {
		conf->elist_protocol = vector_alloc();

		if (!conf->elist_protocol)
			goto out;
	}

	if (setup_default_blist(conf))
		goto out;

	if (conf->mptable == NULL) {
		conf->mptable = vector_alloc();
		if (!conf->mptable)
			goto out;
	}
	if (conf->bindings_file == NULL)
		conf->bindings_file = set_default(DEFAULT_BINDINGS_FILE);

	if (!conf->multipath_dir || !conf->bindings_file ||
	    !conf->wwids_file || !conf->prkeys_file)
		goto out;

	if (conf->ignore_new_boot_devs)
		in_initrd();

	if (conf->new_bindings_in_boot == 0 && in_initrd())
		conf->bindings_read_only = 1;

	return 0;
out:
	free_config(conf);
	return 1;
}

