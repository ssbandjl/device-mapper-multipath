#ifndef _CONFIG_H
#define _CONFIG_H

#include <sys/types.h>
#include <stdint.h>
#include <inttypes.h>
#include "byteorder.h"

#define ORIGIN_DEFAULT 0
#define ORIGIN_CONFIG  1
#define ORIGIN_NO_CONFIG 2

/*
 * In kernel, fast_io_fail == 0 means immediate failure on rport delete.
 * OTOH '0' means not-configured in various places in multipath-tools.
 */
#define MP_FAST_IO_FAIL_UNSET (0)
#define MP_FAST_IO_FAIL_OFF (-1)
#define MP_FAST_IO_FAIL_ZERO (-2)

enum devtypes {
	DEV_NONE,
	DEV_DEVT,
	DEV_DEVNODE,
	DEV_DEVMAP
};

enum mpath_cmds {
	CMD_CREATE,
	CMD_DRY_RUN,
	CMD_LIST_SHORT,
	CMD_LIST_LONG,
	CMD_VALID_PATH,
	CMD_REMOVE_WWID,
	CMD_RESET_WWIDS,
	CMD_ADD_WWID,
};

struct hwentry {
	char * vendor;
	char * product;
	char * revision;
	char * uid_attribute;
	char * features;
	char * hwhandler;
	char * selector;
	char * checker_name;
	char * prio_name;
	char * prio_args;
	char * alias_prefix;

	int all_devs;
	int pgpolicy;
	int pgfailback;
	int rr_weight;
	int no_path_retry;
	int minio;
	int minio_rq;
	int pg_timeout;
	int flush_on_last_del;
	int fast_io_fail;
	unsigned int dev_loss;
	int user_friendly_names;
	int retain_hwhandler;
	int detect_prio;
	int detect_checker;
	int deferred_remove;
	int delay_watch_checks;
	int delay_wait_checks;
	int marginal_path_err_sample_time;
	int marginal_path_err_rate_threshold;
	int marginal_path_err_recheck_gap_time;
	int marginal_path_double_failed_time;
	int skip_kpartx;
	int max_sectors_kb;
	int unpriv_sgio;
	int ghost_delay;
	int all_tg_pt;
	char * bl_product;
};

struct mpentry {
	char * wwid;
	char * alias;
	char * uid_attribute;
	char * selector;
	char * features;

	char * prio_name;
	char * prio_args;
	int prkey_source;
	struct be64 reservation_key;
	uint8_t sa_flags;
	int pgpolicy;
	int pgfailback;
	int rr_weight;
	int no_path_retry;
	int minio;
	int minio_rq;
	int pg_timeout;
	int flush_on_last_del;
	int attribute_flags;
	int user_friendly_names;
	int deferred_remove;
	int delay_watch_checks;
	int delay_wait_checks;
	int marginal_path_err_sample_time;
	int marginal_path_err_rate_threshold;
	int marginal_path_err_recheck_gap_time;
	int marginal_path_double_failed_time;
	int skip_kpartx;
	int max_sectors_kb;
	int unpriv_sgio;
	int ghost_delay;
	uid_t uid;
	gid_t gid;
	mode_t mode;
};

struct config {
	int verbosity;
	enum mpath_cmds cmd;
	int pgpolicy_flag;
	int pgpolicy;
	enum devtypes dev_type;
	int minio;
	int minio_rq;
	int checkint;
	int max_checkint;
	int pgfailback;
	int remove;
	int rr_weight;
	int no_path_retry;
	int user_friendly_names;
	int bindings_read_only;
	int pg_timeout;
	int max_fds;
	int force_reload;
	int queue_without_daemon;
	int ignore_wwids;
	int checker_timeout;
	int daemon;
	int flush_on_last_del;
	int attribute_flags;
	int fast_io_fail;
	unsigned int dev_loss;
	int log_checker_err;
	int allow_queueing;
	int find_multipaths;
	int hw_strmatch;
	uid_t uid;
	gid_t gid;
	mode_t mode;
	int reassign_maps;
	int retain_hwhandler;
	int detect_prio;
	int detect_checker;
	int force_sync;
	int deferred_remove;
	int ignore_new_boot_devs;
	int processed_main_config;
	int delay_watch_checks;
	int delay_wait_checks;
	int marginal_path_err_sample_time;
	int marginal_path_err_rate_threshold;
	int marginal_path_err_recheck_gap_time;
	int marginal_path_double_failed_time;
	int retrigger_tries;
	int retrigger_delay;
	int new_bindings_in_boot;
	int delayed_reconfig;
	int uev_wait_timeout;
	int skip_kpartx;
	int remove_retries;
	int disable_changed_wwids;
	int max_sectors_kb;
	int unpriv_sgio;
	int ghost_delay;
	int all_tg_pt;
	unsigned int version[3];

	char * dev;
	struct udev * udev;
	char * multipath_dir;
	char * selector;
	char * uid_attribute;
	char * features;
	char * hwhandler;
	char * bindings_file;
	char * wwids_file;
	char * prkeys_file;
	char * prio_name;
	char * prio_args;
	char * checker_name;
	char * alias_prefix;
	char * config_dir;
	int prkey_source;
	struct be64 reservation_key;
	uint8_t sa_flags;

	vector keywords;
	vector mptable;
	vector hwtable;

	vector blist_devnode;
	vector blist_wwid;
	vector blist_device;
	vector blist_property;
	vector blist_protocol;
	vector elist_devnode;
	vector elist_wwid;
	vector elist_device;
	vector elist_property;
	vector elist_protocol;
};

struct config * conf;

struct hwentry * find_hwe (vector hwtable, char * vendor, char * product, char *revision);
struct mpentry * find_mpe (char * wwid);
char * get_mpe_wwid (char * alias);

struct hwentry * alloc_hwe (void);
struct mpentry * alloc_mpe (void);

void free_hwe (struct hwentry * hwe);
void free_hwtable (vector hwtable);
void free_mpe (struct mpentry * mpe);
void free_mptable (vector mptable);

int store_hwe (vector hwtable, struct hwentry *);

int load_config (char * file, struct udev * udev);
struct config * alloc_config (void);
void free_config (struct config * conf);

#endif
