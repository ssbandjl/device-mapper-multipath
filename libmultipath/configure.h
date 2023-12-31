/*
 * configurator actions
 */
#define ACT_NOTHING_STR         "unchanged"
#define ACT_REJECT_STR          "reject"
#define ACT_RELOAD_STR          "reload"
#define ACT_SWITCHPG_STR        "switchpg"
#define ACT_RENAME_STR          "rename"
#define ACT_CREATE_STR          "create"
#define ACT_RESIZE_STR          "resize"

enum actions {
	ACT_UNDEF,
	ACT_NOTHING,
	ACT_REJECT,
	ACT_RELOAD,
	ACT_SWITCHPG,
	ACT_RENAME,
	ACT_CREATE,
	ACT_RESIZE,
	ACT_RENAME2,
};

#define FLUSH_ONE 1
#define FLUSH_ALL 2

int setup_map (struct multipath * mpp, char * params, int params_size,
	       struct vectors *vecs);
int domap (struct multipath * mpp, char * params);
int reinstate_paths (struct multipath *mpp);
int check_daemon(void);
int coalesce_paths (struct vectors *vecs, vector curmp, char * refwwid, int force_reload);
int get_refwwid (char * dev, enum devtypes dev_type, vector pathvec, char **wwid);
int reload_map(struct vectors *vecs, struct multipath *mpp, int refresh);
int sysfs_get_host_adapter_name(struct path *pp, char *adapter_name);
void trigger_uevents (struct multipath *mpp);
void set_max_fds(int max_fds);
