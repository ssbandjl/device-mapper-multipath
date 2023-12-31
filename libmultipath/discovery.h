#ifndef DISCOVERY_H
#define DISCOVERY_H

#define SYSFS_PATH_SIZE 255
#define INQUIRY_CMDLEN  6
#define INQUIRY_CMD     0x12
#define SENSE_BUFF_LEN  32
#define RECOVERED_ERROR 0x01
#define MX_ALLOC_LEN    255
#define TUR_CMD_LEN     6

#ifndef BLKGETSIZE
#define BLKGETSIZE      _IO(0x12,96)
#endif

#ifndef DEF_TIMEOUT
#define DEF_TIMEOUT	60000
#endif

/*
 * exerpt from sg_err.h
 */
#define SCSI_CHECK_CONDITION    0x2
#define SCSI_COMMAND_TERMINATED 0x22
#define SG_ERR_DRIVER_SENSE     0x08

#define PATHINFO_OK 0
#define PATHINFO_FAILED 1
#define PATHINFO_SKIPPED 2

struct config;

int sysfs_get_dev (struct udev_device *udev, char * buff, size_t len);
int path_discovery (vector pathvec, struct config * conf, int flag);

int do_tur (char *);
int path_offline (struct path *);
int get_state (struct path * pp, int daemon, int state);
int pathinfo (struct path *, vector hwtable, int mask);
int store_pathinfo (vector pathvec, vector hwtable,
		    struct udev_device *udevice, int flag,
		    struct path **pp_ptr);
int sysfs_set_scsi_tmo (struct multipath *mpp);
int sysfs_set_max_sectors_kb(struct multipath *mpp, int is_reload);
int sysfs_set_unpriv_sgio(struct multipath *mpp);
int sysfs_get_timeout(struct path *pp, unsigned int *timeout);
int sysfs_get_host_pci_name(struct path *pp, char *pci_name);
int sysfs_get_iscsi_ip_address(struct path *pp, char *ip_address);
int get_uid (struct path * pp, struct udev_device *udev);

/*
 * discovery bitmask
 */
enum discovery_mode {
	__DI_SYSFS,
	__DI_SERIAL,
	__DI_CHECKER,
	__DI_PRIO,
	__DI_WWID,
	__DI_BLACKLIST,
};

#define DI_SYSFS	(1 << __DI_SYSFS)
#define DI_SERIAL	(1 << __DI_SERIAL)
#define DI_CHECKER	(1 << __DI_CHECKER)
#define DI_PRIO		(1 << __DI_PRIO)
#define DI_WWID		(1 << __DI_WWID)
#define DI_BLACKLIST	(1 << __DI_BLACKLIST)

#define DI_ALL		(DI_SYSFS  | DI_SERIAL | DI_CHECKER | DI_PRIO | \
			 DI_WWID)

#endif /* DISCOVERY_H */
