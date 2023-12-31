/*
 * Source: copy of util-linux' partx partx.c
 *
 * Copyrights of the original file applies
 * Copyright (c) 2004, 2005 Christophe Varoqui
 * Copyright (c) 2005 Kiyoshi Ueda
 * Copyright (c) 2005 Lars Soltau
 */

/*
 * Given a block device and a partition table type,
 * try to parse the partition table, and list the
 * contents. Optionally add or remove partitions.
 *
 * Read wholedisk and add all partitions:
 *	kpartx [-a|-d|-l] [-v] wholedisk
 *
 * aeb, 2000-03-21
 * cva, 2002-10-26
 */

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ctype.h>
#include <libdevmapper.h>

#include "devmapper.h"
#include "crc32.h"
#include "lopart.h"
#include "kpartx.h"

#define SIZE(a) (sizeof(a)/sizeof((a)[0]))

#define READ_SIZE	1024
#define MAXTYPES	64
#define MAXSLICES	256
#define DM_TARGET	"linear"
#define LO_NAME_SIZE    64
#define PARTNAME_SIZE	128
#define DELIM_SIZE	8

struct slice slices[MAXSLICES];

enum action { LIST, ADD, DELETE, UPDATE };

struct pt {
	char *type;
	ptreader *fn;
} pts[MAXTYPES];

int ptct = 0;
int udev_sync = 1;

static void
addpts(char *t, ptreader f)
{
	if (ptct >= MAXTYPES) {
		fprintf(stderr, "addpts: too many types\n");
		exit(1);
	}
	pts[ptct].type = t;
	pts[ptct].fn = f;
	ptct++;
}

static void
initpts(void)
{
	addpts("gpt", read_gpt_pt);
	addpts("dos", read_dos_pt);
	addpts("bsd", read_bsd_pt);
	addpts("solaris", read_solaris_pt);
	addpts("unixware", read_unixware_pt);
	addpts("dasd", read_dasd_pt);
	addpts("mac", read_mac_pt);
	addpts("sun", read_sun_pt);
	addpts("ps3", read_ps3_pt);
}

static char short_opts[] = "rladfgvp:t:snu";

/* Used in gpt.c */
int force_gpt=0;

int force_devmap=0;

static int
usage(void) {
	printf("usage : kpartx [-a|-d|-l] [-f] [-v] wholedisk\n");
	printf("\t-a add partition devmappings\n");
	printf("\t-r devmappings will be readonly\n");
	printf("\t-d del partition devmappings\n");
	printf("\t-u update partition devmappings\n");
	printf("\t-l list partitions devmappings that would be added by -a\n");
	printf("\t-p set device name-partition number delimiter\n");
	printf("\t-g force GUID partition table (GPT)\n");
	printf("\t-f force devmap create\n");
	printf("\t-v verbose\n");
	printf("\t-n nosync mode. Return before the partitions are created\n");
	printf("\t-s sync mode. Don't return until the partitions are created. Default.\n");
	return 1;
}

static void
set_delimiter (char * device, char * delimiter)
{
	char * p = device;

	if (*p == 0x0)
		return;

	while (*(++p) != 0x0)
		continue;

	if (isdigit(*(p - 1)))
		*delimiter = 'p';
}

static void
strip_slash (char * device)
{
	char * p = device;

	while (*(p++) != 0x0) {

		if (*p == '/')
			*p = '!';
	}
}

static int
find_devname_offset (char * device)
{
	char *p, *q;

	q = p = device;

	while (*p) {
		if (*p == '/')
			q = p + 1;
		p++;
	}

	return (int)(q - device);
}

static char *
get_hotplug_device(void)
{
	unsigned int major, minor, off, len;
	const char *mapname;
	char *devname = NULL;
	char *device = NULL;
	char *var = NULL;
	struct stat buf;

	var = getenv("ACTION");

	if (!var || strcmp(var, "add"))
		return NULL;

	/* Get dm mapname for hotpluged device. */
	if (!(devname = getenv("DEVNAME")))
		return NULL;

	if (stat(devname, &buf))
		return NULL;

	major = (unsigned int)MAJOR(buf.st_rdev);
	minor = (unsigned int)MINOR(buf.st_rdev);

	if (!(mapname = dm_mapname(major, minor))) /* Not dm device. */
		return NULL;

	off = find_devname_offset(devname);
	len = strlen(mapname);

	/* Dirname + mapname + \0 */
	if (!(device = (char *)malloc(sizeof(char) * (off + len + 1))))
		return NULL;

	/* Create new device name. */
	snprintf(device, off + 1, "%s", devname);
	snprintf(device + off, len + 1, "%s", mapname);

	if (strlen(device) != (off + len))
		return NULL;

	return device;
}

static int
check_uuid(char *uuid, char *part_uuid, char **err_msg) {
	char *map_uuid = strchr(part_uuid, '-');
	if (!map_uuid || strncmp(part_uuid, "part", 4) != 0) {
		*err_msg = "not a kpartx partition";
		return -1;
	}
	map_uuid++;
	if (strcmp(uuid, map_uuid) != 0) {
		*err_msg = "a partition of a different device";
		return -1;
	}
	return 0;
}

int
main(int argc, char **argv){
	int i, j, m, n, op, off, arg, ro=0;
	int fd = -1;
	struct slice all;
	struct pt *ptp;
	enum action what = LIST;
	char *type, *diskdevice, *device, *progname;
	int verbose = 0;
	char partname[PARTNAME_SIZE], params[PARTNAME_SIZE + 16];
	char * loopdev = NULL;
	char * delim = NULL;
	char *uuid = NULL;
	char *mapname = NULL;
	int hotplug = 0;
	int loopcreated = 0;
	struct stat buf;

	initpts();
	init_crc32();

	type = device = diskdevice = NULL;
	memset(&all, 0, sizeof(all));
	memset(&partname, 0, sizeof(partname));

	/* Check whether hotplug mode. */
	progname = strrchr(argv[0], '/');

	if (!progname)
		progname = argv[0];
	else
		progname++;

	if (!strcmp(progname, "kpartx.dev")) { /* Hotplug mode */
		hotplug = 1;

		/* Setup for original kpartx variables */
		if (!(device = get_hotplug_device()))
			exit(1);

		diskdevice = device;
		what = ADD;
	} else if (argc < 2) {
		usage();
		exit(1);
	}

	while ((arg = getopt(argc, argv, short_opts)) != EOF) switch(arg) {
		case 'r':
			ro=1;
			break;
		case 'f':
			force_devmap=1;
			break;
		case 'g':
			force_gpt=1;
			break;
		case 't':
			type = optarg;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'p':
			delim = optarg;
			break;
		case 'l':
			what = LIST;
			break;
		case 'a':
			what = ADD;
			break;
		case 'd':
			what = DELETE;
			break;
		case 's':
			udev_sync = 1;
			break;
		case 'n':
			udev_sync = 0;
			break;
		case 'u':
			what = UPDATE;
			break;
		default:
			usage();
			exit(1);
	}

#ifdef LIBDM_API_COOKIE
	if (!udev_sync)
		dm_udev_set_sync_support(0);
	else
		dm_udev_set_sync_support(1);
#endif

	if (dm_prereq(DM_TARGET, 0, 0, 0) && (what == ADD || what == DELETE || what == UPDATE)) {
		fprintf(stderr, "device mapper prerequisites not met\n");
		exit(1);
	}

	if (hotplug) {
		/* already got [disk]device */
	} else if (optind == argc-2) {
		device = argv[optind];
		diskdevice = argv[optind+1];
	} else if (optind == argc-1) {
		diskdevice = device = argv[optind];
	} else {
		usage();
		exit(1);
	}

	if (stat(device, &buf)) {
		printf("failed to stat() %s\n", device);
		exit (1);
	}

	if (S_ISREG (buf.st_mode)) {
		/* already looped file ? */
		loopdev = find_loop_by_file(device);

		if (!loopdev && what == DELETE)
			exit (0);

		if (!loopdev) {
			loopdev = find_unused_loop_device();

			if (set_loop(loopdev, device, 0, &ro)) {
				fprintf(stderr, "can't set up loop\n");
				exit (1);
			}
			loopcreated = 1;
		}
		device = loopdev;
	}
	else if (!S_ISBLK(buf.st_mode)) {
		fprintf(stderr, "invalid device: %s\n", device);
		exit(1);
	}

	off = find_devname_offset(device);

	if (!loopdev) {
		uuid = dm_mapuuid((unsigned int)MAJOR(buf.st_rdev),
				  (unsigned int)MINOR(buf.st_rdev));
		mapname = dm_mapname((unsigned int)MAJOR(buf.st_rdev),
				     (unsigned int)MINOR(buf.st_rdev));
	}

	if (!uuid)
		uuid = device + off;

	if (!mapname)
		mapname = device + off;
	else if (!force_devmap &&
		 dm_no_partitions((unsigned int)MAJOR(buf.st_rdev),
				  (unsigned int)MINOR(buf.st_rdev))) {
		/* Feature 'no_partitions' is set, return */
		return 0;
	}

	if (delim == NULL) {
		delim = malloc(DELIM_SIZE);
		memset(delim, 0, DELIM_SIZE);
		set_delimiter(mapname, delim);
	}

	fd = open(device, O_RDONLY);

	if (fd == -1) {
		perror(device);
		exit(1);
	}

	/* add/remove partitions to the kernel devmapper tables */
	int r = 0;
	for (i = 0; i < ptct; i++) {
		ptp = &pts[i];

		if (type && strcmp(type, ptp->type))
			continue;

		/* here we get partitions */
		n = ptp->fn(fd, all, slices, SIZE(slices));

#ifdef DEBUG
		if (n >= 0)
			printf("%s: %d slices\n", ptp->type, n);
#endif

		if (n > 0) {
			close(fd);
			fd = -1;
		}
		else
			continue;

		/*
 		 * test for overlap, as in the case of an extended partition
 		 * zero their size to avoid mapping
 		 */
		for (j = 0; j < n; j++) {
			for (m = j + 1; m < n; m++) {
				if (slices[m].start > slices[j].start &&
				    slices[m].start < slices[j].start +
				    slices[j].size)
					slices[j].size = 0;
			}
		}

		switch(what) {
		case LIST:
			for (j = 0; j < n; j++) {
				if (slices[j].size == 0)
					continue;

				printf("%s%s%d : 0 %" PRIu64 " %s %" PRIu64"\n",
				       mapname, delim, j+1,
				       slices[j].size, device,
				       slices[j].start);
			}

			break;

		case DELETE:
			for (j = MAXSLICES-1; j >= 0; j--) {
				char *part_uuid, *reason;

				if (safe_sprintf(partname, "%s%s%d",
					     mapname, delim, j+1)) {
					fprintf(stderr, "partname too small\n");
					exit(1);
				}
				strip_slash(partname);

				if (!dm_map_present(partname, &part_uuid))
					continue;

				if (part_uuid && uuid) {
					if (check_uuid(uuid, part_uuid, &reason) != 0) {
						fprintf(stderr, "%s is %s. Not removing\n", partname, reason);
						free(part_uuid);
						continue;
					}
					free(part_uuid);
				}

				if (!dm_simplecmd(DM_DEVICE_REMOVE, partname,
						  0, 0)) {
					r++;
					continue;
				}
				if (verbose)
					printf("del devmap : %s\n", partname);
			}

			if (S_ISREG (buf.st_mode)) {
				if (del_loop(device)) {
					if (verbose)
						printf("can't del loop : %s\n",
							device);
					exit(1);
				}
				printf("loop deleted : %s\n", device);
			}
			break;

		case ADD:
		case UPDATE:
			/* ADD and UPDATE share the same code that adds new partitions. */
			for (j = 0; j < n; j++) {
				char *part_uuid, *reason;

				if (slices[j].size == 0)
					continue;

				if (safe_sprintf(partname, "%s%s%d",
					     mapname, delim, j+1)) {
					fprintf(stderr, "partname too small\n");
					exit(1);
				}
				strip_slash(partname);

				if (safe_sprintf(params, "%s %" PRIu64 ,
						 device, slices[j].start)) {
					fprintf(stderr, "params too small\n");
					exit(1);
				}

				op = (dm_map_present(partname, &part_uuid) ?
					DM_DEVICE_RELOAD : DM_DEVICE_CREATE);

				if (part_uuid && uuid) {
					if (check_uuid(uuid, part_uuid, &reason) != 0) {
						fprintf(stderr, "%s is already in use, and %s\n", partname, reason);
						r++;
						free(part_uuid);
						continue;
					}
					free(part_uuid);
				}

				if (!dm_addmap(op, partname, DM_TARGET, params,
					       slices[j].size, ro, uuid, j+1,
					       buf.st_mode & 0777, buf.st_uid,
					       buf.st_gid)) {
					fprintf(stderr, "create/reload failed on %s\n",
						partname);
					r++;
					continue;
				}
				if (op == DM_DEVICE_RELOAD &&
				    !dm_simplecmd(DM_DEVICE_RESUME, partname,
						  1, MPATH_UDEV_RELOAD_FLAG)) {
					fprintf(stderr, "resume failed on %s\n",
						partname);
					r++;
					continue;
				}

				dm_devn(partname, &slices[j].major,
					&slices[j].minor);

				if (verbose)
					printf("add map %s (%d:%d): 0 %" PRIu64 " %s %s\n",
					       partname, slices[j].major,
					       slices[j].minor, slices[j].size,
					       DM_TARGET, params);
			}

			if (what == ADD) {
				/* Skip code that removes devmappings for deleted partitions */
				break;
			}

			for (j = MAXSLICES-1; j >= 0; j--) {
				char *part_uuid, *reason;
				if (safe_sprintf(partname, "%s%s%d",
					     mapname, delim, j+1)) {
					fprintf(stderr, "partname too small\n");
					exit(1);
				}
				strip_slash(partname);

				if (slices[j].size ||
				    !dm_map_present(partname, &part_uuid))
					continue;

				if (part_uuid && uuid) {
					if (check_uuid(uuid, part_uuid, &reason) != 0) {
						fprintf(stderr, "%s is %s. Not removing\n", partname, reason);
						free(part_uuid);
						continue;
					}
					free(part_uuid);
				}

				if (!dm_simplecmd(DM_DEVICE_REMOVE,
						  partname, 1, 0)) {
					r++;
					continue;
				}
				if (verbose)
					printf("del devmap : %s\n", partname);
			}

		default:
			break;

		}
		if (n > 0)
			break;
	}
	if (what == LIST && loopcreated && S_ISREG (buf.st_mode)) {
		if (fd != -1)
			close(fd);
		if (del_loop(device)) {
			if (verbose)
				printf("can't del loop : %s\n",
					device);
			exit(1);
		}
		printf("loop deleted : %s\n", device);
	}

	dm_lib_release();
	dm_lib_exit();

	return r;
}

void *
xmalloc (size_t size) {
	void *t;

	if (size == 0)
		return NULL;

	t = malloc (size);

	if (t == NULL) {
		fprintf(stderr, "Out of memory\n");
		exit(1);
	}

	return t;
}

/*
 * sseek: seek to specified sector
 */

static int
sseek(int fd, unsigned int secnr) {
	off64_t in, out;
	in = ((off64_t) secnr << 9);
	out = 1;

	if ((out = lseek64(fd, in, SEEK_SET)) != in)
	{
		fprintf(stderr, "llseek error\n");
		return -1;
	}
	return 0;
}

static
struct block {
	unsigned int secnr;
	char *block;
	struct block *next;
} *blockhead;

char *
getblock (int fd, unsigned int secnr) {
	struct block *bp;

	for (bp = blockhead; bp; bp = bp->next)

		if (bp->secnr == secnr)
			return bp->block;

	if (sseek(fd, secnr))
		return NULL;

	bp = xmalloc(sizeof(struct block));
	bp->secnr = secnr;
	bp->next = blockhead;
	blockhead = bp;
	bp->block = (char *) xmalloc(READ_SIZE);

	if (read(fd, bp->block, READ_SIZE) != READ_SIZE) {
		fprintf(stderr, "read error, sector %d\n", secnr);
		bp->block = NULL;
	}

	return bp->block;
}

int
get_sector_size(int filedes)
{
	int rc, sector_size = 512;

	rc = ioctl(filedes, BLKSSZGET, &sector_size);
	if (rc)
		sector_size = 512;
	return sector_size;
}
