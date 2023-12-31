#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/vfs.h>
#include <linux/magic.h>
#include <errno.h>
#include <libudev.h>
#include <mpath_persist.h>

#include "debug.h"
#include "memory.h"
#include "checkers.h"
#include "vector.h"
#include "structs.h"
#include "util.h"

void
strchop(char *str)
{
	int i;

	for (i=strlen(str)-1; i >=0 && isspace(str[i]); --i) ;
	str[++i] = '\0';
}

int
basenamecpy (const char * str1, char * str2, int str2len)
{
	char *p;

	if (!str1 || !strlen(str1))
		return 0;

	if (strlen(str1) >= str2len)
		return 0;

	if (!str2)
		return 0;

	p = (char *)str1 + (strlen(str1) - 1);

	while (*--p != '/' && p != str1)
		continue;

	if (p != str1)
		p++;

	strncpy(str2, p, str2len);
	str2[str2len - 1] = '\0';
	strchop(str2);
	return strlen(str2);
}

int
filepresent (char * run) {
	struct stat buf;

	if(!stat(run, &buf))
		return 1;
	return 0;
}

int
get_word (char * sentence, char ** word)
{
	char * p;
	int len;
	int skip = 0;

	if (word)
		*word = NULL;

	while (*sentence ==  ' ') {
		sentence++;
		skip++;
	}
	if (*sentence == '\0')
		return 0;

	p = sentence;

	while (*p !=  ' ' && *p != '\0')
		p++;

	len = (int) (p - sentence);

	if (!word)
		return skip + len;

	*word = MALLOC(len + 1);

	if (!*word) {
		condlog(0, "get_word : oom");
		return 0;
	}
	strncpy(*word, sentence, len);
	strchop(*word);
	condlog(4, "*word = %s, len = %i", *word, len);

	if (*p == '\0')
		return 0;

	return skip + len;
}

size_t strlcpy(char *dst, const char *src, size_t size)
{
	size_t bytes = 0;
	char *q = dst;
	const char *p = src;
	char ch;

	while ((ch = *p++)) {
		if (bytes+1 < size)
			*q++ = ch;
		bytes++;
	}

	/* If size == 0 there is no space for a final null... */
	if (size)
		*q = '\0';
	return bytes;
}

size_t strlcat(char *dst, const char *src, size_t size)
{
	size_t bytes = 0;
	char *q = dst;
	const char *p = src;
	char ch;

	while (bytes < size && *q) {
		q++;
		bytes++;
	}
	if (bytes == size)
		return (bytes + strlen(src));

	while ((ch = *p++)) {
		if (bytes+1 < size)
		*q++ = ch;
		bytes++;
	}

	*q = '\0';
	return bytes;
}

void remove_trailing_chars(char *path, char c)
{
	size_t len;

	len = strlen(path);
	while (len > 0 && path[len-1] == c)
		path[--len] = '\0';
}

extern int
devt2devname (char *devname, int devname_len, char *devt)
{
	FILE *fd;
	unsigned int tmpmaj, tmpmin, major, minor;
	char dev[FILE_NAME_SIZE];
	char block_path[PATH_SIZE];
	struct stat statbuf;

	memset(block_path, 0, sizeof(block_path));
	memset(dev, 0, sizeof(dev));
	if (sscanf(devt, "%u:%u", &major, &minor) != 2) {
		condlog(0, "Invalid device number %s", devt);
		return 1;
	}

	if (devname_len > FILE_NAME_SIZE)
		devname_len = FILE_NAME_SIZE;

	if (stat("/sys/dev/block", &statbuf) == 0) {
		/* Newer kernels have /sys/dev/block */
		sprintf(block_path,"/sys/dev/block/%u:%u", major, minor);
		if (lstat(block_path, &statbuf) == 0) {
			if (S_ISLNK(statbuf.st_mode) &&
			    readlink(block_path, dev, FILE_NAME_SIZE-1) > 0) {
				char *p = strrchr(dev, '/');

				if (!p) {
					condlog(0, "No sysfs entry for %s",
						block_path);
					return 1;
				}
				p++;
				strncpy(devname, p, devname_len);
				return 0;
			}
		}
		goto skip_proc;
	}
	memset(block_path, 0, sizeof(block_path));

	if (!(fd = fopen("/proc/partitions", "r"))) {
		condlog(0, "Cannot open /proc/partitions");
		return 1;
	}

	while (!feof(fd)) {
		int r = fscanf(fd,"%u %u %*d %s",&tmpmaj, &tmpmin, dev);
		if (!r) {
			r = fscanf(fd,"%*s\n");
			continue;
		}
		if (r != 3)
			continue;

		if ((major == tmpmaj) && (minor == tmpmin)) {
			if (snprintf(block_path, sizeof(block_path),
				     "/sys/block/%s", dev) >= sizeof(block_path)) {
				condlog(0, "device name %s is too long", dev);
				fclose(fd);
				return 1;
			}
			break;
		}
	}
	fclose(fd);
skip_proc:
	if (strncmp(block_path,"/sys/block", 10)) {
		condlog(3, "No device found for %u:%u", major, minor);
		return 1;
	}

	if (stat(block_path, &statbuf) < 0) {
		condlog(0, "No sysfs entry for %s", block_path);
		return 1;
	}

	if (S_ISDIR(statbuf.st_mode) == 0) {
		condlog(0, "sysfs entry %s is not a directory", block_path);
		return 1;
	}
	basenamecpy((const char *)block_path, devname, devname_len);
	return 0;
}

/* This function returns a pointer inside of the supplied pathname string.
 * If is_path_device is true, it may also modify the supplied string */
char *convert_dev(char *name, int is_path_device)
{
	char *ptr;

	if (!name)
		return NULL;
	if (is_path_device) {
		ptr = strstr(name, "cciss/");
		if (ptr) {
			ptr += 5;
			*ptr = '!';
		}
	}
	if (!strncmp(name, "/dev/", 5) && strlen(name) > 5)
		ptr = name + 5;
	else
		ptr = name;
	return ptr;
}

dev_t parse_devt(const char *dev_t)
{
	int maj, min;

	if (sscanf(dev_t,"%d:%d", &maj, &min) != 2)
		return 0;

	return makedev(maj, min);
}

/* This define was taken from systemd. src/shared/macro.h */
#define F_TYPE_EQUAL(a, b) (a == (typeof(a)) b)

/* This function was taken from systemd. src/shared/util.c */
int in_initrd(void) {
	static int saved = -1;
	struct statfs s;

	if (saved >= 0)
		return saved;

	/* We make two checks here:
	 *
	 * 1. the flag file /etc/initrd-release must exist
	 * 2. the root file system must be a memory file system
	 * The second check is extra paranoia, since misdetecting an
	 * initrd can have bad bad consequences due the initrd
	 * emptying when transititioning to the main systemd.
	 */

	saved = access("/etc/initrd-release", F_OK) >= 0 &&
		statfs("/", &s) >= 0 &&
		(F_TYPE_EQUAL(s.f_type, TMPFS_MAGIC) ||
		 F_TYPE_EQUAL(s.f_type, RAMFS_MAGIC));

	return saved;
}

int parse_prkey(char *ptr, uint64_t *prkey)
{
	if (!ptr)
		return 1;
	if (*ptr == '0')
		ptr++;
	if (*ptr == 'x' || *ptr == 'X')
		ptr++;
	if (*ptr == '\0' || strlen(ptr) > 16)
		return 1;
	if (strlen(ptr) != strspn(ptr, "0123456789aAbBcCdDeEfF"))
		return 1;
	if (sscanf(ptr, "%" SCNx64 "", prkey) != 1)
		return 1;
	return 0;
}

int parse_prkey_flags(char *ptr, uint64_t *prkey, uint8_t *flags)
{
	char *flagstr;

	flagstr = strchr(ptr, ':');
	*flags = 0;
	if (flagstr) {
		*flagstr++ = '\0';
		if (strlen(flagstr) == 5 && strcmp(flagstr, "aptpl") == 0)
			*flags = MPATH_F_APTPL_MASK;
	}
	return parse_prkey(ptr, prkey);
}

int safe_write(int fd, const void *buf, size_t count)
{
	while (count > 0) {
		ssize_t r = write(fd, buf, count);
		if (r < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			return -errno;
		}
		count -= r;
		buf = (char *)buf + r;
	}
	return 0;
}
