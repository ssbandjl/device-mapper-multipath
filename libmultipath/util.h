#ifndef _UTIL_H
#define _UTIL_H

#include <inttypes.h>

void strchop(char *);
int basenamecpy (const char * src, char * dst, int);
int filepresent (char * run);
int get_word (char * sentence, char ** word);
size_t strlcpy(char *dst, const char *src, size_t size);
size_t strlcat(char *dst, const char *src, size_t size);
void remove_trailing_chars(char *path, char c);
int devt2devname (char *, int, char *);
dev_t parse_devt(const char *dev_t);
char *convert_dev(char *dev, int is_path_device);
int in_initrd(void);
int parse_prkey(char *ptr, uint64_t *prkey);
int parse_prkey_flags(char *ptr, uint64_t *prkey, uint8_t *flags);
int safe_write(int fd, const void *buf, size_t count);

#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))

#define safe_sprintf(var, format, args...)	\
	snprintf(var, sizeof(var), format, ##args) >= sizeof(var)
#define safe_snprintf(var, size, format, args...)      \
	snprintf(var, size, format, ##args) >= size

#endif /* _UTIL_H */
