/*
 * Copyright (c) 2010 Benjamin Marzinski, Redhat
 */

#ifndef _FILE_H
#define _FILE_H

#define FILE_TIMEOUT 30
int open_file(char *file, int *can_write, char *header);
int ensure_directories_exist(const char *str, mode_t dir_mode);
int update_timestamp(int create);
int timestamp_equal(long int chk_timestamp);

#endif /* _FILE_H */
