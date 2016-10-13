#ifndef _UMAD_SYSFS_H
#define _UMAD_SYSFS_H

extern int sys_read_string(const char *dir_name, const char *file_name, char *str, int len);
extern int sys_read_guid(const char *dir_name, const char *file_name, uint64_t * net_guid);
extern int sys_read_gid(const char *dir_name, const char *file_name, uint8_t * gid);
extern int sys_read_uint64(const char *dir_name, const char *file_name, uint64_t * u);
extern int sys_read_uint(const char *dir_name, const char *file_name, unsigned *u);

#endif /* _UMAD_SYSFS_H */
