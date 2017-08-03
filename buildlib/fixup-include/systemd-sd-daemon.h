#define SD_LISTEN_FDS_START 3

static inline int sd_listen_fds(int unset_environment)
{
	return 0;
}

static inline int sd_is_socket(int fd, int family, int type, int listening)
{
	return 0;
}

static inline int sd_notify(int unset_environment, const char *state)
{
	return 0;
}
