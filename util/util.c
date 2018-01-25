/* GPLv2 or OpenIB.org BSD (MIT) See COPYING file */
#include <util/util.h>
#include <unistd.h>
#include <fcntl.h>

int set_fd_nonblock(int fd, bool nonblock)
{
	int val;

	val = fcntl(fd, F_GETFL);
	if (val == -1)
		return -1;

	if (nonblock)
		val |= O_NONBLOCK;
	else
		val &= ~(unsigned int)(O_NONBLOCK);

	if (fcntl(fd, F_SETFL, val) == -1)
		return -1;
	return 0;
}
