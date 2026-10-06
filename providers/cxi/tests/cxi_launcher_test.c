// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#define _GNU_SOURCE
#include <sys/resource.h>
#include <sys/syscall.h>
#undef SYS_close_range
int cxi_launcher_program_main(int argc, char **argv);
#define main cxi_launcher_program_main
#include "../utils/cxi_launcher.c"
#undef main

static int check_fd_cleanup(int keep)
{
	struct rlimit limit;
	pid_t child;
	int status;

	child = fork();
	if (child < 0)
		return 1;
	if (!child) {
		int source;
		int high;
		int descriptor;

		source = open("/dev/null", O_RDWR);
		if (source < 0)
			_exit(1);
		for (descriptor = 0; descriptor < 3; descriptor++)
			if (dup2(source, descriptor) < 0)
				_exit(2);
		if (source != 3) {
			if (dup2(source, 3) < 0)
				_exit(3);
			close(source);
		}
		if (getrlimit(RLIMIT_NOFILE, &limit))
			_exit(5);
		if (limit.rlim_cur < 70001) {
			limit.rlim_cur = 70001;
			if (limit.rlim_max < limit.rlim_cur)
				limit.rlim_max = limit.rlim_cur;
			if (setrlimit(RLIMIT_NOFILE, &limit))
				_exit(4);
		}
		high = fcntl(3, F_DUPFD, 70000);
		if (high < 0)
			_exit(4);
		limit.rlim_cur = 256;
		if (setrlimit(RLIMIT_NOFILE, &limit) || close_inherited_fds(keep))
			_exit(6);
		if (fcntl(high, F_GETFD) != -1 || errno != EBADF)
			_exit(7);
		for (descriptor = 0; descriptor < 3; descriptor++)
			if (fcntl(descriptor, F_GETFD) < 0)
				_exit(8);
		if (keep >= 3 && fcntl(keep, F_GETFD) < 0)
			_exit(9);
		_exit(0);
	}
	if (waitpid(child, &status, 0) != child)
		return 1;
	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		fprintf(stderr, "FD cleanup failed for keep=%d, status=%d\n", keep, status);
		return 1;
	}
	return 0;
}

int main(void)
{
	static const int keep_fds[] = { -1, 0, 1, 3 };
	size_t index;

	for (index = 0; index < ARRAY_SIZE(keep_fds); index++)
		if (check_fd_cleanup(keep_fds[index]))
			return 1;
	puts("PASS: FD fallback closes high descriptors and preserves stdio/grant");
	return 0;
}
