/* GPLv2 or OpenIB.org BSD (MIT) See COPYING file */
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/types.h>
#include <time.h>
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

#ifndef GRND_INSECURE
#define GRND_INSECURE 0x0004
#endif
unsigned int get_random(void)
{
	static unsigned int seed;
	ssize_t sz;

	if (!seed) {
		sz = getrandom(&seed, sizeof(seed),
			       GRND_NONBLOCK | GRND_INSECURE);
		if (sz < 0)
			sz = getrandom(&seed, sizeof(seed), GRND_NONBLOCK);

		if (sz != sizeof(seed))
			seed = time(NULL);
	}

	return rand_r(&seed);
}

bool check_env(const char *var)
{
	const char *env_value = getenv(var);

	return env_value && (strcmp(env_value, "0") != 0);
}

/* Xorshift random number generator */
uint32_t xorshift32(struct xorshift32_state *state)
{
	/* Algorithm "xor" from p. 4 of Marsaglia, "Xorshift RNGs" */
	uint32_t x = state->seed;;

	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	return state->seed = x;
}
