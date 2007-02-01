#define MAX_PATH_LENGTH 256

struct msg {
	char type;
	char path[MAX_PATH_LENGTH];
	time_t wakeup_time;
	char major, minor;
};

struct key_n_msg {
	long key;
	struct msg msg;
};

#define KEY_FILE "/mswg/work/ishai/mpsd.key"


