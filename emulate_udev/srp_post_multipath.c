#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "srp_dm_multipath_daemon.h"

void usage(char *name)
{
	fprintf(stderr, "Usage: %s M multipath_path sleep_time major minor\n", 
		name);
	fprintf(stderr, "Usage: %s K kpartx_path sleep_time\n", name);
}

int main(int argc, char **argv)
{
	struct key_n_msg send_st;
	int msgqid;
	int ret;
	int sleep_time;

	if (argc != 4 && argc != 6) {
		usage(argv[0]);
		return -1;
	}

	msgqid = msgget(ftok(KEY_FILE, 'a'), 0);

	if (msgqid == -1) {
		perror("msgget");
		return -1;
	}
	send_st.key = 1;
	send_st.msg.type = *argv[1];
	switch (send_st.msg.type) {
	case 'M':
		ret = sscanf(argv[4], "%sd", &send_st.msg.major);
		if (ret < 1) {
			usage(argv[0]);
			return -2;
		}
		ret = sscanf(argv[5], "%sd", &send_st.msg.minor);
		if (ret < 1) {
			usage(argv[0]);
			return -2;
		}
		break;
	case 'K':
		break;
	default:
		fprintf(stderr, "Unknown type %c\n", send_st.msg.type);
		usage(argv[0]);
		return -2;
	}
	if (strlen(argv[2]) >= MAX_PATH_LENGTH) {
		fprintf(stderr, "Path is too long\n");
		return -2;
	}
	strcpy(send_st.msg.path, argv[2]);
	ret = sscanf(argv[3], "%d", &sleep_time);
	if (ret < 1) {
		usage(argv[0]);
		return -2;
	}
	send_st.msg.wakeup_time = time(NULL) + sleep_time;

	if(msgsnd(msgqid, (void *) &send_st,
		  sizeof(struct msg),0) == -1){
		perror("msgsnd");
		return -1;
	}

	return 0;
}
