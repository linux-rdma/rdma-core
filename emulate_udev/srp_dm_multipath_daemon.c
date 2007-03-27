/*
 * srp_dm_multipath_daemon - daemon that executes multipath calls
 * Copyright (c) 2007 Mellanox Technologies Ltd.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * $Author: ishai Rabinovitz [ishai@mellanox.co.il]$
 *
 */

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <sys/wait.h>

#include "srp_dm_multipath_daemon.h"

enum queue_mode {
	EMPTY_QUEUE = 1,
	SERIAL_QUEUE = 2,
	REGULAR_QUEUE = 3,
};
	

void sleep_until_wakeup(time_t wakeup_time)
{
	int ret = wakeup_time - time(NULL);
	while (ret > 0) {
		sleep(ret);
		ret = wakeup_time - time(NULL);
	}
}

/* TODO: change system to exec */

int main(int argc, char **argv)
{
	enum queue_mode mode = SERIAL_QUEUE;
	struct key_n_msg recv_st;
	int msgqid;
	char cmd_str[255];
	int status;
	int count;

	if (argc > 1 && argv[argc-1][0] == '-') 
		switch (argv[argc-1][1]) {
		case 's': 
			mode = SERIAL_QUEUE;
			break;
		case 'r': 
			mode = REGULAR_QUEUE;
			break;
		case 'e': 
			mode = EMPTY_QUEUE;
			break;
		default:  
			break;
		}

	msgqid = msgget(ftok(KEY_FILE, 'a'), IPC_CREAT | 0600);

	if (msgqid == -1) {
		perror("msgget");
		exit(1);
	}

	/* Clean the queue */
	while (msgrcv(msgqid, (void *) &recv_st, 
		   sizeof(struct msg), 1L, IPC_NOWAIT) != -1) 
		;

	while (1) {
		while (waitpid((pid_t)-1, &status, WNOHANG) > 0)
			;
		if (msgrcv(msgqid, (void *) &recv_st,
			   sizeof(struct msg), 1L, 0) == -1) {
			perror("msgrcv");
			return -1;
		}
		sleep_until_wakeup(recv_st.msg.wakeup_time);
		switch (mode) {
		case EMPTY_QUEUE:
			count = 0;
			while (recv_st.msg.type == 'M' &&
			       msgrcv(msgqid, (void *) &recv_st, 
				   sizeof(struct msg), 1L, IPC_NOWAIT) != -1)
				count++;
			if (count) {
				sleep_until_wakeup(recv_st.msg.wakeup_time);
				system(recv_st.msg.path);
			}
			if (recv_st.msg.type == 'K') {
				sprintf(cmd_str, "%s &",
					recv_st.msg.path);
				system(cmd_str);
			}
			break;
		case SERIAL_QUEUE:
		case REGULAR_QUEUE:
			if (recv_st.msg.type == 'M') 
				sprintf(cmd_str, "%s %d:%d %c",
					recv_st.msg.path,
					recv_st.msg.major, recv_st.msg.minor,
					mode==REGULAR_QUEUE?'&':' ');
			else
				sprintf(cmd_str, "%s %c",
					recv_st.msg.path,
					mode==REGULAR_QUEUE?'&':' ');
			system(cmd_str);
			break;
/*
			pid = fork();
			if (pid < 0) {
				perror(argv[0]);
				exit(1);
			} else if (!pid) {
				system(cmd_str);
				exit(0);
			}
			break;
*/
		default:
			/* Should never get here */
			exit(1);
			break;
		}
	}
}
