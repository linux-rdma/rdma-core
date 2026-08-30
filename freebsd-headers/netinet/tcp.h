#ifndef __FREEBSD_NETINET_TCP_H__
#define __FREEBSD_NETINET_TCP_H__

#include_next <netinet/tcp.h>
#include_next <netinet/tcp_fsm.h>

#define	TCP_CLOSE		TCPS_CLOSED
#define	TCP_ESTABLISHED		TCPS_ESTABLISHED

#endif
