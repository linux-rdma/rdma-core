#ifdef SIM

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "libcxgb4.h"

#define SIM_BUFLEN 10000
#define ADDCARRY(x)	((x) > 65535 ? (x) -= 65535 : (x))

struct udp_headers {
	struct ether_header 	eth;
	struct iphdr		ip;
	struct udphdr		udp;
} __attribute__ ((packed));

struct foo {
	uint32_t ipaddr;
	uint16_t port;
};

void *packet_init(char *ifname)
{
	int s;
	struct ifreq ifreq;
	struct sockaddr_ll addr;

	if ((s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
		perror("socket");
		return NULL;
	}

	/*
	 * Put interface in promiscuous mode.
	 */
	memset(&ifreq, 0, sizeof(ifreq));
	strcpy(ifreq.ifr_name, ifname);
#if 0
	if (ioctl(s, SIOCGIFFLAGS, &ifreq)) {
		perror("ioctl SIOCGIFFLAGS");
		return NULL;
	}
	ifreq.ifr_flags |= IFF_PROMISC;
	if (ioctl(s, SIOCSIFFLAGS, &ifreq)) {
		perror("ioctl SIOCSIFFLAGS");
		return NULL;
	}
#endif
		
	memset(&ifreq, 0, sizeof(ifreq));
	strncpy(ifreq.ifr_name, ifname, sizeof(ifreq.ifr_name)-1);
	if (ioctl(s, SIOCGIFINDEX, &ifreq) < 0) {
		perror("ioctl");
		return NULL;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sll_family  = AF_PACKET;
	addr.sll_ifindex = ifreq.ifr_ifindex;
	/* This is the proto that we want to receive. */
	addr.sll_protocol = htons(ETH_P_ALL);
	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		return NULL;
	}

	/* Stash the index in the upper byte. */
	s = s | (ifreq.ifr_ifindex<<24);

	return (void *)(unsigned long)s;
}

int packet_send(void *handle, void *buf, int len)
{
	int n, s = (unsigned long)handle & 0x00ffffff, index = (unsigned long)handle >> 24;
	struct sockaddr_ll addr;

	memset(&addr, 0, sizeof(addr));
	addr.sll_family   = AF_PACKET;
	addr.sll_ifindex  = index;
	addr.sll_protocol = htons(ETH_P_ALL);

	n = sendto(s, buf, len, 0, (struct sockaddr *)&addr, sizeof(addr));
	if (n < 0) {
		perror("sendto");
	}

	return n != len? -1: 0;
}

int packet_recv(void *handle, void *buf, int *plen)
{
	int len, s = (unsigned long)handle & 0x00ffffff;
	struct sockaddr_ll addr;
	socklen_t i;

again:
	i = sizeof(addr);
	len = recvfrom(s, buf, *plen, 0, (struct sockaddr *)&addr, &i);
	if (len < 0) {
		if (errno == EAGAIN) {
			return 0;
		}
		perror("recvfrom");
		return -1;
	}
	if (addr.sll_pkttype == PACKET_OUTGOING)
		goto again;
	*plen = len;
	return len;
}


void *handle;
extern SLIST_HEAD(, c4iw_dev) devices;

static int find_next_recv(struct c4iw_qp *qp, struct fw_ri_recv_wr **wrp)
{
	struct fw_ri_recv_wr *wr;
	int cidx = qp->wq.rq.cidx;

	while (cidx != qp->wq.rq.pidx) {
		wr = &qp->wq.rq.queue[cidx].recv;
		if (wr->isgl.op) {
			wr->isgl.op = 0;
			break;
		}
		cidx++;
		if (cidx == qp->wq.rq.size)
			cidx = 0;
	}
	if (cidx == qp->wq.rq.pidx)
		return ENODATA;
	*wrp = wr;
	return 0;
}

static void build_sgl(struct fw_ri_recv_wr *wr, struct ibv_sge *sgep)
{
	int i;
	struct fw_ri_sge *fw_sgep;
	int nsge = be16_to_cpu(wr->isgl.nsge);
	
	fw_sgep = wr->isgl.sge;
	assert(nsge <= 4);
	for (i = 0; i < nsge; i++) {
		sgep->addr = be64_to_cpu(fw_sgep->to);
		sgep->lkey = be32_to_cpu(fw_sgep->stag);
		sgep->length = be32_to_cpu(fw_sgep->len);
		sgep++;
		fw_sgep++;
	}
	for (; i < 4; i++) {
		sgep->length = 0;
		sgep->addr = 0;
		sgep->lkey = 0;
		sgep++;
	}
}

static void complete_recv_wr(struct c4iw_qp *qp, struct fw_ri_recv_wr *wr, int len)
{
	struct t4_cqe cqe;
	struct c4iw_cq *chp;
	struct t4_cq *cq;

	chp = to_c4iw_cq(qp->ibv_qp.recv_cq);
	cq = &chp->cq;

	memset(&cqe, 0, sizeof(cqe));
	cqe.header = cpu_to_be32(V_CQE_STATUS(0) |
			         V_CQE_OPCODE(FW_RI_SEND) |
			         V_CQE_TYPE(0) |
			         V_CQE_SWCQE(1) |
			         V_CQE_QPID(qp->wq.sq.qid));
	cqe.len = cpu_to_be32(len);
	cqe.bits_type_ts = cpu_to_be64(V_CQE_GENBIT((u64)cq->gen));
	pthread_spin_unlock(&qp->lock);
	pthread_spin_lock(&chp->lock);
	cq->sw_queue[cq->sw_pidx] = cqe;
	t4_swcq_produce(cq);
	if (chp->armed) {
		chp->armed = 0;
		c4iw_resize_cq(&chp->ibv_cq, 0);
	}
	pthread_spin_unlock(&chp->lock);
	pthread_spin_lock(&qp->lock);
}

static void udp_qp_handler(struct c4iw_qp *qhp, uint8_t *buf, int len)
{
	struct foo *f = qhp->ibv_qp.qp_context;
	struct udp_headers *hdr = (struct udp_headers *)buf;
	struct ibv_sge sge[4], *sgep;
	struct fw_ri_recv_wr *wr;
	int ret;
	int rem;

	PDBG("%s qpid %u context %p\n", __func__, qhp->ibv_qp.qp_num, qhp->ibv_qp.qp_context);

	if (!f)
		return;
	
	if (!f->port) {
		PDBG("drop: frag qp\n");
		return;
	}

	if (f->port != hdr->udp.dest) {
		PDBG("drop: port mismatch qp %u pkt %u\n",
			ntohs(f->port), ntohs(hdr->udp.dest));
		return;
	}
	
	pthread_spin_lock(&qhp->lock);
	if (!qhp->wq.rq.in_use) {
		PDBG("drop: empty rq\n");
		pthread_spin_unlock(&qhp->lock);
		return;
	}
	ret = find_next_recv(qhp, &wr);
	if (ret) {
		PDBG("drop: out of rqes\n");
		pthread_spin_unlock(&qhp->lock);
		return;
	}
	build_sgl(wr, sge);
	sgep = sge;
	rem = len;
	while (1) {
		if (rem <= sgep->length) {
			memcpy((void *)sgep->addr, buf, rem);
			break;
		}
		memcpy((void *)sgep->addr, buf, sgep->length);
		rem -= sgep->length;
		buf += sgep->length;
		if (sgep == &sge[3]) {
			PDBG("rqe overflow\n");
			break;
		}
		sgep++;
	}
	complete_recv_wr(qhp, wr, len);
	pthread_spin_unlock(&qhp->lock);
}
	

static void udp_handler(uint8_t *buf, int len)
{
	int i;
	struct c4iw_dev *dev;

	SLIST_FOREACH(dev, &devices, list) {
		pthread_spin_lock(&dev->lock);
		for (i=T4_QID_BASE; i < T4_QID_BASE + T4_MAX_NUM_QP; i++) {
			struct c4iw_qp *qhp = dev->qpid2ptr[i];
			if (qhp) {
				PDBG("%s qid %u type %u\n", __func__, qhp->ibv_qp.qp_num, qhp->ibv_qp.qp_type);
				if (qhp->ibv_qp.qp_type == IBV_QPT_RAW_ETY) {
					udp_qp_handler(qhp, buf, len);
				}
			}
		}
		pthread_spin_unlock(&dev->lock);
	}
}

void *sim_thread(void *arg)
{
	uint32_t buf[SIM_BUFLEN/4];
	int len;
	int ret;
	struct udp_headers *hdr = (struct udp_headers *)buf;

	handle = packet_init("eth3");
	if (!handle) {
		printf("packet_init failed!\n");
		pthread_exit(NULL);
	}
	while (1) {
		struct in_addr s,d;
		len = SIM_BUFLEN;
		ret = packet_recv(handle, buf, &len);
		if (ret == -1) {
			printf("packet_recv failed!\n");
			pthread_exit(NULL);
		}
		PDBG("packet: %u bytes eth %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x %04x",
			len,
			hdr->eth.ether_shost[0],
			hdr->eth.ether_shost[1],
			hdr->eth.ether_shost[2],
			hdr->eth.ether_shost[3],
			hdr->eth.ether_shost[4],
			hdr->eth.ether_shost[5],
			hdr->eth.ether_dhost[0],
			hdr->eth.ether_dhost[1],
			hdr->eth.ether_dhost[2],
			hdr->eth.ether_dhost[3],
			hdr->eth.ether_dhost[4],
			hdr->eth.ether_dhost[5],
			ntohs(hdr->eth.ether_type));
		if (ntohs(hdr->eth.ether_type) == 0x800) {	
			char ss[20], ds[20];

			s.s_addr = hdr->ip.saddr;
			d.s_addr = hdr->ip.daddr;
			strcpy(ss, inet_ntoa(s));
			strcpy(ds, inet_ntoa(d));
			PDBG(" ip %s -> %s proto %u", ss, ds, hdr->ip.protocol);
			if (hdr->ip.protocol == IPPROTO_UDP &&
			    ((ntohs(hdr->ip.frag_off) & IP_MF) == 0)) {
				PDBG(" udp %u -> %u len %u\n", ntohs(hdr->udp.source), ntohs(hdr->udp.dest), ntohs(hdr->udp.len));
				udp_handler((uint8_t *)buf, len);
			} else 
				PDBG("\n");
		} else {
			PDBG("\n");
		}
		fflush(stdout);
	}
}


static void complete_send_wr(struct c4iw_qp *qp, struct ibv_send_wr *wr)
{
	struct t4_cqe cqe;
	struct c4iw_cq *chp;
	struct t4_cq *cq;

	chp = to_c4iw_cq(qp->ibv_qp.send_cq);
	cq = &chp->cq;

	memset(&cqe, 0, sizeof(cqe));
	cqe.header = cpu_to_be32(V_CQE_STATUS(0) |
			         V_CQE_OPCODE(FW_RI_SEND) |
			         V_CQE_TYPE(1) |
			         V_CQE_SWCQE(1) |
			         V_CQE_QPID(qp->wq.sq.qid));
	CQE_WRID_SQ_IDX(&cqe) = qp->wq.sq.pidx;
	cqe.bits_type_ts = cpu_to_be64(V_CQE_GENBIT((u64)cq->gen));
	pthread_spin_unlock(&qp->lock);
	pthread_spin_lock(&chp->lock);
	cq->sw_queue[cq->sw_pidx] = cqe;
	t4_swcq_produce(cq);
	pthread_spin_unlock(&chp->lock);
	pthread_spin_lock(&qp->lock);
}

unsigned short iphdr_cksum(uint8_t *packet)
{
	int i;
	struct ip *iph = (struct ip *)(packet + sizeof(struct ether_header));
	unsigned short *w = (unsigned short *)iph;
	unsigned long sum;
	union {
		unsigned short	s[2];
		unsigned long	l;
	} c;

	for (i = c.l = 0; i < iph->ip_hl*2; ++i)
		c.l += w[i];
	sum = c.s[0] + c.s[1];
	while (sum>>16)
		ADDCARRY(sum);
	return ~sum & 0xffff;
}

unsigned short udp_cksum(uint8_t *packet)
{
	int i;
	struct ip *iph = (struct ip *)(packet + sizeof(struct ether_header));
	unsigned short *w = (unsigned short *)((char *)iph + iph->ip_hl*4);
	int udplen = ntohs(iph->ip_len) - iph->ip_hl*4;
	unsigned long sum;
	union {
		unsigned short	s[2];
		unsigned long	l;
	} c;

	/*
	 * Start with the UDP pseudo header.
	 */
	c.l  = iph->ip_src.s_addr & 0xffff;
	c.l += ((iph->ip_src.s_addr) >> 16) & 0xffff;
	c.l += iph->ip_dst.s_addr & 0xffff;
	c.l += ((iph->ip_dst.s_addr) >> 16) & 0xffff;
	c.l += htons(udplen + iph->ip_p);

	/*
	 * If the udp header + payload length is odd, zero the pad byte.
	 */
	if (udplen & 1)
		packet[(sizeof(struct ether_header)) + iph->ip_hl*4 + udplen++] = 0;

	/*
	 * Sum every 16-bit word into a 32-bit running total.
	 */
	for (i = 0; i < udplen/2; ++i)
		c.l += w[i];

	/*
	 * Fold and return the one's complement.
	 */
	sum = c.s[0] + c.s[1];
	while (sum>>16)
		ADDCARRY(sum);
	return ~sum & 0xffff;
}

int sim_send(struct c4iw_qp *qp, struct ibv_send_wr *wr)
{
	uint8_t buf[SIM_BUFLEN], *bp;
	int len;
	int i;
	int ret;
	struct udp_headers *hp;
	
	len = 0;
	bp = buf;
	for (i=0; i<wr->num_sge; i++) {
		if (len + wr->sg_list[i].length > SIM_BUFLEN) {
			ret = EINVAL;
			goto out;
		}
		memcpy(bp, (void *)wr->sg_list[i].addr, wr->sg_list[i].length);
		bp += wr->sg_list[i].length;
		len += wr->sg_list[i].length;
	}

	hp = (struct udp_headers *)buf;
	if (ntohs(hp->eth.ether_type) == 0x800) {
		hp->ip.check = 0;
		hp->ip.check = iphdr_cksum(buf);
		if (hp->ip.protocol == IPPROTO_UDP) {
			hp->udp.check = 0;
			hp->udp.check = udp_cksum(buf);
		} else {
			PDBG("SIM unsupported ipproto %u\n", hp->ip.protocol);
		}
	}
	ret = packet_send(handle, buf, len);
	if (!ret)
		complete_send_wr(qp, wr);
out:
	return ret;
}

int sim_attach_mcast(struct c4iw_qp *qp, const uint8_t *mcaddr)
{
	struct packet_mreq m;
	int s = (unsigned long)handle & 0x00ffffff;
	int index = (unsigned long)handle >> 24;
	socklen_t len = sizeof m;
	int ret;

	m.mr_type = PACKET_MR_MULTICAST;
	m.mr_ifindex = index;
	m.mr_alen = 6;
	memcpy(m.mr_address, mcaddr, 6);
	ret = setsockopt(s, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &m, len);
	if (ret == -1) {
		perror("setsockopt");
		printf("index %d, sock %d\n", index, s);
	}
	return ret;
}

int sim_detach_mcast(struct c4iw_qp *qp, const uint8_t *mcaddr)
{
	struct packet_mreq m;
	int s = (unsigned long)handle & 0x00ffffff;
	int index = (unsigned long)handle >> 24;
	socklen_t len = sizeof m;

	m.mr_type = PACKET_MR_MULTICAST;
	m.mr_ifindex = index;
	m.mr_alen = 6;
	memcpy(m.mr_address, mcaddr, 6);
	return setsockopt(s, SOL_PACKET, PACKET_DROP_MEMBERSHIP, &m, len);
}
#endif
