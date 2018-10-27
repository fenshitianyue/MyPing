#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <netdb.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define DATA_LEN 56
#define PSIZE    1024

char sendpacket[PSIZE];
char recvpacket[PSIZE];

int sendnum = 0;
int recvnum = 0;
struct sockaddr_in from;

void handler(int s)
{
	printf("-----------------------status-----------------------\n");
	printf("%d packets transmitted, %d received, %.3f%% packet lost.\n",
				sendnum, recvnum, ((sendnum-recvnum) / sendnum) * 100.0);
	exit(0);
}

float diftime(struct timeval *begin, struct timeval *end)
{
	float d = (end->tv_sec - begin->tv_sec) * 1000 + 	
					(end->tv_usec - begin->tv_usec ) / 1000;
	return d;
}

unsigned short chksum(unsigned short *addr, int len)
{
	unsigned int ret = 0;

	while ( len > 1 ) {
		ret += *addr++;
		len -= 2;
	}
	
	if ( len == 1 )
		ret += *(char*)addr;

	ret = (ret>>16) + (ret & 0xffff);
	ret = ret + (ret>>16);
	
	return (unsigned short)~ret;
}

int pack(int no, pid_t pid)
{
	struct icmp *icmp;
	icmp = (struct icmp*)sendpacket;
	icmp->icmp_type  = ICMP_ECHO;
	icmp->icmp_code  = 0;
	icmp->icmp_cksum = 0;
	icmp->icmp_seq   = no;
	icmp->icmp_id    = pid;
	struct timeval *pt;
	pt = (struct timeval*)(icmp->icmp_data),
	gettimeofday(pt, NULL);
	int len = DATA_LEN + 8;
	icmp->icmp_cksum = chksum((unsigned short*)sendpacket, len);

	return len;
}

void unpack(char *buf, int len, pid_t pid)
{
	struct ip *pip = (struct ip*)buf;
	struct icmp *picmp = (struct icmp*)(buf+(pip->ip_hl<<2));
	struct timeval end;
	gettimeofday(&end, NULL);
	float diff = diftime(&end, (struct timeval*)(picmp->icmp_data));
	printf("%d bytes from %s : icmp_seq=%d, ttl=%d, rtt=%.3f ms\n",
			DATA_LEN, inet_ntoa(from.sin_addr), picmp->icmp_seq, pip->ip_ttl, diff);
}

void send_packet(int fd, pid_t pid, struct sockaddr_in addr)
{
	int r = 0;
	sendnum++;
	r = pack(sendnum, pid);
	socklen_t sz = sizeof addr;
	sendto(fd, sendpacket, r, 0, (struct sockaddr*)&addr, sz);
}

void recv_packet(int fd, pid_t pid)
{
	socklen_t len = sizeof from;
	int n = recvfrom(fd, recvpacket, PSIZE, 0, (struct sockaddr*)&from, &len);
	recvnum++;
	unpack(recvpacket, n, pid);
}

int main( int argc, char *argv[] ) {
	in_addr_t addr;
	struct sockaddr_in ad;
	struct hostent *ph = NULL;

	if ( argc != 2 ) {
		fprintf(stderr, "./myping ip\n");
		exit(1);
	}

	signal(SIGINT, handler);
	ad.sin_family = AF_INET;
	if ((addr = inet_addr(argv[1])) == INADDR_NONE ) {
		if ( (ph = gethostbyname(argv[1])) == NULL)
			perror("gethostbyname"),exit(1);
		memcpy((char*)&ad.sin_addr, (char*)ph->h_addr, ph->h_length);
	} else
		ad.sin_addr.s_addr = addr;
	
	int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if ( fd == -1 ) perror("socket"),exit(1);
	
	printf("ping %s(%s) %d bytes of data.\n", argv[1], inet_ntoa(ad.sin_addr), DATA_LEN);
	pid_t pid = getpid();
	while ( 1 ) {
		send_packet(fd, pid, ad);
		recv_packet(fd, pid);
		sleep(1);
	}
}

