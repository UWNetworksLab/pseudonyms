#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>             
#include <net/if.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#if __GLIBC__ >=2 && __GLIBC_MINOR >= 1
#include <netpacket/packet.h>
#include <net/ethernet.h>
#else
#include <asm/types.h>
#include <linux/if_ether.h>
#endif

#define ifreq_offsetof(x)  offsetof(struct ifreq, x)

struct in6_ifreq {
    struct in6_addr ifr6_addr;
    __u32 ifr6_prefixlen;
    unsigned int ifr6_ifindex;
};

int assign_address(const char *IFNAME, const char *HOST) {

    struct ifreq ifr;
    struct sockaddr_in6 sai;
    int sockfd;                     
    struct in6_ifreq ifr6;

    sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP);
    if (sockfd == -1) {
          printf("Bad fd\n");
          return -1;
    }

    /* get interface name */
    strncpy(ifr.ifr_name, IFNAME, IFNAMSIZ);

    memset(&sai, 0, sizeof(struct sockaddr));
    sai.sin6_family = AF_INET6;
    sai.sin6_port = 0;

    if(inet_pton(AF_INET6, HOST, (void *)&sai.sin6_addr) <= 0) {
        printf("Bad address\n");
        return -1;
    }

    memcpy((char *) &ifr6.ifr6_addr, (char *) &sai.sin6_addr,
               sizeof(struct in6_addr));

    if (ioctl(sockfd, SIOGIFINDEX, &ifr) < 0) {
        perror("SIOGIFINDEX");
    }
    ifr6.ifr6_ifindex = ifr.ifr_ifindex;
    ifr6.ifr6_prefixlen = 64;
    if (ioctl(sockfd, SIOCSIFADDR, &ifr6) < 0) {
        perror("SIOCSIFADDR");
    }

    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;

    int ret = ioctl(sockfd, SIOCSIFFLAGS, &ifr);
    printf("ret: %d\terrno: %d\n", ret, errno);

    close(sockfd);
    return 0;
}
