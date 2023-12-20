/*
 *  Lab problem set for INP course
 *  by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
 *  License: GPLv2
 */
#include <iostream>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/select.h>
using namespace std;
#define NIPQUAD(m)	((unsigned char*) &(m))[0], ((unsigned char*) &(m))[1], ((unsigned char*) &(m))[2], ((unsigned char*) &(m))[3]
#define errquit(m)	{ perror(m); exit(-1); }

#define MYADDR		0x0a0000fe		//10.0.0.254
#define ADDRBASE	0x0a00000a		//10.0.0.10
#define	NETMASK		0xffffff00		//255.255.255.0
#define MTU 1400

char tun_name[IFNAMSIZ] = "tun0";

static int 
max(int a, int b) {
  return a > b ? a : b;
}

int
tun_alloc(char *dev) {
	struct ifreq ifr;
	int fd, err;
	if((fd = open("/dev/net/tun", O_RDWR)) < 0 )
		return -1;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;	/* IFF_TUN (L3), IFF_TAP (L2), IFF_NO_PI (w/ header) */
	if(dev && dev[0] != '\0') strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	if((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
		close(fd);
		return err;
	}
	if(dev) strcpy(dev, ifr.ifr_name);
	return fd;
}

int
ifreq_set_mtu(int fd, const char *dev, int mtu) {
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_mtu = mtu;
	if(dev) strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	return ioctl(fd, SIOCSIFMTU, &ifr);
}

int
ifreq_get_flag(int fd, const char *dev, short *flag) {
	int err;
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	if(dev) strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	err = ioctl(fd, SIOCGIFFLAGS, &ifr);
	if(err == 0) {
		*flag = ifr.ifr_flags;
	}
	return err;
}

int
ifreq_set_flag(int fd, const char *dev, short flag) {
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	if(dev) strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	ifr.ifr_flags = flag;
	return ioctl(fd, SIOCSIFFLAGS, &ifr);
}

int
ifreq_set_sockaddr(int fd, const char *dev, int cmd, unsigned int addr) {
	struct ifreq ifr;
	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = addr;
	memset(&ifr, 0, sizeof(ifr));
	memcpy(&ifr.ifr_addr, &sin, sizeof(struct sockaddr));
	
	if(dev) strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	cout << "cmd: " << cmd << endl;
	cout << "tun fd: " << fd << "dev: " << dev << endl;
	cout << "ifr: " << &ifr << endl; 
	int error = ioctl(fd, cmd, &ifr);
	cout << "ioctl return: " << error << endl;	
	return error;
}

int
ifreq_set_addr(int fd, const char *dev, unsigned int addr) {
	return ifreq_set_sockaddr(fd, dev, SIOCSIFADDR, addr);
}

int
ifreq_set_netmask(int fd, const char *dev, unsigned int addr) {
	return ifreq_set_sockaddr(fd, dev, SIOCSIFNETMASK, addr);
}

int
ifreq_set_broadcast(int fd, const char *dev, unsigned int addr) {
	return ifreq_set_sockaddr(fd, dev, SIOCSIFBRDADDR, addr);
}

void 
encrypt(char *plantext, char *ciphertext, int len) {
  memcpy(ciphertext, plantext, len);
}

void 
decrypt(char *ciphertext, char *plantext, int len) {
  memcpy(plantext, ciphertext, len);
}

int
tunvpn_server(int port) {
	// XXX: implement your server codes here ...
	fprintf(stderr, "## [server] starts ...\n");

	int tun_fd,udp_fd;
	//create UDP socket
	if((udp_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
		errquit("socket");
	}

	//set up UDP address
	struct sockaddr_in server_addr;
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

	//bind UDP socket
	if (bind(udp_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        errquit("bind");
    }

	//create tun interface
	if((tun_fd = tun_alloc(tun_name)) < 0){
		errquit("tun_alloc");
	}
	cout << "allocate device: " << tun_fd << endl;
	unsigned int addr = MYADDR;
	addr = htonl(addr);
	printf("%u.%u.%u.%u\n", NIPQUAD(addr));

	// configure TUN interface address
    if(ifreq_set_addr(udp_fd, tun_name, addr)){
		errquit("ifreq_set_addr");
	}
	unsigned int mask = NETMASK;
	mask = htonl(mask);
	printf("%u.%u.%u.%u\n", NIPQUAD(mask));
    // configure TUN interface network mask
    if(ifreq_set_netmask(udp_fd, tun_name, mask))
		errquit("ifreq_set_netmask");
    // configure TUN interface broadcast address
	unsigned int addbase = ADDRBASE | ~NETMASK;
	addbase = htonl(addbase);
    if(ifreq_set_broadcast(udp_fd, tun_name, addbase)<0)
		errquit("ifreq_set_broadcast");
	// set MTU
	if(ifreq_set_mtu(udp_fd, tun_name, MTU) < 0)
		errquit("ifreq_set_mtu");
	short int flags;
	if(ifreq_get_flag(udp_fd, tun_name, &flags) < 0)
		errquit("ifreq_get_flag");
    // set TUN interface up
	if (ifreq_set_flag(udp_fd, tun_name, flags | IFF_UP) < 0) 
        errquit("ifreq_set_flag");
    
    // ifreq_set_flag(tun_fd, tun_name, IFF_UP & IFF_RUNNING);

	cout << "successful create tun fd!\n";


	char tun_buf[MTU], udp_buf[MTU];
	bzero(tun_buf, MTU);
	bzero(udp_buf, MTU);
	
	while(1){
    	fd_set readset;
		FD_ZERO(&readset);
		FD_SET(tun_fd, &readset);
		FD_SET(udp_fd, &readset);
		int max_fd = max(tun_fd, udp_fd) + 1;
		
		if (-1 == select(max_fd, &readset, NULL, NULL, NULL)) {
			errquit("select");
			break;
		}

		int r;
		if (FD_ISSET(tun_fd, &readset)) {

			//read from tun
			r = read(tun_fd, tun_buf, MTU);
			if (r < 0) {
				errquit("read");
			}

			printf("Read from tun %d bytes ...\n", r);


			//encrypt
			encrypt(tun_buf, udp_buf, r);

			//write to UDP
			r = write(udp_fd, udp_buf, r);
			if (r < 0) {
				errquit("write");
			}
			printf("Writing to UDP %d bytes ...\n", r);

		}

		if (FD_ISSET(udp_fd, &readset)) {

			//read from UDP
			r = read(udp_fd, udp_buf, MTU);
			if (r < 0) {
				errquit("read");
			}

			printf("Read from UDP %d bytes ...\n", r);


			//decrypt
			decrypt(udp_buf, tun_buf, r);

			//write to tun
			r = write(tun_fd, tun_buf, r);
			if (r < 0) {
				errquit("write");
			}
			printf("Writing to tun %d bytes ...\n", r);

		}
	}
	close(tun_fd);
	close(udp_fd);

	return 0;
}

int 
tunvpn_client(const char *server, int port, int client_number) {
    fprintf(stderr, "## [client] starts ...\n");

    int tun_fd, udp_fd;

    // Create tun interface
    if ((tun_fd = tun_alloc(tun_name)) < 0) {
        errquit("tun_alloc");
    }

    // Configure TUN interface address
    unsigned int client_vpn_addr = ADDRBASE + client_number;
    ifreq_set_addr(tun_fd, tun_name, client_vpn_addr);

    // Configure TUN interface network mask
    ifreq_set_netmask(tun_fd, tun_name, NETMASK);

    // Configure TUN interface broadcast address
    ifreq_set_broadcast(tun_fd, tun_name, ADDRBASE | ~NETMASK);

	// set MTU
	ifreq_set_mtu(tun_fd, tun_name, MTU);

    // Set TUN interface up
    ifreq_set_flag(tun_fd, tun_name, IFF_UP & IFF_RUNNING);

	

	// Create UDP socket
    if ((udp_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        errquit("socket");
    }

    // Set up UDP server address
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
	server_addr.sin_addr.s_addr = INADDR_ANY;
	// char server_str[] = "";

    // if (inet_pton(AF_INET, server_str, &server_addr.sin_addr) <= 0) {
    //     errquit("inet_pton");
    // }

    char tun_buf[MTU], udp_buf[MTU];
    bzero(tun_buf, MTU);
    bzero(udp_buf, MTU);

    while (1) {
        fd_set readset;
        FD_ZERO(&readset);
        FD_SET(tun_fd, &readset);
        FD_SET(udp_fd, &readset);
        int max_fd = max(tun_fd, udp_fd) + 1;

        if (-1 == select(max_fd, &readset, NULL, NULL, NULL)) {
            errquit("select");
            break;
        }

        int r;
        if (FD_ISSET(tun_fd, &readset)) {
            // Read from tun
            r = read(tun_fd, tun_buf, MTU);
            if (r < 0) {
                errquit("read");
            }

            printf("Read from tun %d bytes ...\n", r);

            // Encrypt
            encrypt(tun_buf, udp_buf, r);

            // Write to UDP
            r = sendto(udp_fd, udp_buf, r, 0, (struct sockaddr*)&server_addr, sizeof(server_addr));
            if (r < 0) {
                errquit("sendto");
            }
            printf("Writing to UDP %d bytes ...\n", r);
        }

        if (FD_ISSET(udp_fd, &readset)) {
            // Read from UDP
            r = recvfrom(udp_fd, udp_buf, MTU, 0, NULL, NULL);
            if (r < 0) {
                errquit("recvfrom");
            }

            printf("Read from UDP %d bytes ...\n", r);

            // Decrypt
            decrypt(udp_buf, tun_buf, r);

            // Write to tun
            r = write(tun_fd, tun_buf, r);
            if (r < 0) {
                errquit("write");
            }
            printf("Writing to tun %d bytes ...\n", r);
        }
    }

    // Close file descriptors
    close(tun_fd);
    close(udp_fd);

    return 0;
}

int
usage(const char *progname) {
	fprintf(stderr, "usage: %s {server|client} {options ...}\n"
		"# server mode:\n"
		"	%s server port\n"
		"# client mode:\n"
		"	%s client servername serverport client_number(1 or 2)\n",
		progname, progname, progname);
	return -1;
}

int main(int argc, char *argv[]) {
	if(argc < 3) {
		return usage(argv[0]);
	}
	if(strcmp(argv[1], "server") == 0) {
		if(argc < 3) return usage(argv[0]);
		return tunvpn_server(strtol(argv[2], NULL, 0));
	} else if(strcmp(argv[1], "client") == 0) {
		if(argc < 5) return usage(argv[0]);
		return tunvpn_client(argv[2], strtol(argv[3], NULL, 0),strtol(argv[4], NULL, 0));
	} else {
		fprintf(stderr , "## unknown mode %s\n", argv[1]);
	}
	return 0;
}