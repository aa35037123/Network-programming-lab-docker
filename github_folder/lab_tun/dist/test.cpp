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
#include <thread>
#include <mutex>
#include <csignal>
#include <cstdlib>
#include <cstdio>
#include <sstream>
#include <cmath>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>

using namespace std;
char tun_dev[IFNAMSIZ] = "tun0";
#define NIPQUAD(m)	((unsigned char*) &(m))[0], ((unsigned char*) &(m))[1], ((unsigned char*) &(m))[2], ((unsigned char*) &(m))[3]
#define errquit(m)	{ perror(m); exit(-1); }

#define MYADDR		0x0a0000fe // 10.0.0.254
// char MYADDR[10] = "0a0000fe";
#define ADDRBASE	0x0a00000a // 10.0.0.10
#define	NETMASK		0xffffff00 // 255.255.255.0

int
tun_alloc(char *dev) {
	struct ifreq ifr;
	int fd, err;
	if((fd = open("/dev/net/tun", O_RDWR)) < 0 )
		return -1;
	memset(&ifr, 0, sizeof(ifr));
	// IFF_TUN: this virtual interface works on network layer
	// IFF_TAP: works on link layer
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

/*set flag to tun dev*/
int
ifreq_get_flag(int fd, const char *dev, short *flag) {
	int err;
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	if(dev) strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	cout << "get_flag fd: " << fd << endl;
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
	cout << "HAHA, fd: " << fd << endl;
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
	return ioctl(fd, cmd, &ifr);
}
/*fd must be socket, no tun descriptor*/
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

void handle_client(int sockfd, int tun_fd_serv, struct sockaddr_in cli_addr, unsigned int client_num){
	char sendline[1500];
	char rcvbuf[1500];
	int n;
	bzero(&sendline, sizeof(sendline));
	sprintf(sendline, "%u\n", client_num);
	if(sendto(sockfd, sendline, sizeof(sendline), 0, (struct sockaddr *) &cli_addr, sizeof(cli_addr)) < 0){
		errquit("server-handle_client send error");
	}
	else{ cout << "send to cli success!\n";}
	while(1){
		// TODO: handle connection to client
		bzero(&rcvbuf, sizeof(rcvbuf));
		if((n = read(tun_fd_serv, rcvbuf, sizeof(rcvbuf))) < 0){
			continue;
		}else{
			cout << "server read " << n << " byte from tun socket\n";
		} 
	}
}
int
tunvpn_server(int port) {
	char rcvbuf[1500];
	char sendline[1500];
	stringstream ss;
	// XXX: implement your server codes here ...
	fprintf(stderr, "## [server] starts ...\n");
	struct sockaddr_in serv_addr, cli_addr;
	short flags;
	int sockfd;
	unsigned int client_num = 0;
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) errquit("server create socket");
	bzero(&serv_addr, sizeof(serv_addr));
	bzero(&cli_addr, sizeof(cli_addr));
	serv_addr.sin_family = AF_INET; // IPv4 
    serv_addr.sin_addr.s_addr = INADDR_ANY; 
    serv_addr.sin_port = htons(port);
	int n;
	if(bind(sockfd, (const struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) errquit("server bind");
	socklen_t clilen = sizeof(cli_addr);
	int tun_fd_serv;
	if((tun_fd_serv = tun_alloc(tun_dev)) < 0){
		close(sockfd);
		errquit("tun_alloc");
	}
	cout << "Allocate fd: " << tun_fd_serv << endl;
	unsigned int addr = MYADDR;
	
	addr = htonl(addr);
	cout << "server addr: " << addr << endl;
	printf("%u.%u.%u.%u\n", NIPQUAD(addr));
	
	if(ifreq_set_addr(sockfd, tun_dev, addr) < 0){
		close(sockfd);
		close(tun_fd_serv);
		errquit("ifreq_set_addr");
	}
	// ss.str("");
    // ss.clear();
	// ss << std::hex << NETMASK;
	// ss >> x;
	// cout << "server netmask: " << x;
	unsigned int mask = NETMASK;
	// sscanf(NETMASK, "%x", &mask);
	mask = htonl(mask);
	cout << "server mask: " << mask;
	printf("%u.%u.%u.%u\n", NIPQUAD(mask));
	if(ifreq_set_netmask(sockfd, tun_dev, mask) < 0){
		close(sockfd);
		close(tun_fd_serv);
		errquit("ifreq_set_netmask");
	}

	if(ifreq_set_mtu(sockfd, tun_dev, 1400) < 0){
		close(sockfd);
		close(tun_fd_serv);
		errquit("ifreq_set_netmask");
	}
	if (ifreq_get_flag(sockfd, tun_dev, &flags) < 0){
		close(sockfd);
        close(tun_fd_serv);
		errquit("ifreq_get_flag");
	}
	// flags |= (IFF_POINTOPOINT|IFF_MULTICAST|IFF_NOARP|IFF_UP);  // Set the IFF_UP flag to bring up the interface
	flags |= IFF_UP;
	if (ifreq_set_flag(sockfd, tun_dev, flags) < 0) {
		close(sockfd);
        close(tun_fd_serv);
		errquit("ifreq_set_flag");
	}
	// thread receive_tun(tun_from_serv, tun_fd_serv, sockfd, cli_addr);
	// receive_tun.detach();
	// this write when server receive ping from another client
	while(1) { 
		// when there are a client connect in, create a new thread to handle it
		client_num += 1;
		bzero(&rcvbuf, sizeof(rcvbuf));
		// data from client pkt is no use, this pkt is used for client detect
		if(recvfrom(sockfd, rcvbuf, sizeof(rcvbuf), 0, (struct sockaddr*)&cli_addr, &clilen) < 0)
			continue;
		else cout << "recv from client!\n";
		thread new_client(handle_client, sockfd, tun_fd_serv, cli_addr, client_num);
		new_client.detach();
		
	}
	return 0;
}
// void tun_from_cli(int tun_fd_cli, int sockfd){
// 	char rcvbuf[1500];
// 	char sendline[1500];
// 	int n;
// 	// lock_.lock();
// 	// memset(bset, '0', sizeof(bset) - 1);
// 	// lock_.unlock();
	
// 	// this write when client ping server 
// 	// read from tun, and write to network through sockfd
// 	while(1){
// 		bzero(&rcvbuf, sizeof(rcvbuf));
// 		if((n = read(tun_fd_cli, rcvbuf, sizeof(rcvbuf))) < 0) 
// 			continue;
// 		bzero(&sendline, sizeof(sendline));
// 		strcpy(sendline, rcvbuf);
// 		if(write(sockfd, sendline, sizeof(sendline)) < 0)
// 			errquit("tun_from_cli udp send");
// 	}
// }
string exec(const char* cmd) {
    array<char, 128> buffer;
    string result;
    unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

int
tunvpn_client(const char *server, int port) {
	char rcvbuf[1500];
	char sendline[1500];
	char tun_dev[20] = "tun0";
	// Concatenate the command
    // char fullCmd[256] = "nslookup server | grep 172";
	// string result = exec(fullCmd);
	// cout << "result: " << result << endl;
	char server_ip[40] = "172.28.28.2";
	// size_t addressPos = result.find("Address: ");
	// string ip_parse;
    // if (addressPos != std::string::npos) {
    //     // Extract the address substring
    //     ip_parse = result.substr(addressPos + 9);
	// 	ip_parse.push_back('\0');
    //     // Print or use the extracted address
    //     std::cout << "Parsed Address: " << ip_parse << std::endl;
	// 	// server_ip = addressSubstring.c_str();
	// }
	// strcpy(server_ip, ip_parse.c_str());
	int n;
	// XXX: implement your client codes here ...
	fprintf(stderr, "## [client] starts ...\n");
	// struct sockaddr_in addr;
	struct sockaddr_in serv_addr;
	int sockfd;
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);
	if(inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) != 1) {
		return -fprintf(stderr, "** cannot convert IPv4 address for client\n");
	}
	
	if((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0){ errquit("client socket");}
	else cout << "successfully create socket\n";
	if(connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0){ errquit("client connect") } 
	else cout << "successfully connect to server\n";
	cout << "server config complete!\n";
	// thread receive_tun(tun_from_cli, tun_fd_cli, sockfd);
	// receive_tun.detach();
	
	// receive client number from server, tun addr = ADDRBASE+client_num
	bzero(&sendline, sizeof(sendline));
	sprintf(sendline, "Hello, server");
	// write to vpn network, so ping can catch it
	if(write(sockfd, sendline, sizeof(sendline)) < 0){
		errquit("client sockfd write wrong");
	}
	else{ cout << "send hello success!\n"; }
	bzero(&rcvbuf, sizeof(rcvbuf));
	if((n = read(sockfd, rcvbuf, sizeof(rcvbuf))) < 0){
		errquit("client sockfd rcv wrong");
	}
	else{ cout << "read from server success!\n";}
	int cli_num = 0;
	sscanf(rcvbuf, "%d\n", &cli_num);
	unsigned int cli_tun_addr = ADDRBASE; cli_tun_addr += cli_num;
	cout << "cli number: " << cli_num << endl;
	int tun_fd_cli;
	if((tun_fd_cli = tun_alloc(tun_dev)) < 0){
		errquit("tun_alloc");
	}

	cli_tun_addr = htonl(cli_tun_addr);
	cout << "client addr: " << cli_tun_addr << endl;
	printf("%u.%u.%u.%u\n", NIPQUAD(cli_tun_addr));
	
	if(ifreq_set_addr(sockfd, tun_dev, cli_tun_addr) < 0){
		close(sockfd);
		close(tun_fd_cli);
		errquit("ifreq_set_addr");
	}

	if(ifreq_set_mtu(sockfd, tun_dev, 1400) < 0){
		close(sockfd);
		close(tun_fd_cli);
		errquit("ifreq_set_netmask");
	}
	short int flags = 0;
	if (ifreq_get_flag(sockfd, tun_dev, &flags) < 0){
		close(sockfd);
        close(tun_fd_cli);
		errquit("ifreq_get_flag");
	}
	// flags |= (IFF_POINTOPOINT|IFF_MULTICAST|IFF_NOARP|IFF_UP);  // Set the IFF_UP flag to bring up the interface
	flags |= IFF_UP;
	if (ifreq_set_flag(sockfd, tun_dev, flags) < 0) {
		close(sockfd);
        close(tun_fd_cli);
		errquit("ifreq_set_flag");
	}
	// this write when server ping client 
	while(1) { 
		
		bzero(&rcvbuf, sizeof(rcvbuf));
		if((n = read(tun_fd_cli, rcvbuf, sizeof(rcvbuf))) < 0){
			continue;
		}else{
			cout << "read " << n << " byte from udp socket\n";
		}
		// bzero(&sendline, sizeof(sendline));
		// strcpy(sendline, rcvbuf);
		// // write to vpn network, so ping can catch it
		// if(write(tun_fd_cli, sendline, sizeof(sendline)) < 0){
		// 	errquit("tun_from_cli udp send");
		// }else{
		// 	cout << "write sucess";
		// }
	}
	return 0;
}

int
usage(const char *progname) {
	fprintf(stderr, "usage: %s {server|client} {options ...}\n"
		"# server mode:\n"
		"	%s server port\n"
		"# client mode:\n"
		"	%s client servername serverport\n",
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
		if(argc < 4) return usage(argv[0]);
		return tunvpn_client(argv[2], strtol(argv[3], NULL, 0));
	} else {
		fprintf(stderr , "## unknown mode %s\n", argv[1]);
	}
	return 0;
}
