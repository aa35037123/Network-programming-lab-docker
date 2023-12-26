/*
 *  Lab problem set for INP course
 *  by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
 *  License: GPLv2
 */
#include <iostream>
#include <ctype.h>
#include <cstdio>
#include <cstring>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <thread>
#include <mutex>
#include <cstdlib>
#include <sstream>
#include <cmath>
#include <string>
#include <assert.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <map>
#include <unordered_map>

using namespace std;
char tun_dev[IFNAMSIZ] = "tun0";
#define NIPQUAD(m)	((unsigned char*) &(m))[0], ((unsigned char*) &(m))[1], ((unsigned char*) &(m))[2], ((unsigned char*) &(m))[3]
#define errquit(m)	{ perror(m); exit(-1); }
#define MTU 1400
#define MAXLINE 2000
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


static void run(const char *cmd) {
  printf("Execute `%s`\n", cmd);
  char auth_cmd[100];
//   sprintf(auth_cmd, "sudo %s", cmd);
  if (system(cmd)) {
    perror(cmd);
    exit(1);
  }
}
static std::string get_eth0_ip() {
    FILE* pipe = popen("ifconfig eth0 | awk '/inet addr/{print substr($2,6)}'", "r");
    if (!pipe) {
        perror("popen");
        exit(1);
    }

    char buffer[128];
    std::string result = "";
    while (!feof(pipe)) {
        if (fgets(buffer, 128, pipe) != nullptr)
            result += buffer;
    }

    pclose(pipe);
	// 找到換行符的位置，並使用 erase 刪除
	size_t pos;
	while((pos = result.find('\n')) != std::string::npos){
		result.erase(pos, 1); // erase 1 char form pos
	}
    return result;
}

// void setup_route_table(string ip_addr) {
// 	// run("sysctl -w net.ipv4.ip_forward=1");
// 	run("iptables -I FORWARD 1 -i tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT");
// 	run("iptables -I FORWARD 1 -o tun0 -j ACCEPT");
// 	run("ip route add 0/1 dev tun0");
//   	run("ip route add 128/1 dev tun0");
// // #ifdef AS_CLIENT
// //   run("iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE");
// //   run("iptables -I FORWARD 1 -i tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT");
// //   run("iptables -I FORWARD 1 -o tun0 -j ACCEPT");
// //   char cmd[1024];
// //   snprintf(cmd, sizeof(cmd), "ip route add %s via $(ip route show 0/0 | sed -e 's/.* via \([^ ]*\).*/\1/')", SERVER_HOST);
// //   run(cmd);
// //   run("ip route add 0/1 dev tun0");
// //   run("ip route add 128/1 dev tun0");
// // #else
// //   run("iptables -t nat -A POSTROUTING -s 10.8.0.0/16 ! -d 10.8.0.0/16 -m comment --comment 'vpndemo' -j MASQUERADE");
// //   run("iptables -A FORWARD -s 10.8.0.0/16 -m state --state RELATED,ESTABLISHED -j ACCEPT");
// //   run("iptables -A FORWARD -d 10.8.0.0/16 -j ACCEPT");
// // #endif
// 	string rule_cmd = "ip rule add table 128 from " + ip_addr; 
// 	run(rule_cmd.c_str());
// 	run("ip route add table 128 to 172.28.28.0/24 dev eth0");
// 	run("ip route add table 128 default via 172.28.28.1");
// }
void setup_route_table(const char* client_ip, const char* server_ip, int serial, int is_client) {
	// run("sysctl -w net.ipv4.ip_forward=1");
	char cmd[1024];
    int table_num = 128;
    if(is_client){
		run("iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE");
		run("iptables -I FORWARD 1 -i tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT");
		run("iptables -I FORWARD 1 -o tun0 -j ACCEPT");
		run("ip route add 0/1 dev tun0");
		run("ip route add 128/1 dev tun0");
		bzero(&cmd, sizeof(cmd));
		snprintf(cmd, sizeof(cmd), "ip route add %s via 172.28.28.1", server_ip);
		run(cmd);
		/*===================my rule==================*/
		string rule_cmd = "ip rule add table " + to_string(table_num) + " from " + client_ip; 
		run(rule_cmd.c_str());
		bzero(&cmd, sizeof(cmd));
		snprintf(cmd, sizeof(cmd), "ip route add table %d to 172.28.28.0/24 dev eth0", table_num);
		run(cmd);

		bzero(&cmd, sizeof(cmd));
		snprintf(cmd, sizeof(cmd), "ip route add table %d default via 172.28.28.1", table_num);
		run(cmd);

		// run("ip route add table 128 to 172.28.28.0/24 dev eth0");
		// run("ip route add table 128 default via 172.28.28.1");
	}else{
        run("iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE");
		run("iptables -I FORWARD 1 -i tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT");
		run("iptables -I FORWARD 1 -o tun0 -j ACCEPT");
		run("ip route add 0/1 dev tun0");
		run("ip route add 128/1 dev tun0");
		bzero(&cmd, sizeof(cmd));
		snprintf(cmd, sizeof(cmd), "ip route add %s via 172.28.28.1", server_ip);
		run(cmd);
		/*===================my rule==================*/
		string rule_cmd = "ip rule add table " + to_string(table_num) + " from " + client_ip; 
		run(rule_cmd.c_str());
		bzero(&cmd, sizeof(cmd));
		snprintf(cmd, sizeof(cmd), "ip route add table %d to 172.28.28.0/24 dev eth0", table_num);
		run(cmd);

		bzero(&cmd, sizeof(cmd));
		snprintf(cmd, sizeof(cmd), "ip route add table %d default via 172.28.28.1", table_num);
		run(cmd);
        /*Let packet whose dest_ip not in 10.0.0.0/24 can work after leave tunnel network*/
		run("iptables -t nat -A POSTROUTING -s 172.28.28.0/24 ! -d 172.28.28.0/24 -m comment --comment 'vpndemo' -j MASQUERADE");
		run("iptables -A FORWARD -s 172.28.28.0/24 -m state --state RELATED,ESTABLISHED -j ACCEPT");
		run("iptables -A FORWARD -d 172.28.28.0/24 -j ACCEPT");

        run("iptables -t nat -A POSTROUTING -s 10.0.0.0/24 ! -d 10.0.0.0/24 -m comment --comment 'vpndemo' -j MASQUERADE");
		run("iptables -A FORWARD -s 10.0.0.0/24 -m state --state RELATED,ESTABLISHED -j ACCEPT");
		run("iptables -A FORWARD -d 10.0.0.0/24 -j ACCEPT");
	}
	
}

struct map_addr_port{
	string addr;
	int port;
};
int
tunvpn_server(int port) {
	char rcvbuf[MAXLINE];
	char sendline[MAXLINE];
	char udp_buf[MAXLINE];
    char udp_sendline[MAXLINE];
	char tun_buf[MAXLINE];
	char src_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
	char distri_ip[INET_ADDRSTRLEN];
    char server_ip_tun[INET_ADDRSTRLEN];
    char cmd[100];
	unordered_map<string, map_addr_port> ip_serial_table;
	stringstream ss;
	// XXX: implement your server codes here ...
	fprintf(stderr, "## [server] starts ...\n");
	struct sockaddr_in serv_addr, cli_addr;
	short flags;
	int sockfd;
	unsigned int client_num = 0;
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) errquit("server create socket");
	const int enable = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
        errquit("setsockopt(SO_REUSEADDR) failed");
    const int enable_port = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &enable_port, sizeof(int)) < 0)
        errquit("setsockopt(SO_REUSEPORT) failed");
    bzero(&serv_addr, sizeof(serv_addr));
	bzero(&cli_addr, sizeof(cli_addr));
	serv_addr.sin_family = AF_INET; // IPv4 
    serv_addr.sin_addr.s_addr = INADDR_ANY; 
    serv_addr.sin_port = htons(port);
	int n;
    // setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &serv_addr, sizeof(serv_addr));
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
	cout << "server addr: ";
	printf("%u.%u.%u.%u\n", NIPQUAD(addr));
	string phy_serv_ip = get_eth0_ip();
    snprintf(server_ip_tun, sizeof(server_ip_tun),"%u.%u.%u.%u", NIPQUAD(addr)); // output to c_str
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
	cout << "server mask: ";
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
	// this write when server receive ping from another client
	// setup_route_table(phy_serv_ip);
    setup_route_table(phy_serv_ip.c_str(), phy_serv_ip.c_str(), -1, 0);
	while(1) { 
	
		// bzero(&rcvbuf, sizeof(rcvbuf));
		// // data from client pkt is no use, this pkt is used for client detect
		// if(recvfrom(sockfd, rcvbuf, sizeof(rcvbuf), 0, (struct sockaddr*)&cli_addr, &clilen) < 0)
		// 	continue;
		// else cout << "recv from client!\n";

		// thread new_client(handle_client, sockfd, tun_fd_serv, cli_addr, client_num);
		// new_client.detach();


		fd_set readset;  
		FD_ZERO(&readset);
		FD_SET(tun_fd_serv, &readset);
		FD_SET(sockfd, &readset);
		int max_fd = max(tun_fd_serv, sockfd) + 1;
        cout << "================================\n";
		// select block when none of fd in readset "ready"
		if (-1 == select(max_fd, &readset, NULL, NULL, NULL)) {
			// perror("select error");
			cout << "select error...\n";
			continue;
		}
		int r;
		int counter = 0;
		if (FD_ISSET(tun_fd_serv, &readset)) {
			counter++;
			bzero(&tun_buf, sizeof(tun_buf));
			r = read(tun_fd_serv, tun_buf, MTU);
			if (r < 0) {
				// TODO: ignore some errno
				// errquit("read from tun_fd error");
				cout << "read from <<tun>> error\n";
				continue;
			}else{
				cout << "read from <<tun>> fd\n";
			}
            struct iphdr* ip_header = reinterpret_cast<struct iphdr*>(tun_buf);
			bzero(&src_ip, sizeof(src_ip));
			inet_ntop(AF_INET, &(ip_header->saddr), src_ip, INET_ADDRSTRLEN);
			bzero(&dest_ip, sizeof(dest_ip));
			inet_ntop(AF_INET, &(ip_header->daddr), dest_ip, INET_ADDRSTRLEN);
            cout << "src: " << src_ip << " dest: " << dest_ip << endl;
			bzero(&udp_buf, sizeof(udp_buf));
			// encrypt(tun_buf, udp_buf, r);
			memcpy(udp_buf, tun_buf, r);
            char clientIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(cli_addr.sin_addr), clientIP, INET_ADDRSTRLEN);
            cout << "send to client ip addr: " << clientIP << endl;
			r = sendto(sockfd, udp_buf, r, 0, (struct sockaddr *) &cli_addr, clilen);
			if (r < 0) {
				// TODO: ignore some errno
				// errquit("sendto udp_fd error");
				cout << "sendto <<UDP>> error\n";
				continue;
			}else{
				printf("Writing to <<UDP>> %d bytes ...\n", r);
			}
		}
		if (FD_ISSET(sockfd, &readset)) {
			counter++;
			// when there are a client connect in, create a new thread to handle it
			bzero(&udp_buf, sizeof(udp_buf));
			r = recvfrom(sockfd, udp_buf, MTU, 0, (struct sockaddr *) &cli_addr, &clilen);
            // Convert the client's IP address to a string
            char clientIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(cli_addr.sin_addr), clientIP, INET_ADDRSTRLEN);
            cout << "recv client ip addr: " << clientIP << endl;
			if (r < 0) {
				// TODO: ignore some errno
				// errquit("recvfrom udp_fd error");
				cout << "recvfrom <<UDP>> error\n";
				continue;
			}else{
				cout << "read from <<UDP>> fd(client)\n";
			}
			struct iphdr* ip_header = reinterpret_cast<struct iphdr*>(udp_buf);
			bzero(&src_ip, sizeof(src_ip));
			inet_ntop(AF_INET, &(ip_header->saddr), src_ip, INET_ADDRSTRLEN);
			bzero(&dest_ip, sizeof(dest_ip));
			inet_ntop(AF_INET, &(ip_header->daddr), dest_ip, INET_ADDRSTRLEN);
			// TODO: findout packet ip and parse
            string src_ip_str(src_ip);
			int client_port = ntohs(cli_addr.sin_port);
			// cout << "cli number: " << cli_num << endl;
			// int tun_fd_cli;
			// if((tun_fd_cli = tun_alloc(tun_dev)) < 0){
			// 	errquit("tun_alloc");
			// }
            cout << "src: " << src_ip << " dest: " << dest_ip << endl;
            int is_src_serv = strncmp(src_ip, server_ip_tun, INET_ADDRSTRLEN);
            if(is_src_serv == 0){/*packet received from udp isn't possible has src ip equal to server*/
                errquit("Routing error");
            }
			auto it = ip_serial_table.find(src_ip_str);
			if (it == ip_serial_table.end()) {
                bzero(&cmd, sizeof(cmd));
                snprintf(cmd, sizeof(cmd), "ip route add %s via 172.28.28.1", src_ip);
                run(cmd);
				client_num += 1;
				unsigned int cli_tun_addr = ADDRBASE; cli_tun_addr += client_num;
				cli_tun_addr = htonl(cli_tun_addr);
				// cout << "client addr: " << cli_tun_addr << endl;
				// printf("%u.%u.%u.%u\n", NIPQUAD(cli_tun_addr)); // output to screen
				bzero(&distri_ip, sizeof(distri_ip));
				snprintf(distri_ip, sizeof(distri_ip),"%u.%u.%u.%u", NIPQUAD(cli_tun_addr)); // output to c_str
				
				// Key is not found, there are new client connect in
                string tmp_distri_ip(distri_ip);
				ip_serial_table[src_ip_str] = {tmp_distri_ip, client_port};
				ip_serial_table[tmp_distri_ip] = {src_ip_str, client_port};
				cout << "new client connect in!\n";
				/*====show server ip_serial_table====*/
				for (const auto & entry: ip_serial_table){
					cout << "ip: " << entry.first << " map_ip: " << entry.second.addr << "map_port: "<<entry.second.port <<endl;
				}
				bzero(&udp_buf, sizeof(udp_buf));
				sprintf(udp_buf, "%u\n", client_num);
				if(sendto(sockfd, udp_buf, strlen(udp_buf), 0, (struct sockaddr *) &cli_addr, clilen) < 0){
					errquit("server-handle_client net configuration send error");
				}
			}else{/*receive packet sended with ping or iperf3*/
				/*
					check if destination ip of received pkt is the same as server
					if dest_ip == server_ip_tun: write into tun interface, ping(or iperf3) will catch it
					if dest_ip == any client: write packet back to udp_socket, it will send to client auto I think?
				*/

                int is_dest_phy = strncmp(dest_ip, phy_serv_ip.c_str(), INET_ADDRSTRLEN);
				int is_dest_tun = strncmp(dest_ip, server_ip_tun, INET_ADDRSTRLEN);
                if(is_dest_phy == 0 || is_dest_tun == 0){/*dest_ip == server_ip_tun*/
                    bzero(&tun_buf, sizeof(tun_buf));
                    memcpy(tun_buf, udp_buf, r);
                    printf("Writing to <<tun>> %d bytes ...\n", r);

                    r = write(tun_fd_serv, tun_buf, r);
                    if (r < 0) {
                        // TODO: ignore some errno
                        // errquit("write tun_fd error");
                        cout << "write <<tun>> error\n";
                        continue;
                    }
			    }else{/*dest_ip is any other client*/
                    string dest_ip_str(dest_ip);
                    string dest_ip_map = ip_serial_table[dest_ip_str].addr;
					int dest_port = ip_serial_table[dest_ip_str].port;
                    cout << "dest ip map: " << dest_ip_map << endl;
					struct sockaddr_in dest_addr;
					bzero(&dest_addr, sizeof(dest_addr));
					dest_addr.sin_family = AF_INET;  // IPv4
                    // dest_addr.sin_addr.s_addr = inet_addr(dest_ip_map.c_str());
                    if(inet_pton(AF_INET, dest_ip_map.c_str(), &dest_addr.sin_addr) != 1) {
                        errquit("cannot convert IPv4 address");
                    }
                    dest_addr.sin_port = htons(dest_port);
                    
                    // struct sockaddr_in serv_addr2;
                    // bzero(&serv_addr2, sizeof(serv_addr2));
                    // serv_addr2.sin_family = AF_INET; // IPv4 
                    // serv_addr2.sin_addr.s_addr = INADDR_ANY; 
                    // serv_addr2.sin_port = htons(port);

                    memcpy(udp_sendline, udp_buf, r);
                    // int sockfd2;
                    // if ((sockfd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) errquit("server create socket");
                    // const int enable_addr = 1;
                    // if (setsockopt(sockfd2, SOL_SOCKET, SO_REUSEADDR, &enable_addr, sizeof(int)) < 0)
                    //     errquit("setsockopt(SO_REUSEADDR) failed");
                    // const int enable_port = 1;
                    // if (setsockopt(sockfd2, SOL_SOCKET, SO_REUSEPORT, &enable_port, sizeof(int)) < 0)
                    //     errquit("setsockopt(SO_REUSEPORT) failed");
                    // if(bind(sockfd2, (const struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) errquit("server bind");
                    r = sendto(sockfd, udp_sendline, r, 0, (struct sockaddr *) &dest_addr, sizeof(dest_addr));
					if (r < 0) {
						// TODO: ignore some errno
						// errquit("sendto udp_fd error");
                        errquit("sendto <<UDP>> error");
					}else{
						printf("Writing to <<UDP>> %d bytes ...\n", r);
					}
                    
                }
            }
		}
        cout << "================================\n";
		if(counter == 0){
			cout << "waiting packet...\n";
		}

	}
	return 0;
}
static int max(int a, int b) {
  return a > b ? a : b;
}
int
tunvpn_client(const char *server, int port) {
	char rcvbuf[MAXLINE];
	char sendline[MAXLINE];
	char tun_buf[MAXLINE];
	char udp_buf[MAXLINE];
    char src_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
    char server_ip[INET_ADDRSTRLEN];
	char tun_dev[20] = "tun0";
	struct hostent *host;
	// has same function as nslookup, transfer dns to ip addr
	if((host = gethostbyname(server)) == NULL){
		errquit("gethostbyname error");
	}
	// char server_ip[40] = "172.28.28.2";
	int n;
	// XXX: implement your client codes here ...
	fprintf(stderr, "## [client] starts ...\n");
	// struct sockaddr_in addr;
	struct sockaddr_in serv_addr;
	int sockfd;
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);
	serv_addr.sin_addr.s_addr = *(long *)(host->h_addr_list[0]);
	bzero(&server_ip, sizeof(server_ip));
	snprintf(server_ip, sizeof(server_ip),"%u.%u.%u.%u", NIPQUAD(serv_addr.sin_addr.s_addr)); // output to c_str
	
    if((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0){ errquit("client socket");}
	else cout << "successfully create socket\n";
	if(connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0){ errquit("client connect") } 
	else cout << "successfully connect to server\n";
	// cout << "server config complete!\n";
	// thread receive_tun(tun_from_cli, tun_fd_cli, sockfd);
	// receive_tun.detach();
	
	string client_ip = get_eth0_ip();

	// receive client number from server, tun addr = ADDRBASE+client_num
	bzero(&sendline, sizeof(sendline));
	
	// sprintf(sendline, "Hello, server");
    struct iphdr* ip_header = reinterpret_cast<struct iphdr*>(sendline);
	// Set IP header fields
    ip_header->version = 4;  // IP version
    ip_header->ihl = 5; // Header length in 32-bit words
    ip_header->tos = 0; // Type of service
    ip_header->tot_len = htons(sizeof(struct iphdr) + strlen("Hello, server")); // Total length
    ip_header->id = htons(12345); // Identification
    ip_header->frag_off = 0; // Fragment offset
    ip_header->ttl = 64; // Time to live
    ip_header->protocol = IPPROTO_UDP; // Protocol (UDP in this case)
    // ip_header->ip_sum = 0; // Checksum (set to 0 for now)
    ip_header->saddr = inet_addr(client_ip.c_str()); // Source IP address
    ip_header->daddr = serv_addr.sin_addr.s_addr; // Destination IP address
	// ip->check = in_cksum((unsigned short *)ip, sizeof(struct iphdr));

	// Payload (message to the server)
    strcpy(sendline + sizeof(struct iphdr), "Hello, Server!");
	
	// write to vpn network, so ping can catch it
	if(sendto(sockfd, sendline, sizeof(sendline), 0, (const struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0){
		errquit("client sockfd write wrong");
	}
	else{ cout << "send hello success!\n"; }
	bzero(&rcvbuf, sizeof(rcvbuf));
	if((n = recvfrom(sockfd, rcvbuf, MTU, 0, NULL, NULL)) < 0){
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
	cout << "=======client addr: " << cli_tun_addr <<"========"<< endl;
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
	// setup_route_table(client_ip);
    setup_route_table(client_ip.c_str(), server_ip, cli_num, 1);
	int r;
	// this write when server ping client 
	while(1) { 
		/*===================*/
		// cout << "in client while loop\n";
		fd_set readset;  
		FD_ZERO(&readset);
		FD_SET(tun_fd_cli, &readset);
		FD_SET(sockfd, &readset);
		int max_fd = max(tun_fd_cli, sockfd) + 1;
		// cout << "max_fd: " << max_fd << endl;
		// select block when none of fd in readset "ready"
		if (-1 == select(max_fd, &readset, NULL, NULL, NULL)) {
			// perror("select error");
			cout << "select error...\n";
			continue;
		}
		int r;
		int counter = 0;
        cout << "===========================\n";
		if (FD_ISSET(tun_fd_cli, &readset)) {
			counter++;
			r = read(tun_fd_cli, tun_buf, MTU);
			if (r < 0) {
				// TODO: ignore some errno
				// errquit("read from tun_fd error");
				cout << "read from <<tun_fd>> error\n";
				continue;
			}else{
				cout << "read from <<tun>> fd\n";
			}
            struct iphdr* ip_header = reinterpret_cast<struct iphdr*>(tun_buf);
			bzero(&src_ip, sizeof(src_ip));
			inet_ntop(AF_INET, &(ip_header->saddr), src_ip, INET_ADDRSTRLEN);
			bzero(&dest_ip, sizeof(dest_ip));
			inet_ntop(AF_INET, &(ip_header->daddr), dest_ip, INET_ADDRSTRLEN);
            cout << "src: " << src_ip << " dest: " << dest_ip << endl;
			// encrypt(tun_buf, udp_buf, r);
			memcpy(udp_buf, tun_buf, r);

			r = sendto(sockfd, udp_buf, r, 0, (const struct sockaddr *)&serv_addr, sizeof(serv_addr));
			if (r < 0) {
				// TODO: ignore some errno
				// errquit("sendto udp_fd error");
				cout << "sendto <<UDP>> error\n";
				continue;
			}else{
				printf("Writing to <<UDP>> %d bytes ...\n", r);
			}
		}
		if (FD_ISSET(sockfd, &readset)) {
			counter++;
			r = recvfrom(sockfd, udp_buf, MTU, 0, NULL, NULL);
			if (r < 0) {
				// TODO: ignore some errno
				// errquit("recvfrom udp_fd error");
				cout << "recvfrom <<UDP>> error\n";
				continue;
			}else{
				cout << "read from <<UDP>> fd\n";
			}
            struct iphdr* ip_header = reinterpret_cast<struct iphdr*>(udp_buf);
			bzero(&src_ip, sizeof(src_ip));
			inet_ntop(AF_INET, &(ip_header->saddr), src_ip, INET_ADDRSTRLEN);
			bzero(&dest_ip, sizeof(dest_ip));
			inet_ntop(AF_INET, &(ip_header->daddr), dest_ip, INET_ADDRSTRLEN);
            cout << "src: " << src_ip << " dest: " << dest_ip << endl;
			memcpy(tun_buf, udp_buf, r);

			r = write(tun_fd_cli, tun_buf, r);
			if (r < 0) {
				// TODO: ignore some errno
				// errquit("write tun_fd error");
				cout << "write <<tun_fd>> error\n";
				continue;
			}else{
				printf("Writing to <<tun>> %d bytes ...\n", r);
			}
		}
        cout << "===========================\n";
		if(counter == 0){
			cout << "waiting packet...\n";
		}
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