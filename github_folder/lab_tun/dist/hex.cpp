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
#include <sstream>
#include <cmath>
#include <string>

using namespace std;
#define NIPQUAD(m)	((unsigned char*) &(m))[0], ((unsigned char*) &(m))[1], ((unsigned char*) &(m))[2], ((unsigned char*) &(m))[3]
#define errquit(m)	{ perror(m); exit(-1); }
#define MYADDR		0x0a0000fe // 10.0.0.254

int main(){
    unsigned int addr = MYADDR;
    addr = htonl(addr);
    cout << "server addr: " << addr << endl;
	printf("%u.%u.%u.%u\n", NIPQUAD(addr));
}