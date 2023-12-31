#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define errquit(m)	{ perror(m); exit(-1); }

int main(int argc, char *argv[]) {
	int s;
	struct sockaddr_in sin;

	if((s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) errquit("socket");

	do {
		int v = 1;
		setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v));
	} while(0);

	bzero(&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(80);
	if(bind(s, (struct sockaddr*) &sin, sizeof(sin)) < 0) errquit("bind");
	if(listen(s, SOMAXCONN) < 0) errquit("listen");
	// the while-loop is used for waiting client
	do {
		// c is socket
		int c;
		FILE *fp;
		struct sockaddr_in csin;
		char buf[4096];
		socklen_t csinlen = sizeof(csin);

		if((c = accept(s, (struct sockaddr*) &csin, &csinlen)) < 0) {
			perror("accept");
			continue;
		}
		if((fp = fdopen(c, "r+")) == NULL){
			perror("fdopen");
			close(c);
			continue;
		} 
		// setbuffer to the mode fgets accept
		// disable buffering, real-time react to I/O 
		// setbuf(fp, NULL, _IONBF, 0);

		while(fgets(buf, sizeof(buf), fp) != NULL){
			fprintf(fp, "xxx:%s", buf);
		}
	
		close(c);
	} while(1);

	return 0;
}