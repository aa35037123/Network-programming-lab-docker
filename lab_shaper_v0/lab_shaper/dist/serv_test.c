#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>

#define errquit(m)	{ perror(m); exit(-1); }
#define MAXLINE 60000
#define PKTNUM 30000

const int SERV_PORT = 80;
void error(char *msg) {
  perror(msg);
  exit(1);
}
int main(int argc, char *argv[]) {
	int sockfd;
	long long int n;
	struct sockaddr_in server_addr, client_addr;
	struct timeval timeout = {2, 0}; 
	socklen_t client_len = sizeof(client_addr);
	char buf[MAXLINE];
	if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) errquit("socket");
	// SO_RCVTIMEO determines maximum time a recv call will block waiting to receive data.
	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(struct timeval));

	bzero(&server_addr, sizeof(server_addr));
	server_addr.sin_family      = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port        = htons(SERV_PORT);

	if(bind(sockfd, (struct sockaddr*) &server_addr, sizeof(server_addr)) < 0) errquit("bind");
	// the while-loop is used for waiting client
	do {
		int flag = 1;
		long long int start_sec = 0;
		long long int end_sec = 0;
		long long int total_size = 0;
		long long int serv_sec = 0, serv_usec = 0;
		int counter = PKTNUM;
		double latency = 0;
		double bandwidth = 0;
		struct timeval arrival_time;
		while(counter --){
			bzero(buf, MAXLINE);
			// printf("before recv\n");
			n = recvfrom(sockfd, buf, MAXLINE, MSG_WAITALL, 
								(struct sockaddr *)&client_addr, &client_len);
			if(n < 0) break;
			gettimeofday(&arrival_time, NULL);
			total_size += n;
			buf[n] = '\0';
			char *send_sec = strtok(buf, "\n");
			char *send_usec = strtok(NULL, "\n");
			char *payload = strtok(NULL, "\n");
			printf("pkt flag: %c\n", payload[0]);
			long long int send_sec_num = 0, send_usec_num = 0;
			sscanf(send_sec, "%lld", &send_sec_num);
			sscanf(send_usec, "%lld", &send_usec_num);
			serv_sec = arrival_time.tv_sec;
			serv_usec = arrival_time.tv_usec;
			if(serv_usec < send_usec_num){
                serv_sec--; serv_usec += 1e6;
            }
			if(flag){
				latency = ((serv_sec - send_sec_num) + (serv_usec-send_usec_num)/1000000.0)*1000.0;
				flag = 0;
				printf("start!\n");
				start_sec = send_sec_num;
			}
			if(payload[0] == 'e'){
				end_sec = serv_sec;
				printf("end!\n");
				break;
			}
		}
		// set this restrict is because the recv timeout sockopt
		// if timeout, end_sec and start_sec will not be assigned, which lead to error   
		if(latency > 0.00001){
			printf("start sec: %lld, end sec: %lld\n", start_sec, end_sec);
			// printf("total_size")
			bandwidth = (total_size * 8 / (end_sec - start_sec)) / 1000000.0; 
			printf("# RESULTS: delay = {%.3lf} ms, bandwidth = {%.3lf} Mbps\n", latency, bandwidth);
			sprintf(buf, "has receive your data!\n");
			// Null-terminate the received data to print it as a string
			n = sendto(sockfd, buf, sizeof(buf), 0, (struct sockaddr*)&client_addr, client_len);
			if(n < 0){
				perror("Send failed");
				continue;  // Continue to the next iteration
			}
		
		}


		
		// if(n < 0){
		// 	perror("Receive failed");
        //     continue;  // Continue to the next iteration
		// }
		// gettimeofday(&arrive_time, NULL); // get current time
		// // float arrive_sec = arrive_time.tv_sec;
		// // printf("get message: %s\n", buf);
        // char time_str[30];
        // sprintf(time_str, "%ld.%6ld", arrive_time.tv_sec, arrive_time.tv_usec);
		// // Concatenate time_str with the received buffer
		// strncpy(buf, time_str, sizeof(buf)-1); // -1: leave room for null of buf

	} while(1);
	close(sockfd);
	return 0;
}
