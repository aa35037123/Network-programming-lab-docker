#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>

#define MAXLINE 60000
#define PKTNUM 10000
const char* SERVER_IP = "127.0.0.1";
const int PORT = 47777;
// client send extreme large buffer to server
// after server get client packet, server send pkt contain time to client   
int main() {
    int sockfd;
    struct sockaddr_in server_addr;
    socklen_t server_len = sizeof(server_addr);
    char buf[MAXLINE];
	int n = 0;
    long long int send_byte = 0;
	struct timeval send_time;
    // float latency = 0;
    // float bandwidth = 0;
    // float latency;
    bzero(&server_addr, sizeof(server_addr));
    // Set up server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT); // Use any available port
    // int inet_pton(int af, const char *src, void *dst);
	if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        perror("Error converting IP address");
        exit(EXIT_FAILURE);
    }
    // Create socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }
    // if(connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0){
    //     perror("connection"); 
    //     exit(EXIT_FAILURE); 
    // }
    int counter = PKTNUM;
    // packet content
    // sec
    // usec
    // 111111111......
    // printf("====send====\n");
    while(counter --){ /*after condition evaluate, the counter minus 1 */

        // Send data to the server (replace this with your actual data)

        gettimeofday(&send_time, NULL); // get current time
        sprintf(buf, "%lld\n%lld\n", (long long int)send_time.tv_sec, (long long int)send_time.tv_usec);
		int len = strlen(buf);
        if(counter == PKTNUM - 1){
            buf[len] = 's'; // means start
        }
        else if(counter == 0){
            // printf("client send end!\n");
            buf[len] = 'e'; // means end
        }
        else{
            buf[len] = 'x';    
        }

        // for(int i = len+1; i < MAXLINE-1 && counter != PKTNUM-1; i++){
        //     buf[i] = '1';
        // }
        // if(counter == PKTNUM-1){
        //     buf[strlen(buf)] = '\0';
        // }
        // else{
        //     buf[MAXLINE-1] = '\0';
        // }
       
        for(int i = len+1; i < MAXLINE-1 ; i++){
            buf[i] = '1';
        }
        buf[MAXLINE-1] = '\0';
        // if(counter == PKTNUM-1){
        //     buf[strlen(buf)] = '\0';
        // }
        // else{
        //     buf[MAXLINE-1] = '\0';
        // }

        // Concatenate time_str with the received buffer
        // printf("====send====\nbuffer flag: %c\n", buf[len]);
        send_byte = sendto(sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
        // printf("send %lld byte to server\n", send_byte);
        if(send_byte < 0){
                perror("send failed");
                close(sockfd);
                return 0;
        }
    }
    bzero(&buf, sizeof(buf));
    // Receive data from the server (replace this with your actual data)
    // printf("====receive====\n");
    // MSG_WAITALL: wait for all MAX_BUF_SIZE bytes arrive
    n = recvfrom(sockfd, buf, MAXLINE, MSG_WAITALL, (struct sockaddr *) &server_addr, &server_len);
    if(n < 0){
            perror("receive failed");
            close(sockfd);
            return 0;
    }
    buf[n] = '\0';
    printf("%s", buf);
    // int arrive_sec = 0, arrive_usec = 0;
    // sscanf(buf, "%d.%6d", &arrive_sec, &arrive_usec);
    // // time 1000 to transfer sec to msec
    // latency = ((arrive_sec - send_time.tv_sec) + (arrive_usec-send_time.tv_usec)/1000000.0)*1000.0;
    // bandwidth = (send_byte * 8 / (latency / 1000)) / 1000000.0; 
    // printf("# RESULTS: delay = {%.3f} ms, bandwidth = {%.3f} Mbps\n", latency, bandwidth);
    // Close the socket
    close(sockfd);

    return 0;
}
