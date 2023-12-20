#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/socket.h>
#define MAX 10000
#define MAXLINE 60000
const int port = 47777;

int main(int argc, char *argv[]) {
	int sockfd; 
    char buf[MAXLINE]; 
    // const char *hello = "Hello from server"; 
    struct sockaddr_in servaddr, cliaddr; 
    struct timeval timeout = {2, 0}; //set timeout for 2 seconds

    // Creating socket file descriptor 
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
        perror("socket creation failed"); 
        exit(EXIT_FAILURE); 
    } 
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(struct timeval));
       
    memset(&servaddr, 0, sizeof(servaddr)); 
    memset(&cliaddr, 0, sizeof(cliaddr)); 
       
    // Filling server information 
    servaddr.sin_family    = AF_INET; // IPv4 
    servaddr.sin_addr.s_addr = INADDR_ANY; 
    servaddr.sin_port = htons(port); 
       
    // Bind the socket with the server address 
    if ( bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0 ) { 
        perror("bind failed"); 
        exit(EXIT_FAILURE); 
    } 
    
    socklen_t len;

    while(1){
        int n; 
        int flag = 1;
        long long int startSec = 0, startUsec = 0;
        long long int endSec = 0, endUsec = 0;
        double delay = 0;
        long long int totalSize = 0;
        long long int serv_sec, serv_usec, send_sec_num, send_usec_num;
        int cnt = MAX;
        struct timeval arrival_time;
        while(cnt--){
            len = sizeof(cliaddr);
            bzero(buf, sizeof(buf));
            n = recvfrom(sockfd, (char*)buf, MAXLINE, MSG_WAITALL, (struct sockaddr*)&cliaddr, &len);
            if(n < 0) break;
            if(flag) printf("pkt series start!\n", buf);
            totalSize += n;
            buf[n] = '\0';
            // printf("Receive %d char from client\n", n, buf);
            // printf("%s\n", p);
            
            char *send_sec = strtok(buf, "\n");
			char *send_usec = strtok(NULL, "\n");
			char *payload = strtok(NULL, "\n");
            // printf("pkt flag: %c\n", payload[0]);
			long long int send_sec_num = 0, send_usec_num = 0;
			sscanf(send_sec, "%lld", &send_sec_num);
			sscanf(send_usec, "%lld", &send_usec_num);
            gettimeofday(&arrival_time, NULL);
			serv_sec = arrival_time.tv_sec;
			serv_usec = arrival_time.tv_usec;
            // printf("client time: %lld %lld\n", send_sec_num, send_usec_num);
            
            // serv_sec = (long long int)_time.tv_sec;
            // serv_usec = (long long int)_time.tv_usec;
            // if(serv_usec < send_usec_num){
            //     serv_sec--; serv_usec += 1e6;
            // }
            if(flag){
                startSec = send_sec_num;
                startUsec = send_usec_num;
                delay = (serv_sec - send_sec_num + (serv_usec - send_usec_num) / 1000000.0) * 1000.0;
                flag = 0;
            }
            // if(cnt % 1000 == 0) printf("%d ", cnt);
            // printf("%c", payload[0]);
            if(payload[0] == 'e')break;
            
        }
        endSec = serv_sec; endUsec = serv_usec; 
        // if(endUsec < startUsec){
        //     endSec--; endUsec += 1e6;
        // }
        double total_time = (endSec-startSec) + ((endUsec-startUsec) / 1e6);
        // if(endSec != serv_sec){
        //     endSec = serv_sec;
        // }else{
        //     endSec = 1;
            
        // }
        // if((endSec - startSec) < 2){
        //     endSec = startSec * 1.7;
        // }
        printf("start time: %lld, end time: %lld\n", startSec, endSec);
        double bandwidth = ((8.0 * totalSize / 1.0 / total_time) / 1000000.0);
        // printf("\n# RESULTS: delay = %.4lf ms, bandwidth = %.4lf Mbps\n", delay, bandwidth);
        
        // send result back
        if((delay - 0) > 0.001){
            bzero(buf, sizeof(buf));
            sprintf(buf, "# RESULTS: delay = %.4lf ms, bandwidth = %.4lf Mbps\n", delay, bandwidth);
            if(sendto(sockfd, buf, sizeof(buf), 0, (struct sockaddr *) &cliaddr, sizeof(cliaddr)) == -1){
                perror("sending");
                exit(EXIT_FAILURE);
            } else {
                printf("send result back to client\n");
                // if(cnt % 1000 == 0) printf("%d\n", cnt);
                // printf("%d\n", cnt);
                // printf("%s\nsent\n", sendData);
            }
        }
    }

  	
   
	// while(cnt--){
    //     // printf("%d ", cnt);
		
    //     // if(cnt % 1000 == 0){
    //     //     printf("\nserver time: %lld %lld\n", (long long int)_time.tv_sec, (long long int)_time.tv_usec);
    //     //     printf("latency: %llds %lldµs\n", serv_sec - send_sec_num, serv_usec - send_usec_num);
    //     //     printf("============================================================\n");
    //     // }
    //     if(cnt == 0){
    //         endSec = serv_sec;
    //         printf("totalSize: %lld\tstartSec: %lld\tendSec: %lld\n", totalSize, startSec, endSec);
    //         printf("throughput: %lf bits/sec\n", 8.0 * totalSize / 1.0 / (endSec - startSec));
    //         fflush(stdout);
    //         totalSize = 0;
    //         endSec = startSec = 0;
    //         flag = 1;
    //         cnt = MAX;
    //     }
	// }
    

    // len = sizeof(cliaddr);  //len is value/result 
   
    // n = recvfrom(sockfd, (char *)buf, MAXLINE,  
    //             MSG_WAITALL, ( struct sockaddr *) &cliaddr, 
    //             &len); 
    // buf[n] = '\0'; 
    // printf("Client : %s\n", buf); 
    // sendto(sockfd, (const char *)hello, strlen(hello),  
    //     MSG_CONFIRM, (const struct sockaddr *) &cliaddr, 
    //         len); }
	return 0;
}