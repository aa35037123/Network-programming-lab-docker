#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <regex.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define errquit(m)	{ perror(m); exit(-1); }
#define MAXLINE 1500000
#define DMAXLINE 3000000

static int port_http = 80;
static int port_https = 443;
static const char *docroot = "/html";

const char *get_file_extension(const char *filename) {
	// strrchr: search for the last time '.' appear
    const char *dot = strrchr(filename, '.');
	// Check if there is no dot in the file_name or if it is the first character.
    if (!dot || dot == filename) {
        // If there is no dot or it's the first character, there's no extension.
		return "";
    }
	// Return the portion of the file_name after the dot (the file extension).
    return dot + 1;
}

char *url_decode(const char *src){
	size_t src_len = strlen(src);
	char *decoded = malloc(src_len + 1);
	size_t decoded_len = 0;
	for(size_t i = 0; i < src_len; i++){
		// %: an escape character to represent special characters using a hexadecimal encoding 
		// ex: Original: Hello World -> Encoded: Hello%20World
		// i + 2: check that two chars after i is still in range of src_len
		if(src[i] == '%' && i + 2 < src_len){
			int hex_val;
			sscanf(src + i + 1, "%2x", &hex_val);
			decoded[decoded_len++] = hex_val;
		}
		else{
			decoded[decoded_len++] = src[i];
		}
	}	
	// add null terminator
    decoded[decoded_len] = '\0';
	return decoded;
}

const char *get_mime_type(const char *file_extension){
	// + '/' because we need to add the tailing slash
	// strcasecmp: if two string are equal, ignore case
	if (strcasecmp(file_extension, "html/") == 0 || strcasecmp(file_extension, "htm/") == 0) {
        return "text/html";
    } else if (strcasecmp(file_extension, "txt/") == 0) {
        return "text/plain";
    } else if (strcasecmp(file_extension, "jpg/") == 0 || strcasecmp(file_extension, "jpeg/") == 0) {
        return "image/jpeg";
    } else if (strcasecmp(file_extension, "png/") == 0) {
        return "image/png";
    } else if(strcasecmp(file_extension, "mp3/") == 0){
		return "audio/mpeg";
	}
	else {
        return "application/octet-stream";
    }
}
void removeFirstChar(char *str) {
	int len = strlen(str);
    // Check if the string is not empty
	for(int i = 0; i < len-1; i++){
		str[i] = str[i+1];
	}
	str[len-1] = '\0';
    // if (str != NULL && str[0] != '\0') {
    //     // Shift all characters to the left by one position
    //     memmove(str, str + 1, strlen(str));
    // }
	// str[len-1] = '\0';
}
void build_http_response(const char *filename, const char *file_extension, 
						char *response, size_t *response_len, int connfd) {
	
	
	char buf[MAXLINE];
	bzero(&buf, sizeof(buf));
	// snprintf(buf, MAXLINE,"hello");
	snprintf(buf, MAXLINE,"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n");
	send(connfd, buf, strlen(buf), 0);
	
	// build HTTP header
    const char *mime_type = get_mime_type(file_extension);

	// this is header
	
	// int file_fd = open(filename, O_RDONLY);/*O_RDONLY: open with read only*/
	
	// /*can not open file*/
	// if(file_fd == -1){
	// 	// snprintf(response, MAXLINE, "HTTP/1.0 404 Not Found\r\nContent-Type: text/plain\r\n\r\n404 Not Found");
    //     // *response_len = strlen(response);
    //     snprintf(send_line, MAXLINE, "HTTP/1.0 404 Not Found\r\nContent-Type: text/plain\r\n\r\n404 Not Found");
	// 	send(*connfd, send_line, strlen(send_line), 0);
	// 	return;
	// }
	// snprintf(send_line, MAXLINE,"HTTP/1.0 200 OK\r\nContent-Type: %s\r\n\r\n",
    //          mime_type);
	// send(*connfd, send_line, strlen(send_line), 0);
	// // // get file size for Content-Length	
    // // struct stat file_stat;
    // // fstat(file_fd, &file_stat);
    // // off_t file_size = file_stat.st_size;
	// ssize_t bytes_read;
	// // response is a pointer point to start of string
	// // so "response + *response_len" can read data after header 
	// while((bytes_read = read(file_fd, send_line, MAXLINE))>0){
	// 	send(*connfd, send_line, strlen(send_line), 0);
	// }
	// // *response_len = 0;
	// // memcpy(response, send_line, strlen(send_line));
	// // *response_len += strlen(send_line);
	// // ssize_t bytes_read;
	// // // response is a pointer point to start of string
	// // // so "response + *response_len" can read data after header 
	// // while((bytes_read = read(file_fd, response + *response_len, 
	// // 		MAXLINE-*response_len))>0){
	// // 	*response_len += bytes_read;
	// // }
	// close(file_fd);
}

void *handle_client(void *arg){
	int connfd = *(int*)arg;
	char buf[MAXLINE];
	char send_line[DMAXLINE];
	char file_extension[1024];
	// receive request data from client and store into buffer
    ssize_t bytes_received = recv(connfd, buf, MAXLINE, 0);
	// ssize_t bytes_received = read(connfd, buf, MAXLINE);
	if (bytes_received > 0){
		// bzero(&buf, sizeof(buf));
		// snprintf(buf, MAXLINE,"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nhello\n");
		// send(connfd, buf, strlen(buf), 0);
		// bzero(&send_line, sizeof(send_line));
		// snprintf(send_line, DMAXLINE,"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n%s\n", buf);
		// send(connfd, send_line, strlen(send_line), 0);
		

		char *request = url_decode(buf);
		// bzero(&send_line, sizeof(send_line));
		// snprintf(send_line, DMAXLINE,"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nrequest:%s\n", request);
		// send(connfd, send_line, strlen(send_line), 0);
		char *method = strtok(request, " ");
				

		char *path = strtok(NULL, " ");
		char *protocol = strtok(NULL, " ");
		
		// bzero(&send_line, sizeof(send_line));
		// snprintf(send_line, MAXLINE*2,"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\rmethod:%s\n", method);
		// send(connfd, send_line, strlen(send_line), 0);
		// bzero(&send_line, sizeof(send_line));
		// snprintf(send_line, MAXLINE*2,"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\rpath:%s\n", path);
		// send(connfd, send_line, strlen(send_line), 0);
		// bzero(&send_line, sizeof(send_line));
		// snprintf(send_line, MAXLINE*2,"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\rprotocol:%s\n", protocol);
		// send(connfd, send_line, strlen(send_line), 0);

		// // if method is not "GET", return 0
		if(strcmp(method, "GET") != 0){
			close(connfd);
			return NULL;
		}
		// if path is root, then redirect it to index.html
		if(strcmp(path, "/") == 0){
			// char file_extension[32];
			strcpy(path, "/index.html/");	
		}
		
		int path_len = strlen(path);
		// if path is not end with '/', return 301 status code
		
		if(path[path_len-1] != '/'){
			path[path_len] = '/';
			path[path_len+1] = '\0';
			// write 301 code
		}
		/*remove first '/' char from path*/

		strcpy(file_extension, get_file_extension(path));
		// removeFirstChar(path);
		char *file_path = strtok(path, "/");
		// bzero(&send_line, sizeof(send_line));
		// snprintf(send_line, MAXLINE*2,"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nnew_path:%s\n", file_path);
		// // snprintf(send_line, MAXLINE*2,"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r");
		// send(connfd, send_line, strlen(send_line), 0);
		
		// send(connfd, buf, sizeof(buf), 0);
		// regex_t regex;
		// regcomp(&regex, "^GET (/[^ ]*) HTTP/1.0", REG_EXTENDED);
		// // index0: whole match string
		// // index1: first matching group
		// regmatch_t matches[2];
		// // check if buf match the pattern of regex
		// if(regexec(&regex, buf, 2, matches, 0) == 0){
			// rm_eo: regex match end offset
			// buf[matches[1].rm_eo] = '\0';
			// buf is end at index matches[1].rm_eo
			// const char *url_encode_filename = buf + matches[1].rm_so;// start offset
			
		// check for filename is end with "/"

			/*add root of web in front of every path */
            // Construct the full path by appending the requested filename to the document root
            // filename has the form: /.../...
			// snprintf(full_path, MAXLINE, "%s%s", docroot, filename);
		char response[DMAXLINE];
		size_t response_len;
		
		// build_http_response(file_path, file_extension, response, &response_len, connfd);
		// build HTTP header
    	const char *mime_type = get_mime_type(file_extension);
		// bzero(&send_line, sizeof(send_line));
		// snprintf(send_line, MAXLINE,"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n%s\n", mime_type);
		// // snprintf(send_line, MAXLINE*2,"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r");
		// send(connfd, send_line, strlen(send_line), 0);
		int file_fd = open(file_path, O_RDONLY);/*O_RDONLY: open with read only*/
	
		/*can not open file*/
		if(file_fd == -1){
			// snprintf(response, MAXLINE, "HTTP/1.0 404 Not Found\r\nContent-Type: text/plain\r\n\r\n404 Not Found");
			// *response_len = strlen(response);
			bzero(&send_line, sizeof(send_line));
			snprintf(send_line, MAXLINE, "HTTP/1.0 404 Not Found\r\nContent-Type: text/plain\r\n\r\n404 Not Found");
			send(connfd, send_line, strlen(send_line), 0);
			return;
		}
		bzero(&send_line, sizeof(send_line));
		snprintf(send_line, MAXLINE,"HTTP/1.0 200 OK\r\nContent-Type: %s\r\n\r\n",
				mime_type);
		send(connfd, send_line, strlen(send_line), 0);
		// // get file size for Content-Length	
		// struct stat file_stat;
		// fstat(file_fd, &file_stat);
		// off_t file_size = file_stat.st_size;
		ssize_t bytes_read;
		// response is a pointer point to start of string
		// so "response + *response_len" can read data after header 
		bzero(&send_line, sizeof(send_line));
		while((bytes_read = read(file_fd, send_line, MAXLINE))>0){
			send(connfd, send_line, strlen(send_line), 0);
			bzero(&send_line, sizeof(send_line));
		}
		close(file_fd);
		// send HTTP response to client
		// send(connfd, response, response_len, 0);
		free(request);
		
	}
	close(connfd);
	free(arg); /*arg is the int pointer of connfd */
	return NULL;
}
int main(int argc, char *argv[]) {
	int listenfd;
	struct sockaddr_in sin;
	pid_t				childpid;

	if(argc > 1) {
		port_http  = strtol(argv[1], NULL, 0); 
	}
	if(argc > 2) { 
		if((docroot = strdup(argv[2])) == NULL) errquit("strdup"); 
	}
	if(argc > 3) { 
		port_https = strtol(argv[3], NULL, 0); 
	}
	 /* 使用 /html 當網站根目錄 */
    if(chdir(docroot) == -1){ 
        printf("ERROR: Can't Change to directory %s\n",docroot);
        exit(-1);
    }

	if((listenfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) errquit("socket");

	do {
		int v = 1;
		setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v));
	} while(0);

	bzero(&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port_http);
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	if(bind(listenfd, (struct sockaddr*) &sin, sizeof(sin)) < 0) errquit("bind");
	if(listen(listenfd, SOMAXCONN) < 0) errquit("listen");
	
	do {
		int *connfd = malloc(sizeof(int));
		struct sockaddr_in csin;
		socklen_t csinlen = sizeof(csin);
		FILE *fp;
		// char buf[4096];
		/*wait for client connect*/
		if((*connfd= accept(listenfd, (struct sockaddr*) &csin, &csinlen)) < 0) {
			perror("accept");
			continue;
		}
		pthread_t thread_id;
		pthread_create(&thread_id, NULL, handle_client, (void *)connfd);
		//  detach thread: system releasing the resources associated with the thread once it finishes its execution. 
		pthread_detach(thread_id);
		// if((fp = fdopen(*connfd, "r+")) == NULL){
		// 	perror("fdopen");
		// 	close(connfd);
		// 	continue;
		// } 
		// if((childpid = fork()) == 0){
		// 	close(listenfd); /*closing listening socket*/
		// 	while(fgets(buf, sizeof(buf), fp) != NULL){/*read until reach EOF*/
		// 		fprintf(fp, "xxx%s\n", buf);
		// 	}
		// }
		
	} while(1);
	close(listenfd);
	return 0;
}
