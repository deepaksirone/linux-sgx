#include <stdio.h>
#include <stdio.h> 
#include <netdb.h> 
#include <netinet/in.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/socket.h> 
#include <sys/types.h> 
#include <unistd.h> // read(), write(), close()
		    //
#include "network_ra.h"
#include "remote_attestation_result.h"

#include "service_provider.h"

#define MAX 80
#define PORT 7777 
#define SA struct sockaddr 

int handle(int sockfd)
{
	uint64_t request_size;
	int bytes = 0;
	do {
		bytes += read(sockfd, (void *)&request_size, sizeof(uint64_t) - bytes);
	} while (bytes < sizeof(uint64_t));

	printf("Read message size: %lu\n", request_size);
	
	char *message = (char *)malloc(request_size);
	bytes = 0;
	do {
		bytes += read(sockfd, message, request_size - bytes);
	} while (bytes < request_size);

	printf("Read message\n");

	ra_samp_response_header_t *p_resp = NULL;

	int ret = ra_network_send_receive("sampleatt.intel.com",
		(ra_samp_request_header_t *)message,
    		&p_resp);

	if (ret != 0) {
		printf("Error in ra_network_send_receive\n");
		return -1;
	}

	uint64_t response_size = sizeof(ra_samp_response_header_t) + p_resp->size;

	// Write the message size
	bytes = 0;

	do {
		bytes += write(sockfd, (void*)&response_size, sizeof(uint64_t) - bytes);
	} while (bytes < sizeof(uint64_t));

	bytes = 0;
	do {
		bytes += write(sockfd, (void*)p_resp, response_size - bytes);
	} while(bytes < response_size);

	return 0;
}

int main()
{
	printf("[info] Starting Attestation Server\n");
	int sockfd, connfd;
	unsigned int len;
	struct sockaddr_in servaddr, cli; 

	// socket create and verification 
	sockfd = socket(AF_INET, SOCK_STREAM, 0); 
	if (sockfd == -1) { 
        	printf("socket creation failed...\n"); 
        	exit(0); 
    	} 
    	else
        	printf("[info] TCP Socket Created\n");
    	bzero(&servaddr, sizeof(servaddr)); 

	// assign IP, PORT 
    	servaddr.sin_family = AF_INET; 
    	servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
    	servaddr.sin_port = htons(PORT); 
   
	// Binding newly created socket to given IP and verification 
    	if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) { 
        	printf("socket bind failed...\n"); 
        	exit(0); 
    	} 
	else
        	printf("[info] TCP socket binded to 0.0.0.0 on port: %d\n", PORT); 
   
	// Now server is ready to listen and verification 
    	if ((listen(sockfd, 5)) != 0) { 
        	printf("Listen failed...\n"); 
        	exit(0); 
    	} 
	else
        	printf("[info] Listening for connections\n"); 
	len = sizeof(cli); 

	while (1) {
		// Accept the data packet from client and verification 
		connfd = accept(sockfd, (SA*)&cli, &len); 
		if (connfd < 0) { 
        		printf("server accept failed...\n"); 
        		exit(0); 
		} 
		else
        		printf("[info] Got connection\n");

		handle(connfd);
		close(connfd);
	}
   
	return 0;
}
