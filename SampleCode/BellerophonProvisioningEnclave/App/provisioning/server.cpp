#include <iostream>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "server.h"


int connect_to_server(char *server_address, int server_port) {

	int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
	if (clientSocket == -1) {
		std::cerr << "Error creating socket" << std::endl;
		return -1;
	}

	sockaddr_in serverAddress;
    	serverAddress.sin_family = AF_INET;
    	serverAddress.sin_port = htons(server_port); // Replace with your server's port
    	if (inet_pton(AF_INET, server_address, &serverAddress.sin_addr) <= 0) { // Replace with your server's IP address
        	std::cerr << "Invalid address/ Address not supported" << std::endl;
        	close(clientSocket);
        	return -2;
    	}

	if (connect(clientSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) == -1) {
        	std::cerr << "Error connecting to server" << std::endl;
        	close(clientSocket);
        	return -3;
	}

	return clientSocket;
}
