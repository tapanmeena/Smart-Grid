#define _GNU_SOURCE
#include <stdio.h> 
#include <strings.h> 
#include <sys/types.h> 
#include <arpa/inet.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <math.h>
#include "kdc.h"

#define PORT 5000 
#define MAXLINE 1000 

lli compute_public_values(int g, int a, int p)
{
	return (((lli)pow(g, a)) % p);
}

lli compute_shared_key(lli received_value, int a, int p)
{
	return (((lli)pow(received_value, a)) % p);
}


int main()
{
	while(1)
	{
		lli public_value = compute_public_values(G, privateKey, P);
		printf("Calculated Public Value at KDC : %lld\n",public_value);

		char buffer[100]; 
		char message[MAXLINE];
		snprintf (message, sizeof(message), "%lld",public_value); // print int 'n' into the char[] buffer

		// char *message = "Hello Client"; 
		int listenfd, len; 
		struct sockaddr_in servaddr, cliaddr; 
		bzero(&servaddr, sizeof(servaddr));

		// Create a UDP Socket 
		listenfd = socket(AF_INET, SOCK_DGRAM, 0);		 
		servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
		servaddr.sin_port = htons(PORT); 
		servaddr.sin_family = AF_INET; 

		// bind server address to socket descriptor 
		bind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr)); 
		
		//receive the datagram 
		len = sizeof(cliaddr); 
		int n = recvfrom(listenfd, buffer, sizeof(buffer), 
				0, (struct sockaddr*)&cliaddr,&len); //receive message from server 
		buffer[n] = '\0';
		// puts(buffer);
		char *ip = inet_ntoa(cliaddr.sin_addr);
		printf("Received Public Value : %s from %s\n", buffer, ip);
		// send the response 
		sendto(listenfd, message, MAXLINE, 0,
			(struct sockaddr*)&cliaddr, sizeof(cliaddr)); 

		printf("#### Calculating Shared Key ####\n");

		sscanf(buffer, "%lld", &shared_key); // Using sscanf
		shared_key = compute_shared_key(shared_key, privateKey, P);
		printf("Shared Key is : %lld\n",shared_key);
		close(listenfd); 
	}
} 
