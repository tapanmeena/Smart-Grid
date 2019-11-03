#define _GNU_SOURCE
#include <stdio.h> 
#include <string.h> 
#include <sys/types.h> 
#include <arpa/inet.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <unistd.h> 
#include <stdlib.h> 
#include <math.h>
#include <openssl/md5.h>

#define caPORT 9999 
#define MAXLINE 1000

struct X509CERT
{
	int version;
	int certificateSerial;
	char *issuer_name;
	int validity_period;
	char *subject_name;
	char *public_key;
	char *issuer_unique_identifier;
	unsigned char digital_signature[MD5_DIGEST_LENGTH];
};
	
int main() 
{
	struct X509CERT certificate;
	certificate.version = 1;
	certificate.certificateSerial = 4;
	certificate.issuer_name = "tapan";
	certificate.validity_period = 513;
	certificate.subject_name = "someSubject";
	certificate.public_key = "3";
/*
	char message[MAXLINE];
	snprintf(message, sizeof(message), "%d,%d,%s,%d,%s,%s", certificate.version, certificate.certificateSerial,certificate.issuer_name, certificate.validity_period, certificate.subject_name, certificate.public_key);
	
	// message[0] = certificate.version - '0';
	// snprintf(message + 0, MAXLINE, "%s%d", message,certificate.version, certificate.issuer_name);
	printf("(%s)\n", message);
	unsigned char result[MD5_DIGEST_LENGTH];
	MD5(message, strlen(message), result);

	for(int i=0; i<MD5_DIGEST_LENGTH*2; i++)
		printf("%02x", result[i]);
*/
	int sockfd, n; 
	struct sockaddr_in servaddr; 

	// clear servaddr
	bzero(&servaddr, sizeof(servaddr)); 
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
	servaddr.sin_port = htons(caPORT); 
	servaddr.sin_family = AF_INET; 

	// create datagram socket 
	sockfd = socket(AF_INET, SOCK_DGRAM, 0); 

	// connect to server 
	if(connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) 
	{ 
		printf("\n Error : Connect Failed \n"); 
		exit(0); 
	} 

	char message[MAXLINE];
	snprintf (message, sizeof(message), "%s","Create"); // print int 'n' into the char[] buffer
	sendto(sockfd, message, MAXLINE, 0, (struct sockaddr*)NULL, sizeof(servaddr)); 
	// printf("After message send");

	//for sending certificate for creation
	{
		memset(message, '\0', sizeof message);
		snprintf(message, sizeof(message), "%d,%d,%s,%d,%s,%s", certificate.version, certificate.certificateSerial,certificate.issuer_name, certificate.validity_period, certificate.subject_name, certificate.public_key);
		sendto(sockfd, message, MAXLINE, 0, (struct sockaddr*)NULL, sizeof(servaddr));
/*		sendto(sockfd, &certificate.version, sizeof(certificate.version), 0, (struct sockaddr*)NULL, sizeof(servaddr)); 
		sendto(sockfd, &certificate.certificateSerial, sizeof(certificate.certificateSerial), 0, (struct sockaddr*)NULL, sizeof(servaddr)); 
		// message = certificate.issuer_name;
		sendto(sockfd, certificate.issuer_name, sizeof(char *), 0, (struct sockaddr*)NULL, sizeof(servaddr)); 
		sendto(sockfd, &certificate.validity_period, sizeof(certificate.validity_period), 0, (struct sockaddr*)NULL, sizeof(servaddr)); 
		sendto(sockfd, certificate.subject_name, sizeof(char *), 0, (struct sockaddr*)NULL, sizeof(servaddr)); 
		sendto(sockfd, certificate.public_key, sizeof(char *), 0, (struct sockaddr*)NULL, sizeof(servaddr)); */

		unsigned char computedHash[MD5_DIGEST_LENGTH];
		int n = recvfrom(sockfd, computedHash, sizeof(computedHash), 0, (struct sockaddr*)NULL, NULL); 
		computedHash[n] = '\0';
		for(int i=0;;i++)
		{
			if(computedHash[i] == '\0')
				break;
			printf("%02x",computedHash[i]);
			certificate.digital_signature[i] = computedHash[i];
		}
		printf("\n");
	}
	memset(message, '\0', sizeof message);
	snprintf (message, sizeof(message), "%s","Verify"); // print int 'n' into the char[] buffer
	sendto(sockfd, message, MAXLINE, 0, (struct sockaddr*)NULL, sizeof(servaddr)); 
	//for certificate verification
	{
		memset(message, '\0', sizeof message);
		snprintf(message, sizeof(message), "%d,%d,%s,%d,%s,%s", certificate.version, certificate.certificateSerial,certificate.issuer_name, certificate.validity_period, certificate.subject_name, certificate.public_key);
		sendto(sockfd, message, MAXLINE, 0, (struct sockaddr*)NULL, sizeof(servaddr));
		sendto(sockfd, certificate.digital_signature, sizeof(certificate.digital_signature), 0, (struct sockaddr*)NULL, sizeof(servaddr));
	}
	close(sockfd);
} 
