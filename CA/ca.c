#define _GNU_SOURCE
#include <openssl/md5.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include <stdlib.h>
#include <memory.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <stdarg.h>
/* the next two includes probably aren't relevant for you, but I typically use them all anyway */
#include <math.h>
#include <sys/termios.h>

#define lli long long int
// #define kdcPort 5000
#define MAXLINE 1000
#define caPORT 9999 

const char *string = "The quick brown fox jumped over the lazy dog's back";

struct X509CERT
{
	int version;
	int certificateSerial;
	char *issuer_name;
	int validity_period;
	char *subject_name;
	char *public_key;
	char *issuer_unique_identifier;
	char *digital_signature;
};

struct X509CERT **certificate;

void requestCertificate(struct sockaddr_in servaddr, int listenfd, struct sockaddr_in cliaddr, int len)
{
/*	// char mes
	// struct X509CERT certificate;
	int n = recvfrom(listenfd, &certificate.version, sizeof(certificate.version), 
			0, (struct sockaddr*)&cliaddr,&len); //receive message from server
	// printf("ID %d\n", certificate.version);
	
	n = recvfrom(listenfd, &certificate.certificateSerial, sizeof(certificate.certificateSerial), 
		0, (struct sockaddr*)&cliaddr,&len); //receive message from server
	// printf("Certificate Serial %d\n", certificate.certificateSerial);
	
	char issuer[MAXLINE];
	n = recvfrom(listenfd, issuer, MAXLINE, 
		0, (struct sockaddr*)&cliaddr,&len); //receive message from server
	issuer[n] = '\0';
	certificate.issuer_name = issuer;
	// printf("Issuer %s\n", certificate.issuer_name);
	
	n = recvfrom(listenfd, &certificate.validity_period, sizeof(certificate.certificateSerial), 
		0, (struct sockaddr*)&cliaddr,&len); //receive message from server
	// printf("Validity %d\n", certificate.validity_period);
	
	char subject[MAXLINE];
	n = recvfrom(listenfd, subject, MAXLINE, 
		0, (struct sockaddr*)&cliaddr,&len); //receive message from server
	subject[n] = '\0';
	certificate.subject_name = subject;
	// printf("Subject %s\n", certificate.subject_name);
	
	char pkey[MAXLINE];
	n = recvfrom(listenfd, pkey, MAXLINE, 
		0, (struct sockaddr*)&cliaddr,&len); //receive message from server
	pkey[n] = '\0';
	certificate.public_key = pkey;
	// printf("Public Key %s\n", certificate.public_key);

	char message[MAXLINE];
	snprintf(message, sizeof(message), "%d,%d,%s,%d,%s,%s", certificate.version, certificate.certificateSerial,certificate.issuer_name, certificate.validity_period, certificate.subject_name, certificate.public_key);
	// snprintf(message, sizeof(message), "%d,%d,%s,%d,%s,%s", certificate.version, certificate.certificateSerial,certificate.issuer_name, certificate.validity_period, certificate.subject_name, certificate.public_key);
	
	// message[0] = certificate.version - '0';
	// snprintf(message + 0, MAXLINE, "%s%d", message,certificate.version, certificate.issuer_name);
	printf("%s\n", message);
*/
	char message[MAXLINE];
	int n = recvfrom(listenfd, message, MAXLINE, 
			0, (struct sockaddr*)&cliaddr,&len); //receive message from server
	message[n] = '\0';
	printf("Cert:->%s<-\n", message);

	unsigned char digitalSignature[MD5_DIGEST_LENGTH];
	MD5(message, sizeof(message), digitalSignature);
	for(int i=0;i<MD5_DIGEST_LENGTH;i++)
	{
		printf("%02x", digitalSignature[i]);
	}
	printf("\n");

	sendto(listenfd, digitalSignature, sizeof(digitalSignature), 0, (struct sockaddr* )&cliaddr, sizeof(cliaddr));
}

void verifyCertificate(struct X509CERT certificate, struct sockaddr_in servaddr, int listenfd, struct sockaddr_in cliaddr, int len)
{
	printf("Inside Verify Certificate\n");
	char message[MAXLINE];
	int n = recvfrom(listenfd, message, MAXLINE, 
			0, (struct sockaddr*)&cliaddr,&len); //receive message from server
	message[n] = '\0';
	printf("Cert:->%s<-\n", message);

	unsigned char digitalSignature[MD5_DIGEST_LENGTH];
	n = recvfrom(listenfd, digitalSignature, sizeof(digitalSignature), 0, (struct sockaddr*)&cliaddr, &len); 
	digitalSignature[n] = '\0';
	for(int i=0;;i++)
	{
		if(digitalSignature[i] == '\0')
			break;
		printf("%02x",digitalSignature[i]);
	}
	printf("\n");

	unsigned char computedDigitalSignature[MD5_DIGEST_LENGTH];
	MD5(message, sizeof(message), computedDigitalSignature);
	for(int i=0;i<MD5_DIGEST_LENGTH;i++)
	{
		printf("%02x", computedDigitalSignature[i]);
	}
	printf("\n");
	int match = 1;
	for(int i=0;i<MD5_DIGEST_LENGTH; i++)
	{
		if(computedDigitalSignature[i] == digitalSignature[i])
			continue;
		else
		{
			printf("%02x %02x\n",computedDigitalSignature[i],digitalSignature[i]);
			printf("Digital Signature doesn't Match\n");
			match = 0;
			break;
		}
	}
	if(match)
		printf("Digital Signature Matched\n");
}
void requestHandler_thread()
{
	// char mes
	int listenfd, len;
	struct sockaddr_in servaddr, cliaddr;
	bzero(&servaddr, sizeof(servaddr));

	// Create a UDP Socket 
	listenfd = socket(AF_INET, SOCK_DGRAM, 0);		 
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
	servaddr.sin_port = htons(caPORT); 
	servaddr.sin_family = AF_INET; 

	// bind server address to socket descriptor 
	bind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr)); 

	len = sizeof(cliaddr); 
	while(1)
	{
		struct X509CERT certificate;
		char message[20];
		unsigned char *buffer = malloc(14);
		int n = recvfrom(listenfd, message, MAXLINE, 
				0, (struct sockaddr*)&cliaddr,&len); //receive message from server
		message[n] = '\0';
		// printf("m %d\n", certificate.version);
		// sendto(cliaddr, message, sizeof(message), 0, (struct sockaddr*)NULL, sizeof(servaddr)); 

		char *ip = inet_ntoa(cliaddr.sin_addr);
		printf("message %s\n", message);
		printf("Conection from %s\n", ip);

		if(strcmp(message, "Create") == 0)
		{
			// time.sleep(23);
			// int s = recvfrom(listenfd, buffer, sizeof(buffer),
			// 		0, (struct sockaddr*)&cliaddr, &len);
			// buffer[s] = '\0';
			printf("Hello Shit!!!!!!!\n");
			requestCertificate(servaddr,listenfd, cliaddr, len);
			printf("Outside Recv Certificate\n");
		}
		else if(strcmp(message, "Verify") == 0)
		{
			printf("Received Certificate Verification Request from %s\n", ip);
			verifyCertificate(certificate, servaddr, listenfd, cliaddr, len);
			//########TODO Verification Certificate Request #########//
		}
		else
		{
			printf("Wrong Request Message Sent\n");
		}

		// send the response 
		// sendto(listenfd, message, MAXLINE, 0,
		// 	(struct sockaddr*)&cliaddr, sizeof(cliaddr)); 

		// printf("#### Calculating Shared Key ####\n");

		// sscanf(buffer, "%lld", &shared_key); // Using sscanf
		// shared_key = compute_shared_key(shared_key, privateKey, P);
		// printf("Shared Key is : %lld\n",shared_key);

	}
}

int main()
{
	requestHandler_thread();
	// pthread_t requestHandler_thread;
	// pthread_create(&requestHandler_thread, NULL, requestHandler_thread, NULL);


}