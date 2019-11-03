/* ----------------------------------------------------------------------------- 
 * ipdc.c
 *
 * iPDC - Phasor Data Concentrator
 *
 * Copyright (C) 2011-2012 Nitesh Pandit
 * Copyright (C) 2011-2012 Kedar V. Khandeparkar
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * Authors: 
 *		Nitesh Pandit <panditnitesh@gmail.com>
 *		Kedar V. Khandeparkar <kedar.khandeparkar@gmail.com>			
 *
 * ----------------------------------------------------------------------------- */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h> 
#include <string.h>
#include <search.h>
#include "global.h"
#include "apps.h"

#define lli long long int
#define kdcPort 5000
#define MAXLINE 1000
/* ---------------------------------------------------------------- */
/*                   main program starts here                       */
/* ---------------------------------------------------------------- */
lli compute_public_values(int g, int a, int p)
{
	return (((lli)pow(g, a)) % p);
}

lli compute_shared_key(lli received_value, int a, int p)
{
	return (((lli)pow(received_value, a)) % p);
}

int main(int argc, char **argv)
{
	if (argc != 2 )
	{
		printf("Passing arguments does not match with the iPDC inputs! Try Again?\n");
		exit(EXIT_SUCCESS);
	}
	int P = 1009, G = 109;
	lli shared_key = 0;

	srand(time(0));
	lli privateKey = rand() % 10;
	printf("Private Key : %lld\n", privateKey);
	lli public_value = compute_public_values(G, privateKey, P);
	printf("Calculated Public Value at KDC : %lld\n",public_value);

	char buffer[100];
	char message[MAXLINE];
	snprintf (message, sizeof(message), "%lld",public_value); // print int 'n' into the char[] buffer

// For sending message to KDC
	//#############################
	{
		int sockfd, n; 
		struct sockaddr_in servaddr; 

		// clear servaddr 
		bzero(&servaddr, sizeof(servaddr)); 
		servaddr.sin_addr.s_addr = inet_addr("127.0.0.1"); 
		servaddr.sin_port = htons(kdcPort); 
		servaddr.sin_family = AF_INET; 

		// create datagram socket 
		sockfd = socket(AF_INET, SOCK_DGRAM, 0); 

		// connect to server 
		if(connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) 
		{ 
			printf("\n Error : Connect Failed \n"); 
			exit(0); 
		} 

		// request to send datagram 
		// no need to specify server address in sendto 
		// connect stores the peers IP and port 
		sendto(sockfd, message, MAXLINE, 0, (struct sockaddr*)NULL, sizeof(servaddr)); 

		// waiting for response 
		recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)NULL, NULL); 
		// puts(buffer);
		printf("Received Public Value : %s\n", buffer);

		printf("#### Calculating Shared Key ####\n");
		sscanf(buffer, "%lld", &shared_key); // Using sscanf
		shared_key = compute_shared_key(shared_key, privateKey, P);
		if (shared_key == 0)
		{
			printf("Key Server Not Available Exiting.......\n");
			exit(100);
		}
		printf("Shared Key is : %lld\n",shared_key);
		// close the descriptor 
		close(sockfd);
	}
	//#############################

	int id,i,port,ret;
	
	char *ptr1,buff[20];
	char *l1,*d1,*d2,*d3,*d4;

	FILE *fp;
	size_t l2=0;
	ssize_t result;

	id = atoi(argv[1]);
    ptr1 = malloc(30*sizeof(char));
    memset(ptr1, '\0', 30);
	strcat(ptr1, "iPDC");
	sprintf(buff,"%d",id);
	strcat(ptr1,buff);
	strcat(ptr1, ".csv");

	/* Open the iPDC CSV Setup File */
	fp = fopen (ptr1,"r");

	if (fp != NULL)
	{
		/* For The CSV Headers */
		getdelim (&l1, &l2, ('\n'), fp); 
		
		if ((result = getdelim (&l1, &l2, ('\n'), fp)) >0)
		{
			/* For The First column CSV Header */
			d1 = strtok (l1,","); 
			
			d1 = strtok (NULL,","); 
			PDC_IDCODE = atoi(d1);

			d1 = strtok (NULL,","); 
			TCPPORT = atoi(d1);

			d1 = strtok (NULL,","); 
			UDPPORT = atoi(d1);

			d1 = strtok (NULL,",");
			memset(dbserver_ip, '\0', 20);
			strcpy(dbserver_ip, (char *)d1);
		//			if(!checkip(dbserver_ip))
		//				exit(1);
			
			d1 = strtok (NULL,","); 
			surcCount = atoi(d1);
			
			d1 = strtok (NULL,","); 
			destCount = atoi(d1);
		
		// Commented by Kedar for future use on 12-07-13		
			d1 = strtok (NULL,","); 
			waitTime = atoi(d1);

			d1 = strtok (NULL,","); 			
		//			d1 = strtok (NULL,","); 
		//			printf("%s\n",d1);
			if(!strncmp(d1,"YES",3))
			{			
				IamSPDC = true;
				printf("I am SPDC\n");

				d1 = strtok (NULL,","); 
			//	if(!strncmp(d1,"DDS3",4))
			//		buildAppHashTables(); //Added by KK on 20/11/2013:19.53

			} else {

				IamLPDC = true;
				printf("I am LPDC\n");

				d1 = strtok (NULL,","); // skip DDS

				d1 = strtok (NULL,","); // DELAY/DROP
				delayORdrop = atoi(d1);

				d1 = strtok (NULL,","); // PMU ID of packet to be delayed/dropped
				delayDropPMUID = atoi(d1);

				d1 = strtok (NULL,","); // dropORdelayPeriod
				dropORdelayPeriod = atoi(d1);

				if(!delayORdrop) {
					
					d1 = strtok (NULL,","); // Time for delay
					timedelay = atoi(d1);	// in millisec
					timedelay = timedelay*1e3; // in microsec
				}
		//				printf("Print %s\n",d1);
			}
			
			pthread_mutex_lock(&mutex_Analysis);
			// For Analysis of Aggregated Data dispatch and Distributed Partial Computation
			// first_arrival_lpdc = 9999999;
			// Min_pmutolpdc = 9999999;
			Min_pmutolpdcdelay_sum = 0;
			count_patial_computation = 0;
			computation_time_sum = 0;
			appComputeTime = 0;
			dataFrameCreateTime = 0;
			flagApps = 0;
			dropCount = 0;
			
		/*			Dispatch_start_soc = 0;*/
		/*			Dispatch_start_fsec = 0;*/
			VSappTime = 0, SEappTime = 0, CMappTime = 0;
			timestampCount = 0;

			pthread_mutex_unlock(&mutex_Analysis);

			/* setup() call to stablish the connections at iPDC restart */
			setup();		
			
			if (surcCount > 0)
			{
				/* For The CSV Headers */
				getdelim (&l1, &l2, ('\n'), fp); 
				getdelim (&l1, &l2, ('\n'), fp); 
			
				for (i=0; i<surcCount; i++)
				{
					if ((result = getdelim (&l1, &l2, ('\n'), fp)) >0)
					{
						/* For The First column Header */
						if(i == 0)
						{
							d1 = strtok (l1,","); 
							d1 = strtok (NULL,","); 
						}	
						else
							d1 = strtok (l1,","); 

						d2 = strtok (NULL,","); 

						d3 = strtok (NULL,","); 

						d4 = strtok (NULL,","); 

						/* call add_PMU() to actual add pmu/pdc and start communication */ 
						ret = add_PMU(d1,d2,d3,d4);

						if(ret == 0)
							printf("Source Device Successfully Added. For ID: %s, IP: %s, PORT: %s, and Protocol:%s.\n",d1,d2,d3,d4);
						else
							printf("Device details already exists! For ID: %s, IP: %s, PORT: %s, and Protocol:%s.\n",d1,d2,d3,d4);					}
				}	
			}
			else
			{
				printf("\nNo Source Devices mentioned in CSV!\n");
			}

			if (destCount > 0)
			{
				/* For The CSV Headers */
				getdelim (&l1, &l2, ('\n'), fp); 
				getdelim (&l1, &l2, ('\n'), fp); 
			
				for (i=0; i<destCount; i++)
				{
					if ((result = getdelim (&l1, &l2, ('\n'), fp)) >0)
					{
						/* For The First column Header */
						if(i == 0)
						{
							d1 = strtok (l1,","); 
							d1 = strtok (NULL,","); 
						}	
						else
							d1 = strtok (l1,","); 

						d2 = strtok (NULL,","); 

						/* call add_PDC() to add a pdc and start */ 
						ret = add_PDC(d1,d2);

						if(ret == 0)
							printf("Destination Device Successfully Added. For IP: %s, and Protocol:%s.\n",d1,d2);
						else
							printf("Device details already exists! For IP: %s, and Protocol:%s.\n",d1,d2);					}
				}	
			}
			else
			{
				printf("\nNo Destination Devices mentioned in CSV!\n");
			}
		}
		else
			exit(1);

		/* Close the iPDC file */
		fclose(fp);		
	}
	else
	{
		printf("\niPDC CSV file is not present in the system! iPDC Exiting...\n\n");		
	}
	
	pthread_join(UDP_thread, NULL);
	pthread_join(TCP_thread, NULL);
	pthread_join(p_thread, NULL);

	close(UL_UDP_sockfd);
	close(UL_TCP_sockfd);
	
	return 0;
}


/**************************************** End of File *******************************************************/
