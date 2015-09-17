#include <sys/socket.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/ioctl.h>
#include "sha2.h"
#include "hmac_sha2.h"
#include "uECC.h"


int rnd_seed;

void set_rnd_seed (int new_seed)
{
    rnd_seed = new_seed;
}

int rand_int (void)
{
    unsigned int hi,lo;

    hi = 16807 * (rnd_seed >> 16);
    lo = 16807 * (rnd_seed & 0xFFFF);
    lo += (hi & 0x7FFF) << 16;
    lo += hi >> 15;
    if (lo > 2147483647)
        lo -= 2147483647;
    rnd_seed = lo;
    return rnd_seed;
}
uint32_t gen_random(int seed)
{
	//generate a 32-bit random number
	printf("\n generate a random number\n");
	uint32_t random;
	set_rnd_seed(seed);
	random = rand_int();
	return random;
}


/*
	extract the public key and mac value from a buffer
	mac and public key must be pre-allocated
*/
uint32_t extract_pkey_mac(uint8_t *mac,uint8_t *l_public,uint8_t *buffer)
{
	if(buffer == NULL) return 1;
	memcpy(l_public,buffer,uECC_BYTES *2);
	memcpy(mac,buffer + uECC_BYTES *2, SHA256_DIGEST_SIZE);
	return 0;
}
//-------------------------------------------------------------------------------------------//
/*

	receive client's public key
*/

uint32_t receive_pkey(uint32_t sockfd,uint8_t *l_public_client)
{

	if (recv(sockfd,l_public_client,uECC_BYTES * 2,0) == -1) {
		perror("recv");
		exit(EXIT_FAILURE);
	}

	return 0;
	flush_and_exit:
	fflush(stderr);
	exit(EXIT_FAILURE);
}
//-------------------------------------------------------------------------------------------//
/*
	send public key and mac value to client
	l_public1,l_public_client,r_key
*/
uint32_t send_commit(int sockfd, uint8_t *l_server_pub,uint8_t *l_client_pub,uint32_t key, uint32_t random)
{

	uint8_t *buffer= (uint8_t *)malloc(uECC_BYTES * 4 + sizeof(uint32_t) +1);
	memset(buffer,0, uECC_BYTES * 4 + sizeof(uint32_t) +1);
	memcpy(buffer,l_server_pub,uECC_BYTES * 2);
	memcpy(buffer + uECC_BYTES * 2,l_client_pub,uECC_BYTES * 2);
	memcpy(buffer + uECC_BYTES * 4,&random,sizeof(uint32_t));

	uint8_t *mac = (uint8_t*)malloc(SHA256_DIGEST_SIZE +1);
	memset(mac,0,SHA256_DIGEST_SIZE +1);

	unsigned char *key_t = (unsigned char*)malloc(4);
	memcpy(key_t,&key,sizeof(random));
	hmac_sha256(key_t,4,buffer,uECC_BYTES * 4 + sizeof(uint32_t),mac,SHA256_DIGEST_SIZE);

	
	unsigned char *sent_buffer = (unsigned char*)malloc(uECC_BYTES * 2 + SHA256_DIGEST_SIZE + 1);
	memset(sent_buffer,0, uECC_BYTES * 2 + SHA256_DIGEST_SIZE + 1);
	memcpy(sent_buffer,l_server_pub,uECC_BYTES * 2);
	memcpy(sent_buffer + uECC_BYTES * 2, mac, SHA256_DIGEST_SIZE);


	/* send the public key and mac to client */
	if (send(sockfd,sent_buffer,uECC_BYTES * 2 + SHA256_DIGEST_SIZE, 0) == -1) {
		perror("send");
		goto flush_and_exit;
	}

	free(buffer);
	free(sent_buffer);
	free(mac);
	free(key_t);
	return 0;
flush_and_exit:
	fflush(stderr);
	exit(EXIT_FAILURE);
	return 0;
}


//-------------------------------------------------------------------------------------------//
/*
	receive the client's public key and client's random number
*/
uint32_t receive_ran(int newfd,uint32_t *ran_client)
{
	if(recv(newfd,ran_client,sizeof(uint32_t),0) == -1) {
		perror("recv");
		goto flush_and_exit;
	}
	return 0;
flush_and_exit:
	fflush(stderr);
	exit(EXIT_FAILURE);
}
//-------------------------------------------------------------------------------------------//
/*
	the key is a 32-bit random number xor with client's random
*/
uint32_t send_decommit(int sockfd, uint32_t key)
{
	
	/* send the key to client */
	if (send(sockfd,&key,sizeof(uint32_t), 0) == -1) {
		perror("send");
		goto flush_and_exit;
	}

	return 0;
flush_and_exit:
	fflush(stderr);
	exit(EXIT_FAILURE);
	return 0;

}
//-------------------------------------------------------------------------------//

void dec_hex(uint32_t num)   // Function Definition
{
   uint32_t rem[50],i=0,length=0;

   while(num>0)
   {
      rem[i]=num%16;
      num=num/16;
      i++;
      length++;
   }
   i=length-1;
   while(i>0){
      if(rem[i]>9)
	     printf("%c",rem[i]+55);
      else
             printf("%d",rem[i]);
       i--;
    }
    if(rem[0]>9)
	 printf("%c",rem[0]+55);
    else
 	 printf("%d",rem[0]);;
}
void show_random_to_screen(uint32_t number)
{
	printf("\n Random value :");
	dec_hex(number);
}
void vli_print(uint8_t *p_vli, unsigned int p_size)
{
    
    while(p_size)
    {
        printf("%02X ", (unsigned)p_vli[p_size - 1]);
        --p_size;
    }
}

//the shared key must be initiated before this function
int extract_shared_secret(uint8_t *l_private,uint8_t *l_public,uint8_t *l_secret)
{
      if(!uECC_shared_secret(l_public, l_private, l_secret))
        {
            printf("shared_secret() failed (1)\n");
            return 1;
        }
	printf("\nShared Key:");
	vli_print(l_secret, uECC_BYTES);
	return 0;
}
//receive the accept status and verify the status
int receive_accept(int sockfd,uint8_t *l_secret)
{
	uint8_t *buffer = "ACCEPT";
	uint8_t *mac = (uint8_t*)malloc(SHA256_DIGEST_SIZE +1);
	memset(mac,0,SHA256_DIGEST_SIZE +1);
	hmac_sha256(l_secret,uECC_BYTES,buffer,strlen(buffer),mac,SHA256_DIGEST_SIZE);
	printf("\nHMAC:");
	vli_print(mac, SHA256_DIGEST_SIZE);
	uint8_t mac_temp[SHA256_DIGEST_SIZE];
	
	if(recv(sockfd,mac_temp,SHA256_DIGEST_SIZE,0) == -1) {
		perror("recv");
		goto flush_and_exit;
	}
	printf("\nReceived HMAC:");
	vli_print(mac_temp, SHA256_DIGEST_SIZE);
	return memcmp(mac_temp,mac,SHA256_DIGEST_SIZE);
flush_and_exit:
	fflush(stderr);
	exit(EXIT_FAILURE);
	free(mac);
	return 0;
}
int run_protocol(int newfd)
{
	
	//init public key, a private key, a 32-bit random and key 
	uint8_t l_private1[uECC_BYTES];
   	uint8_t l_public1[uECC_BYTES * 2];
	uint8_t l_secret[uECC_BYTES];
	 if(!uECC_make_key(l_public1, l_private1))
        {
            printf("uECC_make_key() failed\n");
            return 1;
        }
	uint32_t r_key;
	r_key =  gen_random(69);
	uint32_t random;
	random = gen_random(r_key);

	//receive the client's public key	
	uint8_t l_public_client[uECC_BYTES * 2];
	receive_pkey(newfd,l_public_client);
	
	//send commitment to client(server's public key, mac-server/client pub + server ran)
	send_commit(newfd,l_public1,l_public_client,r_key,random);

	//show random number to screen 
	show_random_to_screen(random);
	
	printf("\nSend key to client");
	//send key
	send_decommit(newfd,r_key);
	//calculate the secret key
	extract_shared_secret(l_private1,l_public_client,l_secret);
	//receive the accept from client
	int result;
	result = receive_accept(newfd,l_secret);
	if(result == 0)
		printf("\nThe connection is accepted");
	else
		printf("\nThe connection is refused");
	//enter to exit
	printf("\n Enter to continue");
	getchar();
	return 0;
flush_and_exit:
	fflush(stderr);
	exit(EXIT_FAILURE);
}
int main(int argc, const char *argv[])
{
	
	//-------------------------------------------------------------------------------//
	//create a socket
	int sockfd, newfd, chr;
	socklen_t cliaddr_len;
	struct sockaddr_in addr, cliaddr;


	/* simplistic TCP client, uses hardcoded values */
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1) {
		perror("socket");
		goto flush_and_exit;
	}

	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,(int[]) { 1 },sizeof(int)) == -1) 
	{
		perror("setsockopt");
		goto flush_and_exit;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	inet_pton(AF_INET, "172.16.226.137", &addr.sin_addr);
	addr.sin_port = htons(9999);

	if (bind(sockfd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
		perror("bind");
		goto flush_and_exit;
	}

	if (listen(sockfd, 1)) {
		perror("listen");
		goto flush_and_exit;
	}

	printf("waiting for a connection\n");
	
	if ((newfd = accept(sockfd, (struct sockaddr *) &cliaddr, &cliaddr_len)) == -1) {
		perror("accept");
		goto flush_and_exit;
	}
	close(sockfd);

	printf("accepting a connection from a client\n");
	
	run_protocol(newfd);
	close(newfd);

	return 0;
flush_and_exit:
	fflush(stderr);
	exit(EXIT_FAILURE);
}
