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

static int rnd_seed;

void set_rnd_seed (int new_seed)
{
    rnd_seed = new_seed;
}

uint32_t rand_int (void)
{
    uint32_t hi,lo;

    hi = 16807 * (rnd_seed >> 16);
    lo = 16807 * (rnd_seed & 0xFFFF);
    lo += (hi & 0x7FFF) << 16;
    lo += hi >> 15;
    if (lo > 2147483647)
        lo -= 2147483647;
    rnd_seed = lo;
    return rnd_seed;
}


uint32_t extract_publickey(uint8_t *publickey,uint8_t *buffer)
{
	if(buffer == NULL) return 1;
	memcpy(publickey,buffer,uECC_BYTES * 2);
	return 0;
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
/*
	calculate hash value of the server's public key,  and a 32-bits key
	output 256-bit hash value
*/
uint32_t cal_hash(uint8_t *l_public, uint32_t key,uint8_t *hash)
{
	//commitment scheme is implemented by using hash function. 
	// calculate hash value of the public key and the random
	//declare the the buffer
	unsigned char *buffer = (unsigned char*)malloc(uECC_BYTES * 2 + sizeof(uint32_t) +1);
	if(buffer == NULL)
	{
	    printf("allocate memory failed\n");
            return 1;
	}	
	memset(buffer,0, uECC_BYTES * 2 + sizeof(uint32_t) +1);
	memcpy(buffer,l_public,uECC_BYTES * 2);
	memcpy(buffer + uECC_BYTES * 2,&key,sizeof(uint32_t));
	
	sha256(buffer,uECC_BYTES * 2 + sizeof(uint32_t),hash);

	//printf("\n mac:");
	/*int i;
	for(i=0;i<SHA256_DIGEST_SIZE;i++)
		printf(" 0x%x",hash[i]&0xff);
	printf("\n");
	*/
	free(buffer);
	return 0;
}
//-------------------------------------------------------------------------------------------//
/*
	send commitment to server, including : a public key
*/
uint32_t send_commit(int sockfd, uint8_t *l_public)
{

	if (send(sockfd,l_public,uECC_BYTES * 2, 0) == -1) {
		perror("send");
		goto flush_and_exit;
	}
	return 0;
flush_and_exit:
	fflush(stderr);
	exit(EXIT_FAILURE);
	return 0;
}
//-------------------------------------------------------------------------------------------//
/*
	receive the first commitment from server, including : a public key , a MAC value
	public key and mac value must be pre-allocated. 
*/
uint32_t receive_commit(int sockfd,uint8_t *l_public_server,uint8_t *mac)
{
	//receive message from the server	
	unsigned char *buffer = (unsigned char*)malloc(uECC_BYTES * 2 + SHA256_DIGEST_SIZE + 1);
	memset(buffer,0, uECC_BYTES * 2 + SHA256_DIGEST_SIZE + 1);
	if (recv(sockfd,buffer,uECC_BYTES * 2 + SHA256_DIGEST_SIZE ,0) == -1) {
		perror("recv");
		exit(EXIT_FAILURE);
	}

	extract_pkey_mac(mac,l_public_server,buffer);
	free(buffer);
	return 0;
flush_and_exit:
	fflush(stderr);
	exit(EXIT_FAILURE);

}
//-------------------------------------------------------------------------------------------//
/*
	send client's random to server
*/
uint32_t send_random(int sockfd,uint32_t random)
{
	if (send(sockfd,&random, sizeof(uint32_t), 0) == -1) {
		perror("send");
		return 1;
	}
	return 0;
}
//-------------------------------------------------------------------------------------------//
/*
	receive decommit from server, extract server's random
*/
uint32_t receive_key(int sockfd,uint32_t *key)
{

	if (recv(sockfd,key,sizeof(uint32_t),0) == -1) {
		perror("recv");
		exit(EXIT_FAILURE);
	}
	return 0;
flush_and_exit:
	fflush(stderr);
	exit(EXIT_FAILURE);
}
/*
	verify the decommited value( server random/must be extracted in receive commit) to server's mac
*/
//-------------------------------------------------------------------------------------------//
int verify_commitment(uint8_t *l_client_pub,uint32_t key,uint32_t random,uint8_t *l_server_pub,uint8_t *mac)
{

	uint8_t *buffer= (uint8_t *)malloc(uECC_BYTES * 4 + sizeof(uint32_t) +1);
	memset(buffer,0, uECC_BYTES * 4 + sizeof(uint32_t) +1);
	memcpy(buffer,l_server_pub,uECC_BYTES * 2);
	memcpy(buffer + uECC_BYTES * 2,l_client_pub,uECC_BYTES * 2);
	memcpy(buffer + uECC_BYTES * 4,&random,sizeof(uint32_t));

	uint8_t *temp_mac = (uint8_t*)malloc(SHA256_DIGEST_SIZE +1);
	memset(temp_mac,0,SHA256_DIGEST_SIZE +1);

	unsigned char *key_t = (unsigned char*)malloc(4);
	memcpy(key_t,&key,sizeof(random));
	hmac_sha256(key_t,4,buffer,uECC_BYTES * 4 + sizeof(uint32_t),temp_mac,SHA256_DIGEST_SIZE);
	
	int result = memcmp(mac,temp_mac,SHA256_DIGEST_SIZE);
	free(buffer);
	free(temp_mac);
	free(key_t);
	return result;
}
//-------------------------------------------------------------------------------------------//

uint32_t press_button(char ch)
{
	char c;
	printf("\nPress '%c' to continue:",ch);
	c = getchar();
	if(c != ch)
	{
		printf("\n Wrong button");
		return 1;
	}

	return 0;		
}
uint32_t covert_string_int(char *str)
{
	 int base;
         char *endptr;
         long val;

	 errno = 0;    /* To distinguish success/failure after call */
         val = strtol(str, &endptr, 16);

         /* Check for various possible errors */

         if ((errno == ERANGE && (val == INT_MAX || val == INT_MIN))
                   || (errno != 0 && val == 0)) 
	   {
               perror("strtol");
               exit(EXIT_FAILURE);
           }
	if (endptr == str) {
               fprintf(stderr, "No digits were found\n");
               exit(EXIT_FAILURE);
           }
	 return (uint32_t)val;
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
int send_accept(int sockfd,uint8_t *l_secret)
{
	uint8_t *buffer = "ACCEPT";
	uint8_t *mac = (uint8_t*)malloc(SHA256_DIGEST_SIZE +1);
	memset(mac,0,SHA256_DIGEST_SIZE +1);
	hmac_sha256(l_secret,uECC_BYTES,buffer,strlen(buffer),mac,SHA256_DIGEST_SIZE);
	printf("\n HMAC:");
	vli_print(mac, SHA256_DIGEST_SIZE);
	if (send(sockfd,mac,SHA256_DIGEST_SIZE, 0) == -1) {
		perror("send");
		return 1;
	}
	free(mac);
	return 0;
}
int run_protocol(int sockfd)
{
	//initiate the public key, private key
	//------------------------------------------------------------------------------//
	//printf("\n 32-bit random value:%d %04x \n",random,random);
	//generate a public key and a private key
  	 uint8_t l_private1[uECC_BYTES];
   	 uint8_t l_public1[uECC_BYTES * 2];
	 uint8_t l_secret[uECC_BYTES];
  	 if(!uECC_make_key(l_public1, l_private1))
        {
            printf("uECC_make_key() failed\n");
            return 1;
        }
	//------------------------------------------------------------------------------//
	//allocate server's public key and MAC value, server's key and random
	uint8_t l_public_server[uECC_BYTES * 2];
	uint8_t *mac = (uint8_t *)malloc(SHA256_DIGEST_SIZE +1);
 	memset(mac,0,SHA256_DIGEST_SIZE +1);
	uint32_t r_key;
	uint32_t server_random;

	printf("\n send public key to server");
	//send commitment to server
	send_commit(sockfd,l_public1);
	printf("\n receive server's commitment");
	//receive the commitment from the server
	receive_commit(sockfd,l_public_server,mac);
	
	//press a button 'a' to send Acknowledgement 
	if(press_button('a') != 0)
	{
		return 1;
	}
	fflush(stdout);
	//enter the SAS number from server
	printf("\nEnter SAS number:");
	char SAS[30];
	scanf("%s",SAS);
	server_random = covert_string_int(SAS);
	fflush(stdout);
	//receive the key from server
	receive_key(sockfd,&r_key);
	printf("\n Received Key:");
	dec_hex(r_key);
	//check commitment
	char result = verify_commitment(l_public1,r_key,server_random,l_public_server, mac);
	if(result != 0)
	{
		printf("\ndecommit fail\n");
		return 1;
	}
	else 
		printf("\ndecommit successful - press 'A' to accept\n");
	getchar();
	//calculate the secret key
	extract_shared_secret(l_private1,l_public_server,l_secret);
	//send the accept to server
	 send_accept(sockfd,l_secret);
	return 0;
}
int main(int argc, const char *argv[])
{
	//create a shocket
	int sockfd, c;
	struct sockaddr_in addr;

	/* simplistic TCP client, uses hardcoded values */
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1) {
		perror("socket");
		goto flush_and_exit;
	}


	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	inet_pton(AF_INET, "172.16.226.143", &addr.sin_addr);
	addr.sin_port = htons(9999);
	if (connect(sockfd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
		perror("connect");
		goto flush_and_exit;
	}
	
	run_protocol(sockfd);
	

	return 0;

flush_and_exit:
	fflush(stderr);
	exit(EXIT_FAILURE);
}
