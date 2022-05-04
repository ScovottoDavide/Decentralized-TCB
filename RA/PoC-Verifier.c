#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/rand.h>

#include "tpm2_checkquote.h"
#define PORT 8080

int main(int argc, char const* argv[])
{
	int sock = 0, valread;
	struct sockaddr_in serv_addr;
	unsigned char buffer[32] = { 0 };
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		printf("\n Socket creation error \n");
		return -1;
	}

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(PORT);

	// Convert IPv4 and IPv6 addresses from text to binary form
	if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
		printf("\nInvalid address/ Address not supported \n");
		return -1;
	}

	if (connect(sock, (struct sockaddr*)&serv_addr,	sizeof(serv_addr)) < 0) {
		printf("\nConnection Failed \n");
		return -1;
	}

  	if(RAND_bytes(buffer, 32)){
    	int i;
    	//buffer[32] = '\0';
    	for(i=0; buffer[i]!='\0'; i++)
      		printf("%02x", buffer[i]);
		printf("\n");
    	send(sock, buffer, strlen(buffer), 0);
  	}

	sleep(2);

	tpm2_checkquote();

	return 0;
}
