#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/des.h>
#include <openssl/rand.h>
#include <arpa/inet.h>
 
#define BUFSIZE 64


DES_cblock key;
DES_cblock key2;
DES_cblock key3;
DES_cblock seed = {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
DES_key_schedule keysched;
DES_key_schedule keysched2;
DES_key_schedule keysched3;

void key_init();
char* encrypt_ipv6(char *in_string, char* out_string, int encrypt);
