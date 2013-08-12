#include "des_test.h"
/*
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
*/
void key_init() {
    RAND_seed(seed, sizeof(DES_cblock));
 
    DES_random_key(&key);
    DES_random_key(&key2);
    DES_random_key(&key3);
 
    DES_set_key((C_Block *)key, &keysched);
    DES_set_key((C_Block *)key2, &keysched2);
    DES_set_key((C_Block *)key3, &keysched3);
}

void encrypt_tdes(unsigned char * in, unsigned char * out)
{
    DES_ecb_encrypt((C_Block *)in,(C_Block *)out, &keysched, DES_ENCRYPT);
    DES_ecb_encrypt((C_Block *)out,(C_Block *)out, &keysched2, DES_DECRYPT);
    DES_ecb_encrypt((C_Block *)out,(C_Block *)out, &keysched3, DES_ENCRYPT);
}

void decrypt_tdes(unsigned char * in, unsigned char * out)
{
    DES_ecb_encrypt((C_Block *)in,(C_Block *)out, &keysched3, DES_DECRYPT);
    DES_ecb_encrypt((C_Block *)out,(C_Block *)out, &keysched2, DES_ENCRYPT);
    DES_ecb_encrypt((C_Block *)out,(C_Block *)out, &keysched, DES_DECRYPT);
}

char* encrypt_ipv6(char *in_string, char* out_string, int encrypt)
{
    
    unsigned char in[BUFSIZE];
    struct in6_addr in_in6,out_in6;
    inet_pton(AF_INET6, in_string, &in_in6);

    unsigned char * buf3 = (unsigned char *) &out_in6;
    memcpy(buf3, (unsigned char* ) &in_in6, 8);
    memcpy(in, (unsigned char*) &in_in6 + 8, 8);
    if(encrypt)
            encrypt_tdes(in, buf3+8);
    else
            decrypt_tdes(in, buf3+8);

    inet_ntop(AF_INET6, &out_in6, out_string, INET6_ADDRSTRLEN);
    return out_string;
}

/*
int main(void)
{
    key_init();
    char in_string[INET6_ADDRSTRLEN] = "2001:db8:85a3::8a2e:370:7334";
    char out_string[INET6_ADDRSTRLEN];
    char out_string_2[INET6_ADDRSTRLEN];
    encrypt_ipv6(in_string,out_string,1);
    encrypt_ipv6(out_string,out_string_2,0);
    printf("1: %s\n", in_string);
    printf("2: %s\n", out_string);
    printf("3: %s\n", out_string_2);


    unsigned char in[BUFSIZE], out[BUFSIZE], back[BUFSIZE];
    unsigned char *e = out;
    int domain, s;
 
    memset(in, 0, sizeof(in));
    memset(out, 0, sizeof(out));
    memset(back, 0, sizeof(back));

    struct in6_addr buf2;
    unsigned char buf3[sizeof(struct in6_addr)];
    struct in6_addr encrypted;
    memset(buf3, 0, sizeof(buf3));
    char * tempip = "2001:db8:85a3::8a2e:370:7334";
    s = inet_pton(AF_INET6, tempip, &buf2);
    encrypted = encrypt_ipv6(buf2,1);

    char str[INET6_ADDRSTRLEN];
    printf("originip: %s\n", tempip); 
    inet_ntop(AF_INET6, &encrypted, str, INET6_ADDRSTRLEN) ;
    printf("encrypted: %s\n", str); 
    encrypted = encrypt_ipv6(encrypted, 0);
    inet_ntop(AF_INET6, &encrypted, str, INET6_ADDRSTRLEN) ;
    printf("decrypted: %s\n", str); 
 
    //printf("Ciphertext:");
    //while (*e) printf(" [%02x]", *e++);
    //printf("\n");

 
    return(0);
}
*/


