#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/hmac.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <error.h>

//Global
unsigned char key[32], iv[32];
unsigned char final_result[20];
//unsigned int len = 20;
//final_result = (unsigned char*)malloc(sizeof(char) * len);	//Base64 of the ciphertext



/*Function definitions*/
int aes_init(unsigned char* pwd, unsigned int pwd_len, unsigned char *salt,EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx);
void readable(char *str);
void readable1(char *str);
void write_file_plaintext();
unsigned int hash(const char *mode, const char* dataToHash, size_t dataSize, unsigned char* outHashed);
/*********************/




/*generating key and IV*/
int aes_init(unsigned char* pwd, unsigned int pwd_len, unsigned char *salt,EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx)
{
	int i, rounds = 1;                   /* rounds */
	//unsigned char key[32], iv[32];

	i = EVP_BytesToKey(EVP_aes_256_cbc(),EVP_sha1(),salt,pwd,pwd_len,rounds,key,iv);
	if(i != 32)		//256 bits
	{
	    printf("\n Error,Incorrect key size generated:%d:\n",i);
	    return -1;
	}
	
	printf("IV is : ");		//want to see randomness then use -> printf("IV is : %s\n",iv);	
	readable1(iv);
	printf("Key is : ");	
	readable1(key);
	

	EVP_CIPHER_CTX_init(e_ctx);
	EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
	EVP_CIPHER_CTX_init(d_ctx);
	EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);
	return 0;
}
/*******************/

/*Hashing the passphrase to generate salt*/
unsigned int hash(const char *mode, const char* dataToHash, size_t dataSize, unsigned char* outHashed) {
    unsigned int md_len = -1;
    const EVP_MD *md = EVP_get_digestbyname(mode);
    if(NULL != md) {
        EVP_MD_CTX mdctx;
        EVP_MD_CTX_init(&mdctx);
        EVP_DigestInit_ex(&mdctx, md, NULL);
        EVP_DigestUpdate(&mdctx, dataToHash, dataSize);
        EVP_DigestFinal_ex(&mdctx, outHashed, &md_len);
        EVP_MD_CTX_cleanup(&mdctx);
    }
    return md_len;
}

/*******************/



/*Make things visible and store in file*/
void readable(char *str)
{
	FILE *try;
	try = fopen("random.txt","w+");
	BIO *bio, *b64;
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new_fp(try, BIO_NOCLOSE);
	BIO_push(b64, bio);
	BIO_write(b64, str, strlen(str));
	BIO_flush(b64);
	BIO_free_all(b64);	
	fclose(try);
	
}
/*******************/


/*Make things visible convert things to base 64*/
void readable1(char *str)
{
	
	
	BIO *bio, *b64;
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new_fp(stdout, BIO_NOCLOSE);
	BIO_push(b64, bio);
	BIO_write(b64, str, strlen(str));
	BIO_flush(b64);
	BIO_free_all(b64);	
	
	
}
/*******************/





/*Main Function*/
int main()
{

	OpenSSL_add_all_algorithms();	
	int i=0;
	int decryptedtext_len, ciphertext_len;
	FILE *p;
	char passphrase[10],passphrase_check[15],ne_fc[200];	//ne_fc non encrypted file contents
	unsigned char salt[20],ciphertext[128],decryptedtext[128];
	int passphrase_check_len = 0 , passphrase_len=0 , fd=0;	//fd --> file descriptor
	
	EVP_CIPHER_CTX en,de;      /* The EVP structure which keeps track of all crypt operations see evp.h for details */
	

	printf("Enter the random number (len < 10): ");
	scanf("%s",passphrase_check);
	passphrase_check_len = strlen(passphrase_check);
	if(passphrase_check_len < 10)
	{
		strncpy(passphrase,passphrase_check,10);
		passphrase_len = strlen(passphrase);
		printf("Your random number is : %s\n",passphrase);
	}
	else
	{
		printf("Random length increased over limit. Exiting now. . .\n");
		exit(1);
	}
	
	

	//generating salt
		
	hash("SHA1", passphrase, passphrase_len, salt);
	printf("Random number is : ");
	for(i=0; i<sizeof(salt)/sizeof(salt[0]); i++) 
	{
	    	printf("%02x", salt[i]);
	}
	printf("\n");
	
	readable(salt);	
	
	return 0;
}



//http://stackoverflow.com/questions/10391610/issues-with-encrypting-a-file-using-openssl-evp-apiaes256cbc
