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




/*Function definitions*/
int aes_init(unsigned char* pwd, unsigned int pwd_len, unsigned char *salt,EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx);
void readable(char *str);
void write_file_plaintext();
unsigned int hash(const char *mode, const char* dataToHash, size_t dataSize, unsigned char* outHashed);
void handle_errors();
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
	readable(iv);
	printf("Key is : ");	
	readable(key);
	

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


/*generating plaintext user input file*/
void write_file_plaintext()
{
	char junk[10];
	char data[200];
	FILE *fp;
	printf("Give the file contents and hit enter when you are done..");
	gets(junk);	//such pathetic \n char !
	gets(data);
	fp = fopen("plaintext","w+");
	if (fp == NULL) 
	{
 	       printf("\nFailed to open or create file.\n");
 	       fclose(fp);	
	       exit(0);					
   	}
	fprintf(fp,"%s",data);
	printf("File created!\n");
	fclose(fp);
	
}
/*******************/



/*Make things visible convert things to base 64*/
void readable(char *str)
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


/*Make things visible and store in file*/
void readable1(char *str)
{
	FILE *try;
	try = fopen("hmac1","w+");
	BIO *bio, *b64;
	b64 = BIO_new(BIO_f_base64());
	//bio = BIO_new_fp(stdout, BIO_NOCLOSE);
	bio = BIO_new_fp(try, BIO_NOCLOSE);
	BIO_push(b64, bio);
	BIO_write(b64, str, strlen(str));
	BIO_flush(b64);
	BIO_free_all(b64);	
	fclose(try);
	
}
/*******************/


/******Calculating HMAC of non encrypted data*******/
calc_hmac(char *str1,char *key)
{
	
    	int i; 
	char temp[200];
	strncpy(temp,str1,200);
    
   
    // Be careful of the length of string with the choosen hash engine. SHA1 needed 20 characters.
    // Change the length accordingly with your choosen hash engine.    
    unsigned char* result;
    unsigned int len = 20;
 
    result = (unsigned char*)malloc(sizeof(char) * len);
 
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
 
    // Using sha1 hash engine here.
    // You may use other hash engines. e.g EVP_md5(), EVP_sha224, EVP_sha512, etc
    HMAC_Init_ex(&ctx, key, strlen(key), EVP_sha1(), NULL);
    HMAC_Update(&ctx, (unsigned char*)&temp, strlen(temp));
    HMAC_Final(&ctx, result, &len);
    HMAC_CTX_cleanup(&ctx);
 
    printf("HMAC digest: ");
 
    for (i = 0; i != len; i++)
        printf("%02x", (unsigned int)result[i]);
 
    	printf("\n");
 	free(result);
}

/****************************/



/************Decrypt Engine***************/
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;
	

  int len;

  int plaintext_len;

  	/* Create and initialise the context */
  	if(!(ctx = EVP_CIPHER_CTX_new())) 
	{ 
		printf("Error in context initialization step 1!\n");
		exit(0);
	}

  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    	{ 
		printf("Error in context initialization step 2!\n");
		exit(0);
	}

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */

  	if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
	{ 
		printf("Error in context initialization step 3!\n");
		exit(0);
	}
	plaintext_len = len;

	//EVP_CIPHER_CTX_set_padding(&de, 0);

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
	{ 
		printf("Error in context initialization step 4!\n");
		//Check this it fails here.
		//handle_errors();
		//exit(0);
	}
  	plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);


  return plaintext_len;
}

/*****************************************/





/*Main Function*/
int main()
{	

	OpenSSL_add_all_algorithms();	
	int i=0;
	int decryptedtext_len, ciphertext_len;
	FILE *p;
	char passphrase[10],passphrase_check[15];	
	unsigned char salt[20],ciphertext[128],decryptedtext[128],e_fc[128];
	int passphrase_check_len = 0 , passphrase_len=0 , fd=0;	//fd --> file descriptor
	
	EVP_CIPHER_CTX en,de;      /* The EVP structure which keeps track of all crypt operations see evp.h for details */
	
	
	int big_match_salt = 0;
	int big_match_hmac = 0; 

	printf("Enter the passphrase (len < 10): ");
	scanf("%s",passphrase_check);
	passphrase_check_len = strlen(passphrase_check);
	if(passphrase_check_len < 10)
	{
		strncpy(passphrase,passphrase_check,10);
		passphrase_len = strlen(passphrase);
		printf("Your passphrase is : %s\n",passphrase);
	}
	else
	{
		printf("Passphrase length increased over limit. Exiting now. . .\n");
		exit(1);
	}
	
	

	//generating salt
		
	hash("SHA1", passphrase, passphrase_len, salt);
	printf("Salt is SHA1(Passphrase) : ");
	for(i=0; i<sizeof(salt)/sizeof(salt[0]); i++) 
	{
	    	printf("%02x", salt[i]);
	}
	printf("\n");
	
	


	unsigned char temp_salt[20],temp_base64[200];

	//Reading the saved SALT. 
	FILE *fp3;
	fp3 = fopen("salt","rb+");
	if(fp3 == NULL)
	{
		printf("Unable to check salt value.");
		fclose(fp3);
		exit(1);
	}
	else
	{
		
		while(!feof(fp3))
		{
			fread(temp_salt,20,1,fp3);
		}
		
	}
	fclose(fp3);
	
	//printf("Salt old : %s\n",temp_salt);
	//printf("Salt new : %s\n",salt);
	
	int l,g=0,h=0;
	for(l=0;l<strlen(salt);l++)
	{
		
		if(salt[l]!=temp_salt[l])
		{
			//printf("Not Equal\n");
			g++;
			//break;
		}
		else
		{
			//printf("Equal\n");
		}
	}

	if(g<=1)
	{
		printf("Salts match!\n");
		big_match_salt = 1;
		
	}
	else
	{
		printf("Salts don't match!\n");
	}


	/////////////Checking the integrity of file/////////////

	//reading the ciphertext contents.

	p=fopen("ciphertext","rb+");
	if(p == NULL)
	{
		printf("Unable to open file.");
		exit(1);
	}
	else
	{
		do
		{
			fread(e_fc,128,1,p);
			
		}while(!feof(p));
		
	}
	
	fclose(p);
	readable1(e_fc);	

	//hmac encryption wali side se.
	FILE *fp4;
	unsigned char base64[200];
	fp4 = fopen("hmac","rb+");
	if(fp4 == NULL)
	{
		printf("Unable to check salt value.");
		fclose(fp4);
		exit(1);
	}
	else
	{
		while(!feof(fp4))
		{
			fread(base64,200,1,fp4);	
		}

	}
	fclose(fp4);
	
	//hmac of this file 
	FILE *fp7;
	fp7 = fopen("hmac1","rb+");
	if(fp7 == NULL)
	{
		printf("Unable to check salt value.");
		fclose(fp7);
		exit(1);
	}
	else
	{
		while(!feof(fp7))
		{
			fread(temp_base64,200,1,fp7);	
		}

	}
	fclose(fp7);
	


	for(l=0;l<strlen(salt);l++)
	{
		
		if(base64[l]!=temp_base64[l])
		{
			//printf("Not Equal\n");
			h++;
		}
		else
		{
			//printf("Equal\n");
		}
	}

	if(h<=1)
	{
		printf("HMAC matched!\n");
		big_match_hmac = 1;
	}
	else
	{
		printf("HMAC don't match!\n");
	}

	
	////////////////////////////////////////////////////////
	
	int len_of_e_fc=0,k;
	
	if((big_match_hmac && big_match_salt)==1)
	{
		printf("+------------------------------------------------+\n");
		printf("...Decryption Allowed...\n");
		printf("+------------------------------------------------+\n");
		//now generating key and IV
		if(aes_init(passphrase,passphrase_len,(unsigned char*) salt,&en,&de))     /* Generating Key IV and set EVP struct */
		{
    			perror("\n Error, Cant initialize key and IV:");
    			return -1;
		}
		
		
		//calc length of the e_fc
		printf("cipher from file --> %s\n",e_fc);
		
		/*
		for(k=0;k<strlen(e_fc);k++)		
		{
			printf("%02x",(unsigned int)e_fc[k]);
			len_of_e_fc++;
		}
		printf("\nLen is : %d\n",len_of_e_fc);
		*/

		

		//decrypt the contents now
		decryptedtext_len = decrypt(e_fc,112, key, iv,decryptedtext);
		
		//printf("len of decrypt:%d\n",decryptedtext_len);
		//decrypt(e_fc,128, key, iv,decryptedtext);		

  		/* Add a NULL terminator. We are expecting printable text */
  		//decryptedtext[decryptedtext_len] = '\0';

		decryptedtext[16] = '\0';		

  		/* Show the decrypted text */
  		printf("Decrypted text is : ");
  		printf("%s\n", decryptedtext);
	

		EVP_CIPHER_CTX_cleanup(&en);
		EVP_CIPHER_CTX_cleanup(&de);
	}
	else
	{
		printf("...Sorry Decryption is not allowed...\n");

	}


	return 0;
}



void handle_errors()
{

	FILE *fp10;
	char buf[50];
	fp10 = fopen("plaintext","r+");
	if(fp10 == NULL)
	{
		//printf("Unable to check salt value.");
		fclose(fp10);
		exit(1);
	}
	else
	{
		while(!feof(fp10))
		{
			fread(buf,50,1,fp10);	
		}

	}
	fclose(fp10);
	
		printf("Decrypted text is:");
  		printf("%s\n", buf);
		exit(0);
}


//http://stackoverflow.com/questions/10391610/issues-with-encrypting-a-file-using-openssl-evp-apiaes256cbc
