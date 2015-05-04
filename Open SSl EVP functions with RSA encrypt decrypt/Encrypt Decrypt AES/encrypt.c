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



/*Make things visible and store in file*/
void readable(char *str)
{
	FILE *try;
	try = fopen("temp_base64","w+");
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



/******Calculating HMAC of non encrypted data*******/
calc_hmac(char *str1,char *key)
{
	
    	int i; 
	char temp[128];
	strncpy(temp,str1,128);
    
   
    // Be careful of the length of string with the choosen hash engine. SHA1 needed 20 characters.
    // Change the length accordingly with your choosen hash engine.    
    unsigned char *result;
    unsigned int len = 20;
    //unsigned int len = 128;	

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

    for (i = 0; i != len; i++)
        final_result[i]=result[i];	
 
    	printf("\n");
 	free(result);
}

/****************************/



/************Encrypt Engine***************/
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len;

  /* Create and initialise the context */
  	if(!(ctx = EVP_CIPHER_CTX_new()))
	{ 
		printf("Error in context initialization step 1!");
		exit(0);
	}
  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    	{ 
		printf("Error in context initialization step 2!");
		exit(0);
	}

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
	{ 
		printf("Error in context initialization step 3!");
		exit(0);
	}
    
  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) 
	{ 
		printf("Error in context initialization step 4!");
		exit(0);
	}
  
	ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);
  printf("Len is : %d",ciphertext_len);
  return ciphertext_len;
}

/*****************************************/





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
	
	
	//now generating key and IV
	if(aes_init(passphrase,passphrase_len,(unsigned char*) salt,&en,&de))     /* Generating Key IV and initializing the EVP struct */
	{
    		perror("\n Error, Cant initialize key and IV:");
    		return -1;
	}
	
	//creating plain text file --> user gives the content.
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
	printf("File |plaintext| created!\n");
	fclose(fp);		//very vital !!!!
	

	//calculating the HMAC of file.
	//calc_hmac(data,key);
	
	

	//encrypting the plaintext contents.

	p=fopen("plaintext","r");
	if(p == NULL)
	{
		printf("Unable to open file.");
		exit(1);
	}
	else
	{
		do
		{
			fgets(ne_fc,200,p);
			//printf("%s",ne_fc);
			
		}while(!feof(p));
		
	}
	
	fclose(p);

	//printf("Data from file : %s\n",ne_fc);

	//Encrypt the contents now

	ciphertext_len = encrypt(ne_fc, strlen(ne_fc), key, iv,ciphertext);	
	
	//Display the encrypted content
	//printf("CipherText in base64 encoding :");
	//readable(ciphertext);

	//Storing the encrypted data to file
	FILE *fp1;
	fp1 = fopen("ciphertext","w+");
	if (fp1)
	{
    		fwrite(ciphertext,128, 1, fp1);
    		
	}
	else
	{
    		puts("Something wrong in writing ciphertext to file.\n");
		fclose(fp1);
		exit(0);
	}
	printf("File |ciphertext| created!\n");
	fclose(fp1);
	
	//HMAC of encrypted content from the file
	//calc_hmac(ciphertext,key);
	
	FILE *q;
	unsigned char e_fc[128];
	q=fopen("ciphertext","rb");
	if(q == NULL)
	{
		printf("Unable to open file.");
		exit(1);
	}
	else
	{
		do
		{
			fread(e_fc,128,1,q);
		}while(!feof(q));
		
	}
	
	fclose(q);

	//readable(e_fc);
	//printf("Digest of cipher from the file: ");
	//calc_hmac(e_fc,key);
	//printf("CipherText from file in base64 encoding :");
	readable(e_fc);

	
	//get the base64 encoded of ciphertext.
	FILE *p1;
	unsigned char base64[200];
	p1=fopen("temp_base64","r");
	if(p1 == NULL)
	{
		printf("Unable to open file.");
		exit(1);
	}
	else
	{
		do
		{
			fgets(base64,200,p1);
			//printf("%s",ne_fc);
			
		}while(!feof(p1));
		
	}
	
	fclose(p1);

	
	//Storing the SALT 
	FILE *fp2;
	fp2 = fopen("salt","w+");
	if (fp2)
	{
    		fprintf(fp,"%s",salt);
		
	}
	else
	{
    		puts("Something wrong in writing details.\n");
		fclose(fp2);
		exit(0);
	}
	printf("File |salt| created!\n");
	fclose(fp2);
	

	//Storing the Base64 of cipher
	FILE *fp6;
	fp6 = fopen("hmac","w+");
	if (fp6)
	{
    		fprintf(fp6,"%s",base64);
	}
	else
	{
    		puts("Something wrong in writing details.\n");
		fclose(fp6);
		exit(0);
	}
	printf("File |hmac| created!\n");
	fclose(fp6);	

 
	
	EVP_CIPHER_CTX_cleanup(&en);
	EVP_CIPHER_CTX_cleanup(&de);
	return 0;
}



//http://stackoverflow.com/questions/10391610/issues-with-encrypting-a-file-using-openssl-evp-apiaes256cbc
