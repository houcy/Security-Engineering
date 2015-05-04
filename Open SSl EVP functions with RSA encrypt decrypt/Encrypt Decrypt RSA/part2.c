#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#define MAX_DATA_LIMIT 400

unsigned char retrieved_random_number[100];
unsigned char retrieved_message_hash[21];
unsigned char ciphertext[500];
unsigned char random_number[100];
int random_number_length = 0;
char output_filename[100];
FILE *fileptr;


/**************function definitions*************/
int calc_HMAC(char *key, unsigned char message[], unsigned char *result, int messageLength);
int calc_HMAC1(char *key, unsigned char message[], unsigned char *result, int messageLength);
void startEncryption(void);
void start_program();
void input_to_file(unsigned char *encrypted_message, int messageLength, unsigned char *rsa_hash, int hashLength, char *newFilename);
int AES_ENCRYPTION(unsigned char *password, unsigned char *plaintext, unsigned char *ciphertext);
void AES_DECRYPTION(unsigned char *plaintext,unsigned char *password, unsigned char *ciphertext, int ciphertext_len);
/**************function definitions*************/


void start_program()
{
	/* Initialise the library */
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_config(NULL);
  startEncryption();
}



/*Make things visible and store in file*/
void readable1(char *str)
{
	FILE *try;
	try = fopen("hmac_enc","w+");
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


/*Make things visible and store in file*/
void readable2(char *str)
{
	FILE *try;
	try = fopen("hmac_enc_later","w+");
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




int main(int argc, char *argv[])
{	  
  if(argc != 3)
  {
    printf("Too few Parameters Given\n");
    printf("Usage is : ./encrypt_file_rsa |random-number-file| |output-filename-address|\n");
    //printf("[random-number]: The file containing the random number\n");
    //printf("[output_filename]: absolute/relative path of the output file with file extension\n");
    exit(0);
  }  
  else
  {
    FILE *fp = fopen(argv[1],"r");
    fscanf(fp,"%s",random_number);
    random_number_length = strlen(random_number);
    if(0 == random_number_length)
    {
      printf("Error reading random number\n");
      exit(0);
    }
    fclose(fp);
    strcpy(output_filename, argv[2]);
    //printf("Filename is : %s\n", output_filename);
  }
  start_program();
  return 0;
}

int calc_HMAC(char *key, unsigned char message[], unsigned char *result, int messageLength)
{
	unsigned char data[200];
	strcpy(data,message);

	unsigned int len = 20;
	unsigned char tmpresult[21];

	HMAC_CTX ctx;
  HMAC_CTX_init(&ctx);
  
  // Using sha1 hash engine here.
  // You may use other hash engines. e.g EVP_md5(), EVP_sha224, EVP_sha512, etc
  HMAC_Init_ex(&ctx, key, strlen(key), EVP_sha1(), NULL);
  HMAC_Update(&ctx, (unsigned char*)&data, strlen(data));
  HMAC_Final(&ctx, tmpresult, &len);
  HMAC_CTX_cleanup(&ctx);
  HMAC_cleanup(&ctx);
  strcpy(result,tmpresult);    

	return 0;
}


//2nd check of HMAC
int calc_HMAC1(char *key, unsigned char message[], unsigned char *result, int messageLength)
{
	unsigned char data[200];
	strcpy(data,message);

	unsigned int len = 20;
	unsigned char tmpresult[21];

	HMAC_CTX ctx;
  HMAC_CTX_init(&ctx);
  
  // Using sha1 hash engine here.
  // You may use other hash engines. e.g EVP_md5(), EVP_sha224, EVP_sha512, etc
  HMAC_Init_ex(&ctx, key, strlen(key), EVP_sha1(), NULL);
  HMAC_Update(&ctx, (unsigned char*)&data, strlen(data));
  HMAC_Final(&ctx, tmpresult, &len);
  HMAC_CTX_cleanup(&ctx);
  HMAC_cleanup(&ctx);
  strcpy(result,tmpresult);    

	return 0;
}




unsigned char *generateSalt(char *key)
{
	unsigned char *result = (unsigned char *)malloc(sizeof(char)*20);
	//calculate hmac(PassPhrase)  	
	calc_HMAC(key, key, result, strlen(key));
  //calculate hmac(hmac(PassPhrase))
  calc_HMAC(key,result,result,strlen(key));  

  return result;	    
}

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Generate Key and IV ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
void generateKeyIV(unsigned char *password, unsigned char *key, unsigned char *iv)
{  
  unsigned char *salthash = (unsigned char *)malloc(sizeof(unsigned char)*20);
  strcpy(salthash, generateSalt(password));
  /*printf("salt calculated in generateKeyIV is : ");
  for (int i = 0; i != 20; i++)
    printf("%02x", (unsigned int)salthash[i]);
  printf("\n");*/

  unsigned char salt[9];
  for (int i = 0; i < 9; i++)
  {
    salt[i] = salthash[i];     
  }
  salt[9] = '\0';

  const EVP_CIPHER *cipherType;
  
  cipherType = EVP_aes_256_cbc();
  if(!cipherType) 
  { 
    printf("cipher aes 256 not found by name\n"); 
    exit(0); 
  }

  const EVP_MD *digestType = NULL;    
  
  digestType = EVP_md5();
  if(!digestType)
  { 
    printf("digest md5 not found by name\n"); 
    exit(0);
  }

  
  if(!EVP_BytesToKey(cipherType, digestType, salt, password, strlen(password), 1, key, iv))
  {
    printf("EVP_BytesToKey returned and error\n");
    exit(0);
  }

  /*printf("generated salt in key generation is : ");
  for (int i = 0; i != strlen(salt); i++)
    printf("%02x", (unsigned int)salt[i]);
  printf("\n"); */
}

/**************************** AES Encryption Function ******************************************/
int AES_ENCRYPTION(unsigned char *password, unsigned char *plaintext, unsigned char *ciphertext)
{  
  
	//Generate Key and Iv using salt and password
	unsigned char key[EVP_MAX_KEY_LENGTH + 1], iv[EVP_MAX_IV_LENGTH + 1];    
	generateKeyIV(password,key,iv);
  
/******************************************* openssl Encryption Routines ******************************************/

  EVP_CIPHER_CTX *aesctx;

  /* Create and initialise the context */
  if(!(aesctx = EVP_CIPHER_CTX_new()))
  {
    printf("New CTX could not be initialized\n");
    exit(0);
  } 
  
  if(!EVP_EncryptInit_ex(aesctx, EVP_aes_256_cbc(), NULL, key, iv))
  {
    printf("Encryption initialization failed\n");
    exit(0);
  }  

  int len;  
  int ciphertext_len;  

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(aesctx, ciphertext, &len, plaintext, strlen(plaintext)))
  {
   printf("Encryption of data failed\n");
   exit(0); 
  }      
  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(aesctx, ciphertext + len, &len))
  {
    printf("Encryption finalizing failed\n");
    exit(0);
  }

  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(aesctx);

  /*printf("generated ciphertext is : ");
  for (int i = 0; i != ciphertext_len; i++)
    printf("%02x", (unsigned int)ciphertext[i]);
  printf("\n\n");  */

  return ciphertext_len;
}

/**************************** AES Dcryption Function *******************************************/
void AES_DECRYPTION(unsigned char *plaintext, unsigned char *password, unsigned char *ciphertext,int ciphertext_len)
{
 
  //Generate Key and Iv using salt and password
  unsigned char key[EVP_MAX_KEY_LENGTH + 1], iv[EVP_MAX_IV_LENGTH + 1];    
  generateKeyIV(password,key,iv);

/*^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ openssl Dcryption Routines ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^*/
  EVP_CIPHER_CTX *decryptctx;

  int len;

  int plaintext_len;

  /* Create and initialise the context */
  if(!(decryptctx = EVP_CIPHER_CTX_new())) 
  {
    printf("Initialization of decrypt context failed\n");
    exit(0);
  }    
  
  if(1 != EVP_DecryptInit_ex(decryptctx, EVP_aes_256_cbc(), NULL, key, iv))
  {
    printf("Initialization of decrypt function failed\n");
    exit(0);
  }

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */  
  if(1 != EVP_DecryptUpdate(decryptctx, plaintext, &len, ciphertext, ciphertext_len))
  {
    printf("decryption failed\n");
    exit(0);
  }
  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */  
  if(1 != EVP_DecryptFinal_ex(decryptctx, plaintext + len, &len))
  {
    printf("finalizing failed\n");
    exit(0);
  }
  plaintext_len += len;
  plaintext[plaintext_len] = '\0'; //append null termination for printing
  /* Clean up */
  EVP_CIPHER_CTX_free(decryptctx);
  printf("plaintext is: %s\n", plaintext);  

}

int Public_ENCRYPTION(RSA *keypair, int messageLength, unsigned char *message, unsigned char *rsa_encrypted_message)
{
	// Encrypt the message using public key of reciever  
	int rsa_encrypted_message_length = 0;
  if((rsa_encrypted_message_length = RSA_public_encrypt(messageLength, message,
     rsa_encrypted_message, keypair, RSA_PKCS1_OAEP_PADDING)) == -1)
  {      
    printf("Error encrypting message\n");
  	exit(0);
  }
  return rsa_encrypted_message_length;
}

void Private_DECRYPTION(RSA *keypair, int messageLength, unsigned char *message, unsigned char *rsa_decrypted_message)
{
	if(RSA_private_decrypt(messageLength, message, rsa_decrypted_message,
  	 keypair, RSA_PKCS1_OAEP_PADDING) == -1)
  {
   	printf("Error encrypting message\n");
   	exit(0);  
  }  
}

void retrieve_hashes(unsigned char *rsa_decrypted_message, int messageLength, unsigned char *retrieved_random_number, unsigned char *retrieved_message_hash)
{
	
  int i=0;
  for(int k = 20;k!=messageLength;i++,k++)
  {
  	retrieved_random_number[i] = (unsigned char)rsa_decrypted_message[k];
  	//printf("%02x", (unsigned int)rsa_decrypted_message[k]);
  }
  retrieved_random_number[i] = '\0';
  //printf("=> %s",retrieved_random_number);
  //printf("\n");  
  
  for(int i = 0;i!=20;i++)
  {
  	retrieved_message_hash[i] = (unsigned char)rsa_decrypted_message[i];
  	//printf("%02x", (unsigned int)rsa_decrypted_message[k]);
  }
  retrieved_message_hash[20] = '\0';    
}

bool verifyIntegrity(unsigned char *retrieved_message_hash, unsigned char *rand_num, unsigned char *message, unsigned char *password)
{
	unsigned char *hash_random_num = (unsigned char *)malloc(sizeof(unsigned char)*20);
  calc_HMAC(password, rand_num, hash_random_num, strlen(rand_num));
  //printf("/*********** Generating the HMAC *************/\n");
  printf("H(x) | HMAC is : ");
  for (int i = 0; i != 20; i++)
    printf("%02x", (unsigned int)hash_random_num[i]);
  printf("\n");
  
  unsigned char ciphertext[500];
  int ciphertext_len = 0;
  ciphertext_len = AES_ENCRYPTION(hash_random_num, message, ciphertext);

  /***********encrypting the HMAC using AES symmetric key*************/
  //printf("/***********Encrypting the HMAC using AES symmetric key*************/\n");
  printf("E(m) using k is : ");
  for (int i = 0; i != ciphertext_len; i++)
    printf("%02x", (unsigned int)ciphertext[i]);
  printf("\n");

  unsigned char hash_message[121];//20 + 100 + 1
  calc_HMAC(password, message, hash_message, strlen(message));
  
  for (int i = 0; i != 20; i++)
    if (retrieved_message_hash[i] != hash_message[i]){
	printf("retrieved_message_hash --> %x\n",retrieved_message_hash[i]);
	printf("message_hash --> %x\n",hash_message[i]);
    	return false;

	}    
  return true;
}


void input_to_file(unsigned char *encrypted_message, int messageLength, unsigned char *rsa_hash, int hashLength, char *newFilename)
{  
  //printf("Filename is : %s\n", newFilename);  
  fileptr = fopen(newFilename,"w+");   
  
  int *rsa_len_ptr = (int *)malloc(sizeof(int));
  rsa_len_ptr = &hashLength;
  fwrite(rsa_len_ptr, sizeof(int), 1, fileptr);
  fwrite(rsa_hash, sizeof(unsigned char), hashLength, fileptr);

  int *ciphertext_len_ptr = (int *)malloc(sizeof(int));
  ciphertext_len_ptr = &messageLength;  
  fwrite(ciphertext_len_ptr, sizeof(int), 1, fileptr);
  fwrite(encrypted_message, sizeof(unsigned char), messageLength, fileptr);
  fclose(fileptr);


  //printf("file read started\n");
  fileptr = fopen(newFilename,"r");


  unsigned char tmp_hash[400], tmp_ciphertext[400];
  fread(rsa_len_ptr, sizeof(int), 1, fileptr);
  fread(tmp_hash, sizeof(unsigned char), hashLength, fileptr);
  fread(ciphertext_len_ptr, sizeof(int), 1, fileptr);
  
  fread(tmp_ciphertext, sizeof(unsigned char), messageLength, fileptr);
  /*printf("Read rsa hash from file is : ");  
  for (int i = 0; i != hashLength; i++)
    printf("%02x", (unsigned int)tmp_hash[i]);
  printf("\n\n"); 

  printf("Read ciphertext from file is : ");
  for (int i = 0; i != messageLength; i++)
    printf("%02x", (unsigned int)tmp_ciphertext[i]);
  printf("\n\n");
  
  /*
  printf("Enter PassPhrase for decryption : ");
  scanf("%s",PassPhrase);  
  printf("Password for decryption is : %s\n", PassPhrase);
  unsigned char decrypted_plaintext[500];
  AES_DECRYPTION(decrypted_plaintext,PassPhrase,ciphertext,ciphertext_len);
  */
}


void writeRSAtoFile(RSA *keypair)
{
	FILE *fp = fopen("RSA.txt", "w+");

	int rsaLength = RSA_size(keypair);
	int *size_ptr = (int *)malloc(sizeof(int));
	size_ptr = &rsaLength;
	fwrite(size_ptr, sizeof(int), 1, fileptr);	
	fwrite(keypair, sizeof(rsaLength), 1, fileptr);
	fclose(fp);
}


void startEncryption(void)
{
  printf("Random number read is : %s\n", random_number);  
  printf("Please enter PassPhrase : ");
  char PassPhrase[50];
  scanf("%s",PassPhrase);
  unsigned char *hash_random_num = (unsigned char *)malloc(sizeof(unsigned char)*20);
  calc_HMAC(PassPhrase, random_number, hash_random_num, random_number_length);
  printf("H(x) is : ");
  for (int i = 0; i != 20; i++)
    printf("%02x", (unsigned int)hash_random_num[i]);
  printf("\n");

  unsigned char plaintext[MAX_DATA_LIMIT];
  memset(plaintext,'\0',MAX_DATA_LIMIT);
  FILE *fp = fopen(output_filename,"r");  
  fgets(plaintext,MAX_DATA_LIMIT-1,fp);
  plaintext[strlen(plaintext)-1] = '\0';  
  printf("Message read is : %s\n\n", plaintext);
  fclose(fp);
  //unsigned char ciphertext[500];	//moved to global
  int ciphertext_len = 0;
  ciphertext_len = AES_ENCRYPTION(hash_random_num, plaintext, ciphertext);

  printf("E(m) using k is : ");
  for (int i = 0; i != ciphertext_len; i++)
    printf("%02x", (unsigned int)ciphertext[i]);
  printf("\n");

  unsigned char hash_message[121];//20 + 100 + 1
  calc_HMAC(PassPhrase, plaintext, hash_message, strlen(plaintext));
  strcat(hash_message,random_number);
  printf("H(m) || x is : ");
  for (int i = 0; i != (20+random_number_length); i++)
    printf("%02x", (unsigned int)hash_message[i]);
  printf("\n\n");
  /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ RSA Routines ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
 //RSA Encryption
  
  printf("/***********Generating RSA key 2048 bits*************/\n");	
  RSA *keypair = RSA_generate_key(2048, 3, NULL, NULL);
  unsigned char *rsa_encrypted_message = malloc(RSA_size(keypair));
  int rsa_encrypted_message_length = Public_ENCRYPTION(keypair,(20+random_number_length),hash_message, rsa_encrypted_message);  
  printf("[H(m) || x]^e is : ");
  for (int i = 0; i != rsa_encrypted_message_length; i++)
    printf("%02x", (unsigned int)rsa_encrypted_message[i]);
  printf("\n");  

  char encryptedFilename[120];
  strcpy(encryptedFilename,"enc_");
  strcat(encryptedFilename,output_filename);
  input_to_file(ciphertext, ciphertext_len, rsa_encrypted_message, rsa_encrypted_message_length,encryptedFilename);
  writeRSAtoFile(keypair);


  //RSA decryption
  unsigned char *rsa_decrypted_message = malloc(RSA_size(keypair));
  Private_DECRYPTION(keypair, rsa_encrypted_message_length, rsa_encrypted_message, rsa_decrypted_message);
  
  printf("\n\n[[H(m) || x]^e]^d is : ");
  for (int i = 0; i != (20+random_number_length); i++)
    printf("%02x", (unsigned int)rsa_decrypted_message[i]);
  printf("\n");  
  
  /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

  //++++++++++moved two variables to global++++++++++//
  
  retrieve_hashes(rsa_decrypted_message, (20+random_number_length), retrieved_random_number, retrieved_message_hash);

  /*printf("\n\nretrieved H(m) is : ");
  for (int i = 0; i != 20; i++)
    printf("%02x", (unsigned int)retrieved_message_hash[i]);
  printf("\n");   
	*/
  


	/***********************************************************/
	readable1(ciphertext);	//hmac of the enc file
	/***********************************************************/



  printf("Enter PassPhrase for Decryption : ");
  scanf("%s",PassPhrase);
  //decryption of ciphertext
  unsigned char *decryption_key = (unsigned char *)malloc(sizeof(unsigned char)*20);
  calc_HMAC(PassPhrase, random_number, decryption_key, random_number_length);
  unsigned char decrypted_plaintext[500];  
  AES_DECRYPTION(decrypted_plaintext,decryption_key,ciphertext,ciphertext_len);

  int i,flag_rand_ok=0;
  
  if(verifyIntegrity(retrieved_message_hash, retrieved_random_number, decrypted_plaintext, PassPhrase))
  {
  	
	/*for(i=0;i<100;i++)
  	{
     		if(retrieved_random_number[i]==random_number[i])
     		{
			printf("Comapring %x to %x\n",retrieved_random_number[i],random_number[i]);
			flag_rand_ok=1;
			//break;
		}
		
  	}  
	printf("Equal = 0 else 1 : flag_rand_ok : %d\n",flag_rand_ok); */
	
	/*printf("Random number earlier --> ");
	for(i=0;i<strlen(random_number);i++)
	printf("%x",random_number[i]);
	printf("\n");*/
	
	char temp_buff[100];
	FILE *r = fopen("random.txt","r+");
	if(r == NULL)
	{
		printf("Something went wrong in file reopening.\n");
		fclose(r);
		exit(1);
	}
	else
   	{
		//fread(temp_buff,100,1,r);
		fgets(temp_buff,100,r);
	}
	fclose(r);
		
	/*printf("Random number now --> ");
	for(i=0;i<strlen(temp_buff);i++)
	printf("%x",temp_buff[i]);
	printf("\n");*/
	

	/******************intergrity verification on random file # text******************/
	int qa=0;
	for(qa=0;qa<strlen(random_number);qa++)
  	{
     		if(temp_buff[qa]==random_number[qa])
     		{
			//printf("Comapring %x to %x\n",temp_buff[qa],random_number[qa]);
			//printf("Not Equal\n");
			
			//break;
		}
		else
		{
			flag_rand_ok++;	// flag here will be 1 if integrity fails.
			break;
		}
		
  	}  
	
	//printf("FLag -->%d\n",flag_rand_ok);
	if(flag_rand_ok)
	printf("Integrity check fail in reading | random # file |\n"); 
	
	/****************************************************************/

	/******************intergrity verification on enc_file******************/
	
	char temp_buff1[100];
	FILE *r1 = fopen("enc_test","rb+");
	if(r1 == NULL)
	{
		printf("Something went wrong in file reopening.\n");
		fclose(r1);
		exit(1);
	}
	else
   	{
		fread(temp_buff1,100,1,r1);
		//fgets(temp_buff,100,r);
	}
	fclose(r1);
		
	int ja=0;
	for(ja=0;ja<strlen(temp_buff);ja++)
	//printf("%x",temp_buff1[ja]);
	readable2(temp_buff1);

	
	//reading two HMAC's now to compare.
		
	char temp_buff2[100];
	FILE *r2 = fopen("hmac_enc","rb+");
	if(r2 == NULL)
	{
		printf("Something went wrong in file reopening.\n");
		fclose(r2);
		exit(1);
	}
	else
   	{
		fread(temp_buff2,100,1,r2);
		//fgets(temp_buff,100,r);
	}
	fclose(r2);


	char temp_buff3[100];
	FILE *r3 = fopen("hmac_enc_later","rb+");
	if(r3 == NULL)
	{
		printf("Something went wrong in file reopening.\n");
		fclose(r3);
		exit(1);
	}
	else
   	{
		//fread(temp_buff3,100,1,r3);
		fgets(temp_buff3,100,r3);
	}
	fclose(r3);	


	int la = 0;
	int flag_con_ok = 0;

	for(la=0;la<strlen(temp_buff2);la++)
  	{
     		if(temp_buff3[la]==temp_buff2[la])
     		{
			//printf("Comapring %02x to %02x\n",temp_buff2[la],temp_buff3[la]);
			//printf("Not Equal\n");
			//break;
		}
		else
		{
			flag_con_ok++;	// flag here will be 1 if integrity fails.
			//break;
		}
		
  	}

	//printf("Flag_con_ok : %d\n",flag_con_ok);
	if(flag_con_ok != 65)
	printf("Integrity of encrypted file is not okay!\n");
	
	
	/****************************************************************/


	//decide whether to print or not this text.
	if(flag_rand_ok == 0 && flag_con_ok == 65)
	printf("Decrypted Text is : %s\n", decrypted_plaintext);
	else
	{
		printf("/****************************************************************/\n");
		printf("                . . . No decryption allowed . . .                 \n");
		printf("/****************************************************************/\n");
		///eN0yq96h1i4x8tq28oOL1J+quL/fw==
	}
	



  }
  else
  {
  	printf("Hash doesn't match\n");
  }
}
