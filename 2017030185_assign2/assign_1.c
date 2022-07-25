#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/cmac.h>

#define BLOCK_SIZE 16


/* function prototypes */
void print_hex(unsigned char *, size_t);
void print_string(unsigned char *, size_t); 
void usage(void);
void check_args(char *, char *, unsigned char *, int, int);
void keygen(unsigned char *, unsigned char *, unsigned char *, int);
int encrypt(unsigned char *, int, unsigned char *, unsigned char *, 
    unsigned char *, int );
int decrypt(unsigned char *, int, unsigned char *, unsigned char *, 
    unsigned char *, int);
void gen_cmac(unsigned char *, size_t, unsigned char *, unsigned char *, int);
int verify_cmac(unsigned char *, unsigned char *);



/* TODO Declare your function prototypes here... */




/*
 * Prints the hex value of the input
 * 16 values per line
 */
void
print_hex(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++) {
			if (!(i % 16) && (i != 0))
				printf("\n");
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}


/*
 * Prints the input as string
 */
void
print_string(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++)
			printf("%c", data[i]);
		printf("\n");
	}
}


/*
 * Prints the usage message
 * Describe the usage of the new arguments you introduce
 */
void
usage(void)
{
	printf(
	    "\n"
	    "Usage:\n"
	    "    assign_1 -i in_file -o out_file -p passwd -b bits" 
	        " [-d | -e | -s | -v]\n"
	    "    assign_1 -h\n"
	);
	printf(
	    "\n"
	    "Options:\n"
	    " -i    path    Path to input file\n"
	    " -o    path    Path to output file\n"
	    " -p    psswd   Password for key generation\n"
	    " -b    bits    Bit mode (128 or 256 only)\n"
	    " -d            Decrypt input and store results to output\n"
	    " -e            Encrypt input and store results to output\n"
	    " -s            Encrypt+sign input and store results to output\n"
	    " -v            Decrypt+verify input and store results to output\n"
	    " -h            This help message\n"
	);
	exit(EXIT_FAILURE);
}


/*
 * Checks the validity of the arguments
 * Check the new arguments you introduce
 */
void
check_args(char *input_file, char *output_file, unsigned char *password, 
    int bit_mode, int op_mode)
{
	if (!input_file) {
		printf("Error: No input file!\n");
		usage();
	}

	if (!output_file) {
		printf("Error: No output file!\n");
		usage();
	}

	if (!password) {
		printf("Error: No user key!\n");
		usage();
	}

	if ((bit_mode != 128) && (bit_mode != 256)) {
		printf("Error: Bit Mode <%d> is invalid!\n", bit_mode);
		usage();
	}

	if (op_mode == -1) {
		printf("Error: No mode\n");
		usage();
	}
}


/*
 * Generates a key using a password
 */
void
keygen(unsigned char *password, unsigned char *key, unsigned char *iv,
    int bit_mode)
{	
	
	//printf("%d\n",strlen(password) );
	
	if (bit_mode==256) 

		EVP_BytesToKey(EVP_aes_256_ecb(),EVP_sha1(),NULL,(unsigned char *) password,strlen(password),1,key,iv);
	else 	
		EVP_BytesToKey(EVP_aes_128_ecb(),EVP_sha1(),NULL,(unsigned char *) password,strlen(password),1,key,iv);
		

	
}





/*
 * Encrypts the data
 */
int
encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
    unsigned char *iv, unsigned char *ciphertext, int bit_mode)
{
	EVP_CIPHER_CTX *ctx;
	int len=0;
	int ciphertext_len=0;

	/* Create and initialise the context */
	ctx = EVP_CIPHER_CTX_new();

	if (bit_mode==256){
		
		/* Initialise the encryption operation. IMPORTANT - ensure you use a key
   		* In this example we are using 256 bit AES (i.e. a 256 bit key). 
  		*/
  		EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key,iv);
    	

  		/* Provide the message to be encrypted, and obtain the encrypted output.
   		* EVP_EncryptUpdate can be called multiple times if necessary
   		*/
  		EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, plaintext_len);
    		
  			//ciphertext_len = len;

  		/* Finalise the encryption. Further ciphertext bytes may be written at
   		* this stage.
   		*/
  		EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len);
  		ciphertext_len += len;
	
	}else{

		/* Initialise the encryption operation. IMPORTANT - ensure you use a key
   		* In this example we are using 256 bit AES (i.e. a 256 bit key). 
  		*/
  		EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key,iv);
    	

  		/* Provide the message to be encrypted, and obtain the encrypted output.
   		* EVP_EncryptUpdate can be called multiple times if necessary
   		*/
  		EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, plaintext_len);
    		
  			//ciphertext_len = len;

  		/* Finalise the encryption. Further ciphertext bytes may be written at
   		* this stage.
   		*/
  		EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len);
 		ciphertext_len += len;

	}
	
	//printf("%d\n", ciphertext_len);
	 /* Clean up */
  	 EVP_CIPHER_CTX_free(ctx);

  	 return ciphertext_len;
  	
	

}


/*
 * Decrypts the data and returns the plaintext size
 */
int
decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
    unsigned char *iv, unsigned char *plaintext, int bit_mode)
{
  

  EVP_CIPHER_CTX *ctx;

  int len=0;

  int plaintext_len=0;

  /* Create and initialise the context */
  ctx = EVP_CIPHER_CTX_new();


  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */

  if (bit_mode==256){
	  
	    EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, iv);
	    
		/* Provide the message to be decrypted, and obtain the plaintext output.
	   * EVP_DecryptUpdate can be called multiple times if necessary
	   */
	    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
	    //handleErrors();
	  //plaintext_len = len;

	  /* Finalise the decryption. Further plaintext bytes may be written at
	   * this stage.
	   */
	  EVP_DecryptFinal_ex(ctx, plaintext + len, &plaintext_len);
	  	//handleErrors();

	  len += plaintext_len;
	  plaintext_len=len;

	  
  }else{
	  	EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv);
	    
		/* Provide the message to be decrypted, and obtain the plaintext output.
	   * EVP_DecryptUpdate can be called multiple times if necessary
	   */
	    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
	    //handleErrors();
	  //plaintext_len = len;

	  /* Finalise the decryption. Further plaintext bytes may be written at
	   * this stage.
	   */
	   EVP_DecryptFinal_ex(ctx, plaintext + len, &plaintext_len);
	  len += plaintext_len;
	  plaintext_len=len;
  }
  
  
/* Clean up */
	  EVP_CIPHER_CTX_free(ctx);
  return plaintext_len;
}


/*
 * Generates a CMAC
 */
void
gen_cmac(unsigned char *data, size_t data_len, unsigned char *key, 
    unsigned char *cmac, int bit_mode)
{
  size_t len;

  CMAC_CTX *ctx = CMAC_CTX_new();
  if (bit_mode==256){
  	CMAC_Init(ctx, key, 16, EVP_aes_256_ecb(), NULL);
  	CMAC_Update(ctx, data, data_len);
  	CMAC_Final(ctx, cmac, &len);
  }else{
  	CMAC_Init(ctx, key, 16, EVP_aes_128_ecb(), NULL);
  	CMAC_Update(ctx, data, data_len);
  	CMAC_Final(ctx, cmac, &len);
  //printf("%d\n",len);
  //printf("CMAC CREATED :\n");
  //print_hex(cmac, len);
}
  CMAC_CTX_free(ctx);



}


/*
 * Verifies a CMAC
 */
int
verify_cmac(unsigned char *cmac1, unsigned char *cmac2)
{
	int verify;

	verify = 0;

	if (strcmp(cmac1,cmac2) == 0)
		verify =1;
		

	return verify;
}



/* TODO Develop your functions here... */



/*
 * Encrypts the input file and stores the ciphertext to the output file
 *
 * Decrypts the input file and stores the plaintext to the output file
 *
 * Encrypts and signs the input file and stores the ciphertext concatenated with 
 * the CMAC to the output file
 *
 * Decrypts and verifies the input file and stores the plaintext to the output
 * file
 */
int
main(int argc, char **argv)
{
	int opt;			/* used for command line arguments */
	int bit_mode;			/* defines the key-size 128 or 256 */
	int op_mode;			/* operation mode */
	char *input_file;		/* path to the input file */
	char *output_file;		/* path to the output file */
	unsigned char *password;	/* the user defined password */
	unsigned char *key; 
	unsigned char *iv;
	size_t size_cmac;
	FILE *fptr;
	FILE *fptr1;
	unsigned char cmac[16];
	unsigned char cmac2[16];
	unsigned char cmac3[16];
	int *lenght2;
	//nsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
	unsigned char plaintext[2048], ciphertext[2048];
	int len;
	int i;
	/* Init arguments */
	input_file = NULL;
	output_file = NULL;
	password = NULL;
	bit_mode = -1;
	op_mode = -1;
	key = (unsigned char *) malloc(200 * sizeof(unsigned char));

	/*
	 * Get arguments
	 */
	while ((opt = getopt(argc, argv, "b:i:m:o:p:desvh:")) != -1) {
		switch (opt) {
		case 'b':
			bit_mode = atoi(optarg);
			break;
		case 'i':
			input_file = strdup(optarg);
			break;
		case 'o':
			output_file = strdup(optarg);
			break;
		case 'p':
			password = (unsigned char *)strdup(optarg);
			break;
		case 'd':
			/* if op_mode == 1 the tool decrypts */
			op_mode = 1;
			break;
		case 'e':
			/* if op_mode == 1 the tool encrypts */
			op_mode = 0;
			break;
		case 's':
			/* if op_mode == 1 the tool signs */
			op_mode = 2;
			break;
		case 'v':
			/* if op_mode == 1 the tool verifies */
			op_mode = 3;
			break;
		case 'h':
		default:
			usage();
		}
	}


	
	/* check arguments */
	check_args(input_file, output_file, password, bit_mode, op_mode);



	/* TODO Develop the logic of your tool here... */

	if(op_mode == 1){
		fptr=fopen(input_file,"rb");
		fseek(fptr, 0, SEEK_END);
    	int size = ftell(fptr);
    	rewind(fptr);
   	 	fread(ciphertext, 1, size, fptr);
		keygen(password,key,iv,op_mode);
		len = decrypt(ciphertext,size,key,iv,plaintext,bit_mode);
		fptr1=fopen(output_file,"wb");
		fwrite(plaintext, 1, len, fptr1);
		fclose(fptr);
		fclose(fptr1);
	}

	if(op_mode==0){
		int length;
		fptr=fopen(input_file,"rb");
		fseek(fptr, 0, SEEK_END);
    	int size = ftell(fptr);
    	rewind(fptr);
    	fread(plaintext, 1, size, fptr);
		keygen(password,key,iv,op_mode);
		int lenght = encrypt(plaintext,size,key,iv,ciphertext,bit_mode);
		fptr1=fopen(output_file,"wb");
		fwrite(ciphertext, 1, lenght, fptr1);
		fclose(fptr);
		fclose(fptr1);

	}

	if(op_mode==2){																																																																																							
		fptr=fopen(input_file,"r");
		fseek(fptr, 0, SEEK_END);
    	int size = ftell(fptr);
    	rewind(fptr);
    	fread(plaintext, 1, size, fptr);
		keygen(password,key,iv,op_mode);
		gen_cmac(plaintext,strlen(plaintext)-1,key, cmac,bit_mode);
		int s = encrypt(plaintext,size,key,iv,ciphertext,bit_mode); 
		fclose(fptr);
		//printf("%d\n", s);
		fptr1=fopen(output_file,"wb");
		//print_hex(cmac,strlen(cmac));
		fwrite(ciphertext, 1, s, fptr1);
		fwrite(cmac, 1, 16, fptr1);
		fclose(fptr);
	}

	if (op_mode==3){
		
		fptr=fopen(input_file,"rb");
		fseek(fptr, 0, SEEK_END);
    	int size = ftell(fptr);
    	rewind(fptr);
    	size=size-16;
   	 	fread(ciphertext, 1, size, fptr);
		keygen(password,key,iv,op_mode);
		int len = decrypt(ciphertext,size,key,iv,plaintext,bit_mode);
		fread(cmac3, 1, 16, fptr);
		gen_cmac(plaintext,len,key, cmac2,bit_mode);
		char* cmac4=malloc(16);
		char* cmac5=malloc(16);
    	strncpy(cmac4,cmac3,16);
		strncpy(cmac5,cmac2,16);	
		int result = verify_cmac(cmac4,cmac5);
		printf("%d\n", result );
 		fclose(fptr);
 		fptr1=fopen(output_file,"wb");
		fputs(result,fptr1);
		fclose(fptr);

	}

	free(input_file);
	free(output_file);
	free(password);


	/* END */
	return 0;
}
