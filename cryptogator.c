#include <stdio.h>
#include <gcrypt.h>
#include <time.h>
#include <string.h>

//clock_t begin, end;
//double time_spent;

//begin = clock();
//*here, do your time-consuming job */
//end = clock();
//time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
    ////////////////////////
    //FUNCTION DEFINITIONS//
    ////////////////////////
    void myMD5(FILE *file,double md5_buffer[],int index);
    void myAES128(FILE *file,double aes128_encbuffer[],double aes128_decbuffer[],int index);
    void mySHA1(FILE *file,double sha1_buffer[],int index);
    unsigned char* mySHA256(FILE *file,double sha256_buffer[],int index);
    void myRSA1024(FILE *file,double rsa1024_encbuffer[],double rsa1024_decbuffer[],int index);
    void myAES256(FILE *file,double aes256_encbuffer[],double aes256_decbuffer[],int index);
    void myDS(FILE *file);
    void myRSA4096(FILE *file,double rsa4096_encbuffer[],double rsa4096_decbuffer[],int index);

    void convertToBuffer(char *buffer,gcry_sexp_t *sexp );
    void convertToSexpression( gcry_sexp_t sexp, char* buffer, int len);
    void prettyPrint( char *input_sexp, int len );
    char* fileToBuffer(FILE *file);
    double getMean(double buffer[],double total);
    double getMedian(double buffer[],double total);

    
int main(int argc, const char * argv[])
{



    ///////////////
    ///OPEN FILE///
    //////////////
    FILE *file;
    file =fopen(argv[1], "rb");
    if (!file)
    {
        printf("file not opened successfully");
        return 1;
    }

    ////////////////////////////
    ///GCRYPT INITIALIZATIONS///
    ////////////////////////////
    gcry_check_version ( NULL );
    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);


    ////////////////////
    ///METHOD CALLS////
    //////////////////
    

    
    

    


    /////////////////////
    //////AES128 TIME////
    ////////////////////
    
    double aes128_encbuffer[100];
    double aes128_decbuffer[100];
    int i;
    printf("\nRUNNING AES 128...\n");
    for( i=0;i<100;i++)
    {
        myAES128(file,aes128_encbuffer,aes128_decbuffer,i);
    }
    double aes128_encmean= getMean(aes128_encbuffer,100.0);
    double aes128_encmedian= getMedian(aes128_encbuffer,100.0);
    double aes128_decmean= getMean(aes128_decbuffer,100.0);
    double aes128_decmedian= getMedian(aes128_decbuffer,100.0);
    printf("\nMEAN TIME FOR AES128 ENCRYPTION IS :%f ms\n", aes128_encmean);
    printf("\nMEDIAN TIME FOR AES128 ENCRYPTION IS :%f ms\n", aes128_encmedian);
    printf("\nMEAN TIME FOR AES128 DECRYPTION IS :%f ms\n", aes128_decmean);
    printf("\nMEDIAN TIME FOR AES128 DECRYPTION IS :%f ms\n", aes128_decmedian);




    /////////////////////
    //////AES256 TIME////
    ////////////////////
    
    double aes256_encbuffer[100];
    double aes256_decbuffer[100];
    printf("\nRUNNING AES 256...\n");
    for( i=0;i<100;i++)
    {
        myAES256(file,aes256_encbuffer,aes256_decbuffer,i);
    }
    double aes256_encmean= getMean(aes256_encbuffer,100.0);
    double aes256_encmedian= getMedian(aes256_encbuffer,100.0);
    double aes256_decmean= getMean(aes256_decbuffer,100.0);
    double aes256_decmedian= getMedian(aes256_decbuffer,100.0);
    printf("\nMEAN TIME FOR AES256 ENCRYPTION IS :%f ms\n", aes256_encmean);
    printf("\nMEDIAN TIME FOR AES256 ENCRYPTION IS :%f ms\n", aes256_encmedian);
    printf("\nMEAN TIME FOR AES256 DECRYPTION IS :%f ms\n", aes256_decmean);
    printf("\nMEDIAN TIME FOR AES256 DECRYPTION IS :%f ms\n", aes256_decmedian);

    


    ///////////////////
    //////MD5 TIME////
    //////////////////
    printf("\nRUNNING MD5...\n");
    double md5_buffer[100];

    for( i=0;i<100;i++)
    {
        myMD5(file,md5_buffer,i);
    }
    //printf("final i : %f",md5_buffer[99] );
    double md5_mean= getMean(md5_buffer,100.0);
    double md5_median= getMedian(md5_buffer,100.0);
    printf("\nMEAN TIME FOR MD5 IS :%f ms\n", md5_mean);
    printf("\nMEDIAN TIME FOR MD5 IS :%f ms\n", md5_median);


    ///////////////////
    //////SHA1 TIME////
    //////////////////
    printf("\nRUNNING SHA 1...\n");
    double sha1_buffer[100];
    for(i=0;i<100;i++)
    {
        mySHA1(file,sha1_buffer,i);
    }
    //printf("final i : %f",md5_buffer[99] );
    double sha1_mean= getMean(sha1_buffer,100.0);
    double sha1_median= getMedian(sha1_buffer,100.0);
    printf("\nMEAN TIME FOR SHA1 IS :%f ms\n", sha1_mean);
    printf("\nMEDIAN TIME FOR SHA1 IS :%f ms\n", sha1_median);


    /////////////////////
    //////SHA256 TIME////
    ////////////////////
    printf("\nRUNNING SHA 256...\n");
    double sha256_buffer[100];
    for( i=0;i<100;i++)
    {
        mySHA256(file,sha256_buffer,i);
    }
    //printf("final i : %f",md5_buffer[99] );
    double sha256_mean= getMean(sha256_buffer,100.0);
    double sha256_median= getMedian(sha256_buffer,100.0);
    printf("\nMEAN TIME FOR SHA256 IS :%f ms\n", sha256_mean);
    printf("\nMEDIAN TIME FOR SHA256 IS :%f ms\n", sha256_median);

    ///////////////////////////////
    ///////DIGITAL SIGNATURE/////////
    ////////////////////////////////

    printf("\nRUNNING RSA 1024...\n");
    double rsa1024_encbuffer[100];
    double rsa1024_decbuffer[100];
    for( i=0;i<100;i++) ////
    {
        myRSA1024(file,rsa1024_encbuffer,rsa1024_decbuffer,i);
    }
    double rsa1024_encmean= getMean(rsa1024_encbuffer,100.0);
    double rsa1024_encmedian= getMedian(rsa1024_encbuffer,100.0);
    double rsa1024_decmean= getMean(rsa1024_decbuffer,100.0);
    double rsa1024_decmedian= getMedian(rsa1024_decbuffer,100.0);
    printf("\nMEAN TIME FOR RSA1024 ENCRYPTION IS :%f ms\n", rsa1024_encmean);
    printf("\nMEDIAN TIME FOR RSA1024 ENCRYPTION IS :%f ms\n", rsa1024_encmedian);
    printf("\nMEAN TIME FOR RSA1024 DECRYPTION IS :%f ms\n", rsa1024_decmean);
    printf("\nMEDIAN TIME FOR RSA1024 DECRYPTION IS :%f ms\n", rsa1024_decmedian);

    

    printf("\nRUNNING RSA 4096...\n");
    double rsa4096_encbuffer[100];
    double rsa4096_decbuffer[100];

    for(i=0;i<100;i++) ////
    {
        myRSA4096(file,rsa4096_encbuffer,rsa4096_decbuffer,i);
    }
    double rsa4096_encmean= getMean(rsa4096_encbuffer,100.0);
    double rsa4096_encmedian= getMedian(rsa4096_encbuffer,100.0);
    double rsa4096_decmean= getMean(rsa4096_decbuffer,100.0);
    double rsa4096_decmedian= getMedian(rsa4096_decbuffer,100.0);
    printf("\nMEAN TIME FOR RSA4096 ENCRYPTION IS :%f ms\n", rsa4096_encmean);
    printf("\nMEDIAN TIME FOR RSA4096 ENCRYPTION IS :%f ms\n", rsa4096_encmedian);
    printf("\nMEAN TIME FOR RSA4096 DECRYPTION IS :%f ms\n", rsa4096_decmean);
    printf("\nMEDIAN TIME FOR RSA4096 DECRYPTION IS :%f ms\n", rsa4096_decmedian);
   

    printf("\nRUNNING DIGITAL SIGNATURE 256...\n");
    myDS(file);

    
    
    
    
    

    
    fclose(file);  
}
    ////////////////////
    ///////DS/////////
    //////////////////

    
void myDS(FILE* file)
{
    double temp[1];
    unsigned char * sha=mySHA256(file,temp,0);
    

    gcry_sexp_t rsatoken_sexp,rsakey_sexp;
    gcry_sexp_t publickey_sexp,privatekey_sexp;
    gcry_sexp_t sha_sexp;
    gcry_sexp_t ds_sexp;
    gcry_error_t err;
    gcry_sexp_t output_sexp;

    char  buffer[6000];

    char* publickeytoken="public-key";
    char* privatekeytoken="private-key";
    char* rsatoken="(genkey (rsa (nbits 4:4096)))";

    err=gcry_sexp_new( &rsatoken_sexp, rsatoken, strlen(rsatoken), 1 );
    if(err)
    {
        printf("error while while generating rsatoken_sexp");
    }

    err=gcry_pk_genkey( &rsakey_sexp, rsatoken_sexp );
    if(err)
    {
        printf("error while while generating rsakey_sexp");
    }

    gcry_sexp_release(rsatoken_sexp);

    publickey_sexp = gcry_sexp_find_token( rsakey_sexp, publickeytoken, 0 );
    if(publickey_sexp==NULL)
    {
        printf("error while extracting public key");
    }
     
    privatekey_sexp = gcry_sexp_find_token( rsakey_sexp, privatekeytoken, 0 );
    if(privatekey_sexp==NULL)
    {
        printf("error while extracting private key");
    }

    gcry_sexp_release(rsakey_sexp);

    //PUBLIC AND PRIVATE KEY GENERATED

    convertToBuffer( sha, &sha_sexp );

    err=gcry_pk_sign (&ds_sexp, sha_sexp, privatekey_sexp);
    convertToSexpression( ds_sexp, buffer, 6000 );
    printf( "\ndigital signature: " );
    prettyPrint( buffer, 6000 );
    printf("the digital signature of sha256 was successfullly created.\n");
    

    err=gcry_pk_verify (ds_sexp, sha_sexp, publickey_sexp);
    if(err==0)
    {
        printf("Sucessfully verfied digital signature!\n");
    }


    
   
}
    //////////////////
    ///////RSA/////////
    //////////////////


 void myRSA1024(FILE *file,double rsa1024_encbuffer[],double rsa1024_decbuffer[],int index)
 {

    clock_t begin_enc, end_enc , begin_dec, end_dec;
    double time_enc,time_dec;
    double total_enc=0.0;
    double total_dec=0.0;

    //char* plaintext=fileToBuffer(fp);
    //printf("%s",plaintext);
    int size=filesize(file);
    //fprintf(file, "%s", "aString");
    //printf("\nfile size is :%d" , size);
    //printf("\n");
    



    char  buffer[6000];
    //output[size+100];

    gcry_sexp_t rsatoken_sexp,rsakey_sexp;
    gcry_sexp_t publickey_sexp,privatekey_sexp;
    gcry_sexp_t input_sexp;
    gcry_sexp_t ciphertext_sexp;
    gcry_sexp_t plaintext_sexp = NULL;
    gcry_error_t err;
    gcry_mpi_t input_mpi;
    int i;


    char* publickeytoken="public-key";
    char* privatekeytoken="private-key";
    

    char* rsatoken="(genkey (rsa (nbits 4:1024)))";
    err=gcry_sexp_new( &rsatoken_sexp, rsatoken, strlen(rsatoken), 1 );
    if(err)
    {
        printf("error while while generating rsatoken_sexp");
    }

    err=gcry_pk_genkey( &rsakey_sexp, rsatoken_sexp );
    if(err)
    {
        printf("error while while generating rsakey_sexp");
    }

    gcry_sexp_release(rsatoken_sexp);

    publickey_sexp = gcry_sexp_find_token( rsakey_sexp, publickeytoken, 0 );
    if(publickey_sexp==NULL)
    {
        printf("error while extracting public key");
    }
     
    privatekey_sexp = gcry_sexp_find_token( rsakey_sexp, privatekeytoken, 0 );
    if(privatekey_sexp==NULL)
    {
        printf("error while extracting private key");
    }

    //convertToSexpression( publickey_sexp, buffer, 6000 );
    //prettyPrint( buffer, 6000 );
    //printf( "Public Key:\n%s\n\n", buffer );

    
    //convertToSexpression( privatekey_sexp, buffer, 6000 );
    //prettyPrint( buffer, 6000 );
    //printf( "Private Key:\n%s\n\n", buffer );



    gcry_sexp_release(rsakey_sexp);
   ///PRIVATE PUBLIC KEY GENERATED

    


    char* source=malloc(64);
    
    char* output=(char *)malloc(sizeof(char)*size);
    gcry_sexp_t source_sexp;
    gcry_sexp_t destination_sexp;
    int ctr;
    if(size%64==0)
    {
         ctr=size/64;
    }
    else
    {
        ctr=(size/64) + 1;
    }
    int counter=0;

    while(ctr>0)
    {
        int numofbyte=fread(source, 1, 64, file);
        //printf("num of bytes read : %d ",numofbyte);
        //printf("\n");
        if(numofbyte<64)
        {
            
            //printf("\n");
            int padding=64 - numofbyte;
            //printf("adding padding of %d bytes.", padding);
            //printf("\n");
            
            for(i=numofbyte;i<padding;i++)
            {
                source[i]="0";
            }
        }
    
        
        
        //printf("iterations left :%d ",ctr);
        //printf("\n");
        convertToBuffer( source, &source_sexp );
        //PRINT SEXP
        //convertToSexpression( source_sexp, buffer, 6000 ); 
        //prettyPrint( buffer, strlen(buffer) );
        //printf( "source: \n%s\n\n", buffer );
        begin_enc=clock();

        err = gcry_pk_encrypt( &destination_sexp, source_sexp, publickey_sexp );
        //convertToSexpression( destination_sexp, buffer, 6000 ); 
        //prettyPrint( buffer, strlen(buffer) );
        //printf( "destination: \n%s\n\n", buffer );
        end_enc=clock();
        time_enc = (double)(end_enc - begin_enc)*1000.0 / CLOCKS_PER_SEC;
        total_enc+=time_enc;

        begin_dec=clock();
        err = gcry_pk_decrypt( &plaintext_sexp, destination_sexp, privatekey_sexp );
        //convertToSexpression( plaintext_sexp, buffer, 6000 ); 
        //prettyPrint( buffer, strlen(buffer) );
        //printf( "plaintext: \n%s\n\n", buffer );
        end_dec=clock();
        time_dec=(double)(end_dec - begin_dec)*1000.0 / CLOCKS_PER_SEC;
        total_dec+=time_dec;

        char* destination=malloc(64);

        //convertToSexpression(destination_sexp,destination,sizeof(destination));
        //size_t s = gcry_sexp_sprint( plaintext_sexp, GCRYSEXP_FMT_DEFAULT, NULL, sizeof(destination) ) ;
        //if(s==0)
        
            //printf("%zu\n", s);

        destination=gcry_sexp_nth_string (plaintext_sexp,0);

        //printf("output is : %s",destination);
        //printf("\n");
        for(i=0;i<64;i++)
        {
            output[counter]=destination[i];
            counter++;
        }

        
        
        ctr--;

        free(destination);
        
        

    }
    rsa1024_encbuffer[index]=total_enc;
    rsa1024_decbuffer[index]=total_dec;
    /*
    printf("output :");
    for(int i=0;i<size;i++)
    {

            printf("%c ",output[i]);
    }
*/
    rewind( file );

    


    
 }



 void myRSA4096(FILE *file,double rsa4096_encbuffer[],double rsa4096_decbuffer[],int index)
 {
    clock_t begin_enc, end_enc , begin_dec, end_dec ;
    double total_enc=0.0;
    double total_dec=0.0;
    double time_enc,time_dec;
    int i;

    //char* plaintext=fileToBuffer(fp);
    //printf("%s",plaintext);
    int size=filesize(file);
    //fprintf(file, "%s", "aString");
    //printf("\nfile size is :%d" , size);
    //printf("\n");
    



    char  buffer[6000];
    //output[size+100];

    gcry_sexp_t rsatoken_sexp,rsakey_sexp;
    gcry_sexp_t publickey_sexp,privatekey_sexp;
    gcry_sexp_t input_sexp;
    gcry_sexp_t ciphertext_sexp;
    gcry_sexp_t plaintext_sexp = NULL;
    gcry_error_t err;
    gcry_mpi_t input_mpi;


    char* publickeytoken="public-key";
    char* privatekeytoken="private-key";
    

    char* rsatoken="(genkey (rsa (nbits 4:4096)))";
    err=gcry_sexp_new( &rsatoken_sexp, rsatoken, strlen(rsatoken), 1 );
    if(err)
    {
        printf("error while while generating rsatoken_sexp");
    }

    err=gcry_pk_genkey( &rsakey_sexp, rsatoken_sexp );
    if(err)
    {
        printf("error while while generating rsakey_sexp");
    }

    gcry_sexp_release(rsatoken_sexp);

    publickey_sexp = gcry_sexp_find_token( rsakey_sexp, publickeytoken, 0 );
    if(publickey_sexp==NULL)
    {
        printf("error while extracting public key");
    }
     
    privatekey_sexp = gcry_sexp_find_token( rsakey_sexp, privatekeytoken, 0 );
    if(privatekey_sexp==NULL)
    {
        printf("error while extracting private key");
    }

    //convertToSexpression( publickey_sexp, buffer, 6000 );
    //prettyPrint( buffer, 6000 );
    //printf( "Public Key:\n%s\n\n", buffer );

    
    //convertToSexpression( privatekey_sexp, buffer, 6000 );
    //prettyPrint( buffer, 6000 );
    //printf( "Private Key:\n%s\n\n", buffer );



    gcry_sexp_release(rsakey_sexp);
   ///PRIVATE PUBLIC KEY GENERATED

    


    char* source=malloc(64);
    
    char* output=(char *)malloc(sizeof(char)*size);
    gcry_sexp_t source_sexp;
    gcry_sexp_t destination_sexp;
    int ctr;
    if(size%64==0)
    {
         ctr=size/64;
    }
    else
    {
        ctr=(size/64) + 1;
    }
    int counter=0;

    while(ctr>0)
    {
        int numofbyte=fread(source, 1, 64, file);
        //printf("num of bytes read : %d ",numofbyte);
        //printf("\n");
        if(numofbyte<64)
        {
            
            //printf("\n");
            int padding=64 - numofbyte;
            //printf("adding padding of %d bytes.", padding);
            //printf("\n");
            for( i=numofbyte;i<padding;i++)
            {
                source[i]="0";
            }
        }
    
        
        
        //printf("iterations left :%d ",ctr);
        //printf("\n");
        convertToBuffer( source, &source_sexp );
        //PRINT SEXP
        //convertToSexpression( source_sexp, buffer, 6000 ); 
        //prettyPrint( buffer, strlen(buffer) );
        //printf( "source: \n%s\n\n", buffer );
        begin_enc=clock();

        err = gcry_pk_encrypt( &destination_sexp, source_sexp, publickey_sexp );
        //convertToSexpression( destination_sexp, buffer, 6000 ); 
        //prettyPrint( buffer, strlen(buffer) );
        //printf( "destination: \n%s\n\n", buffer );
        end_enc=clock();
        time_enc = (double)(end_enc - begin_enc)*1000.0 / CLOCKS_PER_SEC;
        total_enc+=time_enc;

        begin_dec=clock();
        err = gcry_pk_decrypt( &plaintext_sexp, destination_sexp, privatekey_sexp );
        //convertToSexpression( plaintext_sexp, buffer, 6000 ); 
        //prettyPrint( buffer, strlen(buffer) );
        //printf( "plaintext: \n%s\n\n", buffer );
        end_dec=clock();
        time_dec=(double)(end_dec - begin_dec)*1000.0 / CLOCKS_PER_SEC;
        total_dec+=time_dec;

        char* destination=malloc(64);

        //convertToSexpression(destination_sexp,destination,sizeof(destination));
        //size_t s = gcry_sexp_sprint( plaintext_sexp, GCRYSEXP_FMT_DEFAULT, NULL, sizeof(destination) ) ;
        //if(s==0)
        
            //printf("%zu\n", s);

        destination=gcry_sexp_nth_string (plaintext_sexp,0);

        //printf("output is : %s",destination);
        //printf("\n");
        for( i=0;i<64;i++)
        {
            output[counter]=destination[i];
            counter++;
        }

        
        
        ctr--;
        free(destination);
        

    }
    rsa4096_encbuffer[index]=total_enc;
    rsa4096_decbuffer[index]=total_dec;
/*
    printf("output :");
    for(int i=0;i<size;i++)
    {

            printf("%c ",output[i]);
    }
*/

    rewind( file );

    

 }

     ////////////////////////////
    /////RSA HELPER FUNCTIONS///
    ///////////////////////////

void convertToBuffer(char *buffer,gcry_sexp_t *sexp )
{
    gcry_error_t err;
    gcry_mpi_t buffer_mpi; 
    
     err=gcry_mpi_scan( &buffer_mpi, GCRYMPI_FMT_USG, buffer, strlen(buffer), NULL ) ;
        
    
     err=gcry_sexp_build( sexp, NULL, "(data(flags raw)(value %m))", buffer_mpi ) ;

     if(err)
     {
        printf("error while converting s-expression to buffer");
     }
        
    
     gcry_mpi_release( buffer_mpi );
    
     return;
}

void convertToSexpression( gcry_sexp_t sexp, char* buffer, int len)
{
     size_t size;

     size = gcry_sexp_sprint( sexp, GCRYSEXP_FMT_DEFAULT, buffer, len ) ;

        if(size==0)
        {
            printf("error while converting from buffer to s-expression");
        }
        
}

 void prettyPrint( char *input_sexp, int len )
{
    
    int i;
    for(  i=0; i < len; i++ ) 
    {
        if( input_sexp[i] == ')' && input_sexp[i+1] == '\n' && input_sexp[i+2] == '\0' ) 
        {
            break;
        }
        
        if( input_sexp[i] == '\0' ) 
        {
            input_sexp[i] = ' ';
        }
    }
    printf("%s",input_sexp);
    printf("\n");
    
    return;
}





    ///////////////////
    ////////MD5///////
    //////////////////

 void myMD5(FILE* file,double md5_buffer[],int index)
{
    clock_t start, end;
    double tim;
    int i;

    
    char* plaintext=fileToBuffer(file);
    #define algo GCRY_MAC_HMAC_MD5 
    gcry_mac_hd_t handle;
gcry_error_t err;
    unsigned int mlen;


    size_t keylength= gcry_mac_get_algo_keylen(algo);
    //printf("%u",keylength); // 64 

    unsigned char* buffer=plaintext;
    size_t bufferlength = strlen(buffer)+1;

    unsigned char * key = malloc(keylength); // 16 bytes
    gcry_randomize (key, keylength, GCRY_VERY_STRONG_RANDOM);
    //printf("\nMD5 KEY GENERATED!!\n");


    mlen = gcry_mac_get_algo_maclen (algo);




    start=clock();

    
    err=gcry_mac_open (&handle,algo, 0, NULL);
    err=gcry_mac_setkey (handle, key, keylength);
    err=gcry_mac_write (handle, buffer,bufferlength );

    unsigned int length=gcry_mac_get_algo_maclen (algo);

    size_t hmaclength=length;
    
    unsigned char* hmac=malloc(hmaclength);

    gcry_mac_read (handle, hmac, &hmaclength);

    end=clock();
    tim=(double)(end-start)*1000/CLOCKS_PER_SEC;
    md5_buffer[index]=tim;
/*
    printf("\nMD5 GENERATED IS : ");
    for( i = 0; i < hmaclength ; i++) { printf("%02x",hmac[i]); }
        printf("\n");
*/
     gcry_mac_close (handle);
     



}


    ///////////////////
    ////////SHA1///////
    //////////////////

void mySHA1(FILE *file,double sha1_buffer[],int index)
{
    clock_t start, end;
    double tim;
    unsigned char* plaintext=fileToBuffer(file);
    size_t ptlength = strlen(plaintext)+1;
    #define algo GCRY_MAC_HMAC_SHA1  // Pick the cipher here
    gcry_mac_hd_t handle;
    gcry_error_t err;
    int i;


    size_t keylength = 64;

    unsigned int kl=gcry_mac_get_algo_keylen (algo);
    unsigned char * key = malloc(kl); // 16 bytes
    gcry_randomize (key, keylength, GCRY_VERY_STRONG_RANDOM);
    //printf("\nSHA1 KEY GENERATED!!\n");
    
    start=clock();

    err=gcry_mac_open (&handle, algo, 0, NULL);
    if (err) {
  fprintf(stderr, "mac_open during encryption: %s/%s\n", gcry_strsource(err), gcry_strerror(err));
  
}

    
    err=gcry_mac_setkey(handle, key, kl);

    if (err) {
  fprintf(stderr, "mac_setkey during encryption: %s/%s\n", gcry_strsource(err), gcry_strerror(err));

}
    
    err=gcry_mac_write (handle, plaintext, ptlength);

    if (err) {
  fprintf(stderr, "mac_write during decryption: %s/%s\n", gcry_strsource(err), gcry_strerror(err));
  
}




    unsigned int length=gcry_mac_get_algo_maclen (algo);

    size_t hmaclength=length;
    
    unsigned char* hmac=malloc(hmaclength);

    gcry_mac_read (handle, hmac, &hmaclength);
    end=clock();
    tim=(double)(end-start)*1000/CLOCKS_PER_SEC;
    sha1_buffer[index]=tim;

    //printf("%s",hmac);

    /*
    printf("SHA1 IS : ");
    for( i = 0; i < hmaclength ; i++) { printf("%02x",hmac[i]); }
        printf("\n");
*/

    gcry_mac_close (handle);
    

  
}




    ////////////////////
    ///SHA 256/////////
    //////////////////

 unsigned char* mySHA256(FILE *file,double sha256_buffer[],int index)
  {
      clock_t start, end;
      double tim;
      char* plaintext=fileToBuffer(file);
      #define algo      GCRY_MAC_HMAC_SHA256 
      gcry_mac_hd_t handle;
      gcry_error_t err;

      size_t keylength= gcry_mac_get_algo_keylen(algo);
      //printf("%u",keylength); // 64 

    unsigned char* buffer=plaintext;
    //"123456789 abcdefghijklmnopqrstuvwzyz ABCDEFGHIJKLMNOPQRSTUVWZYZ123456789123456789 abcdefghijklmnopqrstuvwzyz ABCDEFGHIJKLMNOPQRSTUVWZYZ123456789";
    size_t bufferlength = strlen(buffer)+1;
    unsigned char * key = malloc(keylength); // 16 bytes
    gcry_randomize (key, keylength, GCRY_VERY_STRONG_RANDOM);
    //printf("\nSHA256 KEY GENERATED!!\n");

    start=clock();
    err=gcry_mac_open (&handle,algo, 0, NULL);
    err=gcry_mac_setkey (handle, key, keylength);
    err=gcry_mac_write (handle, buffer,bufferlength);

    unsigned int length=gcry_mac_get_algo_maclen (algo); //64

    size_t hmaclength=length;
    
    unsigned char* hmac=malloc(hmaclength);

    gcry_mac_read (handle, hmac, &hmaclength);
    end=clock();
    tim=(double)(end-start)*1000/CLOCKS_PER_SEC;
    sha256_buffer[index]=tim;
    int i;
/*
    printf("SHA256 IS : ");
   
    for( i = 0; i < hmaclength ; i++) { printf("%02x",hmac[i]); }
        printf("\n");
    */

     gcry_mac_close (handle);
     return hmac;
     
     
        
 }


    ///////////////////
    //////AES 128///////
    //////////////////

void myAES128(FILE *file,double aes128_encbuffer[],double aes128_decbuffer[],int index)
{
    clock_t start_enc, end_enc;
    clock_t start_dec, end_dec;
    double time_enc,time_dec;
    char* plaintext=fileToBuffer(file);
    

    #define GCRY_CIPHER GCRY_CIPHER_AES128   // Pick the cipher here
    #define GCRY_MODE GCRY_CIPHER_MODE_CTR // Pick the cipher mode here


    gcry_cipher_hd_t handle;
    size_t keyLength = gcry_cipher_get_algo_keylen(GCRY_CIPHER);
    size_t blocklength=gcry_cipher_get_algo_blklen(GCRY_CIPHER);
    size_t ctrLength = blocklength; //16
    unsigned char* ctr=malloc(blocklength);
    unsigned char * key = malloc(blocklength); // 16 bytes
    gcry_randomize (ctr, blocklength, GCRY_STRONG_RANDOM);
    gcry_randomize (key, blocklength, GCRY_VERY_STRONG_RANDOM);
    //printf("\nAES 128 KEY GENERATED!!\n");




    char* txtBuffer = plaintext;
    size_t txtLength = strlen(txtBuffer)+1; // string plus termination
    char * encBuffer = (char *)malloc(txtLength);
    char * outBuffer = (char *)malloc(txtLength);

    

    gcry_control (GCRYCTL_DISABLE_SECMEM, 0);

    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

    gcry_cipher_open(&handle, GCRY_CIPHER, GCRY_MODE, 0);

    gcry_cipher_setctr(handle, &ctr, 16);

    gcry_cipher_setkey(handle, &key, keyLength);

    start_enc=clock();

    gcry_cipher_encrypt(handle, encBuffer, txtLength, txtBuffer, txtLength);

    end_enc=clock();
    time_enc=(double)(end_enc - start_enc)*1000/CLOCKS_PER_SEC;
    aes128_encbuffer[index]=time_enc;

    gcry_cipher_setctr(handle, &ctr, 16);

    start_dec=clock();

    gcry_cipher_decrypt(handle, outBuffer, txtLength, encBuffer, txtLength);

    end_dec=clock();
    time_dec=(double)(end_dec - start_dec)*1000/CLOCKS_PER_SEC;
    aes128_decbuffer[index]=time_dec;

   
    //printf("outBuffer for AES 128 : %s\n", outBuffer);

    gcry_cipher_close(handle);
    free(encBuffer);
    free(outBuffer);
   



}


    ///////////////////
    //////AES 256///////
    //////////////////

void myAES256(FILE *file,double aes256_encbuffer[],double aes256_decbuffer[],int index)
{
    clock_t start_enc, end_enc;
    clock_t start_dec, end_dec;
    double time_enc,time_dec;
   
    char* plaintext=fileToBuffer(file);

     #define GCRY_CIPHER GCRY_CIPHER_AES256   // Pick the cipher here
     #define GCRY_MODE GCRY_CIPHER_MODE_CTR // Pick the cipher mode here

    gcry_cipher_hd_t handle;
    size_t keyLength = gcry_cipher_get_algo_keylen(GCRY_CIPHER);
    size_t blocklength=gcry_cipher_get_algo_blklen(GCRY_CIPHER);
    size_t ctrLength = blocklength;
    unsigned char* ctr=malloc(blocklength);
    unsigned char * key = malloc(blocklength); // 16 bytes
    gcry_randomize (ctr, blocklength, GCRY_STRONG_RANDOM);
    gcry_randomize (key, keyLength, GCRY_VERY_STRONG_RANDOM);
    //printf("\nAES 256 KEY GENERATED!!\n");





    char* txtBuffer =plaintext;
    size_t txtLength = strlen(txtBuffer)+1; // string plus termination
    char * encBuffer = (char *)malloc(txtLength);
    char * outBuffer = (char *)malloc(txtLength);


    gcry_control (GCRYCTL_DISABLE_SECMEM, 0);

    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

    gcry_cipher_open(&handle, GCRY_CIPHER, GCRY_MODE, 0);

    gcry_cipher_setctr(handle, &ctr, 16);

    gcry_cipher_setkey(handle, &key, keyLength);

    start_enc=clock();

    gcry_cipher_encrypt(handle, encBuffer, txtLength, txtBuffer, txtLength);

    end_enc=clock();
    time_enc=(double)(end_enc - start_enc)*1000/CLOCKS_PER_SEC;
    aes256_encbuffer[index]=time_enc;

    //printf("encBuffer = %s\n", encBuffer);

    gcry_cipher_setctr(handle, &ctr, 16);

    start_dec=clock();

    gcry_cipher_decrypt(handle, outBuffer, txtLength, encBuffer, txtLength);

    end_dec=clock();
    time_dec=(double)(end_dec - start_dec)*1000/CLOCKS_PER_SEC;
    aes256_decbuffer[index]=time_dec;

    //printf("outBuffer for AES 256 : %s\n", outBuffer);

    gcry_cipher_close(handle);
    free(encBuffer);
    free(outBuffer);
    
    


}



//////////////////////
///HELPER FUNCTIONS///
//////////////////////

double getMedian(double buffer[],double total)
{
    int len=(int)total;
    double temp=0.0;
    double median;
    int i,j;
    for( i=0;i<len-1;i++)
    {
        for( j=i+1;j<len;j++)
        {
            if(buffer[j]<buffer[i])
            {
                temp=buffer[j];
                buffer[j]=buffer[i];
                buffer[i]=temp;
            }
        }
    }
    if(len%2!=0)
    {
        median=buffer[len/2];
    }
    else
    {
        median=(buffer[len/2]+buffer[(len/2)+1])/2;
    }
    return median;
}
double getMean(double buffer[],double total)
{
    double sum=0.0;
    double mean=0.0;
    int i;
    for(i=0;i<(int)total;i++)
    {
        sum=sum+buffer[i];
    }
    mean=sum/total;
    return mean;
}

int filesize(FILE *file1)
{
    int p=ftell(file1);
    fseek(file1, 0L, SEEK_END);
    int size=ftell(file1);
    //fseek(file1,p,SEEK_SET); 
    rewind( file1 );
    return size;
}


char* fileToBuffer(FILE *file)
{
    int size;
    char *plaintext;
 
    size=filesize(file);
    

    
    plaintext = calloc( 1, size );
    if( !plaintext ) 
    {
        printf("error in allocating memory for file");
        fclose(file);

    }
    if(fread( plaintext , size, 1 , file)!=1 )
    {
        printf("error in reading file");
        fclose(file);
    }
    rewind( file );
    return plaintext;
}
