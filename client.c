/*****************************************************************************
 *** Program explaining the client-server model                            ***
 *** developed by Ashok Kumar Das, CSE Department, IIT Kharagpur           ***
 ***                                                                       ***
 *****************************************************************************/

/****************************************************************************
Problem: User A (client) sends the request message REQ to the user B (server).
In response, user B (server) replies the response message REP to the user A
(client).
REQ contains:
1. message header
2. integer x
3. integer y
4. integer check1 = x AND y
5. integer check2 = x XOR y

REP contains:
1. message header
2. integer status: 1 (SUCCESS) and 0 (FAIL)
if both check1 and check2 are valid, then return 1;
else return 0.
*******************************************************************************/ 

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <stdlib.h>
#include <time.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <openssl/sha.h>  
/***********RSA head********/
#define STACK_SIZE 10000
#define NOT_EXIST 0xFFFF;
#define LARGE 170
#define MAX_ITERATION 10 // Max tests in Miller-Robin Primality Test.
#define div /
#define mod %
#define and &&
#define true 1
#define false 0
/****ends*******/  


/* Global constants */
#define SERVICE_PORT 41049
#define MAX_SIZE 20
#define MAX_LEN 1024
#define SUCCESS 1
#define FAIL 0


#define DEFAULT_SERVER "127.0.0.1"

#define Pubkey 10  /* Request message */
#define REQ 20  
#define REP 30  /* Reply message */
#define REQCOM 40
#define Disc 50 
/*****struct-RSA******/
  typedef struct{
int top;
char c[STACK_SIZE];
} stack;
typedef short boolean;
typedef union{
    struct{
    long int n;
    long int e;
    } public_key;
    struct{
    long int n;
    long int d;
    } private_key;
} key;
int mul_inverse=0;
int gcd_value;
stack s;
int print_flag=0;
int print_flag1=0;
/*****end***********/

/* Define a message structure */
typedef struct {
 int opcode;
 int src_addr;
 int dest_addr;
 } Hdr;

/* REQ message */
typedef struct {
 //Hdr hdr;
 char filename[1024];
} ReqMsg;

/* REP message */
typedef struct {
 long int chyp;
 //char ch[2];
 //Hdr hdr;
} RepMsg;

typedef struct 
{
  long int n;
  long int e;
  
}PubKey;

typedef struct 
{
  int status;
  
}Disconnect;
typedef struct 
{
  int status;
}Reqcom;
/*dunction prototype RSA*/
/*****main _struct*********/
typedef struct {
Hdr hdr; /* Header for a message */
 union  AllMsg1{
    PubKey pubkey;
    ReqMsg req;
    RepMsg rep;
    Disconnect disconnect;
    Reqcom reqcom;
        } AllMsg;
   // AllMsg1 AllMsg; 
 unsigned char sha1_send [SHA_DIGEST_LENGTH];     
   
} Msg;
/***end***************/

int gcd(int a, int b);
void extended_euclid(int A1, int A2, int A3, int B1, int B2,int B3);
long int ModPower(long int x, long int e, long int n);
boolean MillerRobinTest(long int n, int iteration);
boolean verify_prime(long int p);
void decimal_to_binary(long int n,char str[]);
void reverse_string(char x[]);
long int ModPower(long int x, long int e, long int n);
void KeyGeneration(key *pub_key, key *pvt_key);
long int DecryptionAlgorithm(long int C, key pvt_key);
//global array for substitute 
char string_substitute[STACK_SIZE];
char string_sha1[STACK_SIZE];
/********ends***********/
/* Function prototypes */
int serverConnect ( char * );
void Talk_to_server ( int ,char*);
/******ends****/
/****************char_subtitution***********/
void substitute_back(char substitution[])
{
  char temp[3];
  char s[2];
  int i=0,val;
  memset(string_sha1,'\0',STACK_SIZE);
for(i;i<strlen(substitution)-1;++i)
{
  temp[0]=substitution[i];
  temp[1]=substitution[++i];
  temp[2]='\0';
sscanf(temp,"%d",&val);
    //printf("value : %d\n",value);
    if(val==0)
      {s[0]=' ';
      s[1]='\0';
      strcat(string_substitute,s);
      //printf(" ");
    }
    else if(val==64)
      {s[0]=',';
      s[1]='\0';
      strcat(string_substitute,s);
    }
    else if(val==65)
     { s[0]='.';
      s[1]='\0';
      strcat(string_substitute,s);
    }
    else if(val==66)
      {s[0]='!';
      s[1]='\0';
      strcat(string_substitute,s);
   }
    else if(val>=1 && val<=27)
      {s[0]=val-1+'A';
      s[1]='\0';
      strcat(string_substitute,s);
    }
    else if(val>=28 && val<=53)
      {s[0]=val-28+'a';
      s[1]='\0';
      strcat(string_substitute,s);
    }
    else if(val>53 && val<64)
    {s[0]= val-54+'0';
      s[1]='\0';
      strcat(string_substitute,s);
    }
   strcat(string_sha1,s);   
}
}
/***********ends**********************/
/******RSA WORK*****/
int gcd(int a, int b)
{
int r;
if(a < 0) a = -a;
if(b < 0) b = -b;
if(b == 0)
 return a;
r = a mod b;
// exhange r and b, initialize a = b and b = r;
a = b;
b = r;
return gcd(a,b);
}
void extended_euclid(int A1, int A2, int A3, int B1, int B2,int B3)
{
int Q;
int T1,T2,T3;
if(B3 == 0){
 gcd_value = A3;
 mul_inverse = NOT_EXIST;
 return;
}
if(B3 == 1){
 gcd_value = B3;
 mul_inverse = B2;
 return;
}
Q = (int)(A3/B3);
T1 = A1 - Q*B1;
T2 = A2 - Q*B2;
T3 = A3 - Q*B3;
A1 = B1;
A2 = B2;
A3 = B3;
B1 = T1;
B2 = T2;
B3 = T3;
extended_euclid(A1,A2,A3,B1,B2,B3);
}
void recall_key(key *pub_key, key *pvt_key)
{
  //printf("its here\n");
  KeyGeneration(pub_key, pvt_key);
}
boolean MillerRobinTest(long int n, int iteration)
{
// n is the given integer and k is the given desired
// number of iterations in this primality test algorithm.
// Return true if all the iterations test passed to give
// the higher confidence that n is a prime, otherwise
// return false if n is composite.
long int m, t;
 int i,j;
long int a, u;
 int flag;
 if(n mod 2 == 0)
return false; // n is composite.
 m = (n-1) div 2;
 t = 1;
while( m mod 2 == 0) // repeat until m is even
 {
 m = m div 2;
 t = t + 1;
 }

 for (j=0; j < iteration; j++) { // Repeat the test for MAX_ITERATION times
 flag = 0;
 srand((unsigned int) time(NULL));
 a = random() mod n + 1; // select a in {1,2,......,n}
 u = ModPower(a,m,n);
 if (u == 1 || u == n - 1)
 flag = 1;
for(i=0;i<t;i++)
 {
 if(u == n - 1)
 flag = 1;
 u = (u * u) mod n;
 }
 if ( flag == 0 )
 return false; // n is composite
 }
return true; // n is prime.
} // end of MillerRobinTest().
//KEY GENERATION ALGORITHM IN RSA CRYPTOSYSTEM.
void KeyGeneration(key *pub_key, key *pvt_key)
{
long int p,q;
long int n;
long int phi_n;
long int e;
// Select p and q which are primes and p<q.
if(print_flag1)
printf("\n selecting p->\n\r");
while(1)
{
 srand((unsigned int) time(NULL));
 p = random() % LARGE;
 /* test for even number */
 if ( p & 0x01 == 0 ) continue;
 if(MillerRobinTest(p, MAX_ITERATION))
break;
}
if(print_flag1)
printf("\n selecting q->\n\r");

while(1)
{
 srand((unsigned int) time(NULL));
 q=random() % LARGE;
if( q == p)
{
 srand((unsigned int) time(NULL));
q = random() % LARGE;
continue;
}
if(MillerRobinTest(q, MAX_ITERATION))
break;

}
 // Compute n.
 if (verify_prime(p) && verify_prime(q) )
 printf("p = %ld, q = %ld are primes\n", p, q);
 else {
 //exit(0);

 return recall_key(pub_key, pvt_key);

 }
 printf("p = %ld, q = %ld\n", p, q);
 n = p * q;
 // Compute Euler's phi(totient) function
 phi_n = (p-1)*(q-1);
 // Compute e such that gcd(e,phi_n(n))=1.
 if(print_flag1)
 printf("\n selcting e->\n\r");
 while(1)
 {
 e = random()%phi_n;
 if(gcd(e, phi_n)==1)
 break;
 }
// Compute d such that ed=1(mod phi_n(n)).
 if(print_flag1)
 printf("\n selceting d->\n\r");
 extended_euclid(1, 0, phi_n, 0, 1, e);
 if(mul_inverse <0) {
 mul_inverse = - mul_inverse;
 mul_inverse = ((phi_n - 1 ) * mul_inverse) mod phi_n;
 }
 if(print_flag1)
 printf("\n phi_n= %ld\n\n",phi_n);
// Put Public Key and Private Key.
 pub_key->public_key.n = n;
 pub_key->public_key.e = e;
 pvt_key->private_key.n = n;
 pvt_key->private_key.d = mul_inverse;
} // end of KeyGeneraion()
boolean verify_prime(long int p)
{
long int d;
// Test for p;
for(d = 2; d <= (long int) sqrt(p); d++ )
 if ( p % d == 0 ) return false;
return true;
}
// Encryption Algorithm(E)
/*long int EncryptionAlgorithm(long int M, key pub_key)
{
// Alice computes ciphertext as C := M^e(mod n) to Bob.
long int C;
if(print_flag1)
printf("\n Encryption keys= ( %ld,%ld)\n\r",pub_key.public_key.n,pub_key.public_key.e);
C = ModPower(M, pub_key.public_key.e, pub_key.public_key.n);
return C;
}*/
// Decryption Algorithm(D)
long int DecryptionAlgorithm(long int C, key pvt_key)
{
// Bob retrieves M as M := C^d(mod n)
long int M;
if(print_flag1)
printf("\n Decryption keys= ( %ld,%ld)\n\r",pvt_key.private_key.n,pvt_key.private_key.d);
M = ModPower(C, pvt_key.private_key.d, pvt_key.private_key.n);
return M;
}


void decimal_to_binary(long int n,char str[])
{
// n is the given decimal integer.
// Purpose is to find the binary conversion
// of n.
 // Initialise the stack.
int r;
 s.top = 0;
while(n != 0)
{
r = n mod 2;
s.top++;
if(s.top >= STACK_SIZE)
{
printf("\nstack overflown!\n");
return;
}
s.c[s.top] = r + 48;
if(print_flag)
 printf("\n s.c[%d]= %c\n", s.top, s.c[s.top]);
n = n div 2;
}
while(s.top)
{
 *str++ = s.c[s.top--];
}
*str='\0';
return;
}
// Algorithm: reverse a string.
void reverse_string(char x[])
{
int n = strlen(x)-1;
int i = 0;
char temp[STACK_SIZE];
for(i = 0; i<=n; i++)
 temp[i] = x[n-i];
for(i=0; i<=n; i++)
 x[i] = temp[i];
}
// Algorithm: Modular Power: x^e(mod n).
long int ModPower(long int x, long int e, long int n)
{
// To calculate y:=x^e(mod n).
 //long y;
 long int y;
long int t;
 int i;
int BitLength_e;
char b[STACK_SIZE];
 //printf("e(decimal) = %ld\n",e);
decimal_to_binary(e,b);
if(print_flag)
 printf("b = %s\n", b);
BitLength_e = strlen(b);
y = x;
reverse_string(b);
for(i = BitLength_e - 2; i >= 0 ; i--)
{
if(print_flag)
 printf("\nb[%d]=%c", i, b[i]);
if(b[i] == '0')
t = 1;
else t = x;
 y = (y * y) mod n;
 if ( y < 0 ) {
 y = -y;
 y = (y - 1) * (y mod n) mod n;
 printf("y is negative\n");
 }
y = (y*t) mod n;
 if ( y < 0 ) {
 y = -y;
 y = (y - 1) * (y mod n) mod n;
 printf("y is negative\n");
 }
}
 if ( y < 0 ) {
 y = -y;
 y = (y - 1) * (y mod n) mod n;
 printf("y is negative\n");
 }
return y;

}
/******ens**********/
/* Connect with the server: socket() and connect() */
int serverConnect ( char *sip )
{
   int cfd;
   struct sockaddr_in saddr;   /* address of server */
   int status;

   /* request for a socket descriptor */
   cfd = socket (AF_INET, SOCK_STREAM, 0);
   if (cfd == -1) {
      fprintf (stderr, "*** Client error: unable to get socket descriptor\n");
      exit(1);
   }

   /* set server address */
   saddr.sin_family = AF_INET;              /* Default value for most applications */
   saddr.sin_port = htons(SERVICE_PORT);    /* Service port in network byte order */
   saddr.sin_addr.s_addr = inet_addr(sip);  /* Convert server's IP to short int */
   bzero(&(saddr.sin_zero),8);              /* zero the rest of the structure */

   /* set up connection with the server */
   status = connect(cfd, (struct sockaddr *)&saddr, sizeof(struct sockaddr));
   if (status == -1) {
      fprintf(stderr, "*** Client error: unable to connect to server\n");
      exit(1);
   }

   fprintf(stderr, "Connected to server\n");

   return cfd;
}
/* Interaction with the server */
void Talk_to_server ( int cfd ,char* agrv_filename)
{
    char str[STACK_SIZE],str_concat[STACK_SIZE];
    int x, e;
    FILE *fptr1;
    key pub_key, pvt_key;
    //char ch;
   char buffer[MAX_LEN];
   int nbytes, status;
   int src_addr, dest_addr;
  long int plaintext, ciphertext, deciphertext;
  KeyGeneration(&pub_key, &pvt_key);
   ReqMsg send_msg;
   RepMsg recv_msg;
   //key_public public_key;
   // printf("\n Public Key of Alice is (n,e): (%ld , %ld)\n\r", pub_key.public_key.n, pub_key.public_key.e);
 printf("\n Private key of Alice is (n,d): (%ld , %ld)\n\r", pvt_key.private_key.n,
  pvt_key.private_key.d);
   dest_addr = inet_addr(DEFAULT_SERVER);
   src_addr = inet_addr("127.0.0.5");

    printf("Sending the public_key to the server\n");          
    Msg msg;
    msg.hdr.opcode=Pubkey;
    msg.hdr.src_addr = src_addr;
    msg.hdr.dest_addr = dest_addr;
    msg.AllMsg.pubkey.n=pub_key.public_key.n;
    msg.AllMsg.pubkey.e=pub_key.public_key.e;
      int t_block=66,n_block=0;
    while(t_block<pub_key.public_key.n)
    {
      t_block=66+t_block*100;
      ++n_block;
    }
  status = send(cfd, &msg, sizeof(Msg), 0);
   if (status == -1) {
      fprintf(stderr, "*** Server error: unable to send\n");
      return;
    }
   /* send the request message REQ to the server */
   printf("Sending the request message REQ to the server\n");          
   msg.hdr.opcode = REQ;
   msg.hdr.src_addr = src_addr;
   msg.hdr.dest_addr = dest_addr;
   strcpy(msg.AllMsg.req.filename, agrv_filename);
   //printf("here\n");
   printf("File name is:- %s\n",msg.AllMsg.req.filename);
  

   status = send(cfd, &msg, sizeof(Msg), 0);
   if (status == -1) {
      fprintf(stderr, "*** Server error: unable to send\n");
      return;
    }
    //exit(0);
  while (1) {
  /* receive greetings from server */
   nbytes = recv(cfd, &msg, sizeof(Msg), 0);
   if (nbytes == -1) {
      fprintf(stderr, "*** Client error: unable to receive\n");
      
   }
   switch ( msg.hdr.opcode ) {
    
   case REP : 
                sprintf(str,"%ld",DecryptionAlgorithm(msg.AllMsg.rep.chyp,pvt_key));

                if(strlen(str)%2==1)
                {
                  strcpy(str_concat,"0");
                  strcat(str_concat,str);
                  strcpy(str,str_concat);
                }
                if(strlen(str)/(2*n_block)!=1)
                {
                  strcpy(str_concat,"00");
                  strcat(str_concat,str);
                  strcpy(str,str_concat);
                }
           /*printf("\nsha1 is:"); 
            int loop_print;
               for (loop_print = 0; loop_print < SHA_DIGEST_LENGTH; ++loop_print)
               {
                 printf("%u",msg.sha1_send[loop_print] );
               }*/
                
                //printf("final %s\n",str);
                substitute_back(str);
//printf("sha1 for sub%s\n",string_sha1);
               unsigned char digest[SHA_DIGEST_LENGTH];
               memset(digest,'\0',SHA_DIGEST_LENGTH);
               /*int x;
               for (x= 0; x < strlen(string_sha1); ++x)
               {
                 printf("string[%d]%c",x,string_sha1[x] );
               }
               printf("\n");*/
               //printf("size : %d\nText : #%s#", strlen(string_sha1), string_sha1);
               SHA1(string_sha1,strlen(string_sha1),digest);
               int for_loop;
               /*  for (i=0; i < SHA_DIGEST_LENGTH; i++) {
                 sprintf((char*)&(buf[i*2]), "%02x", temp[i]);
                 }*/

                for (for_loop = 0; for_loop < SHA_DIGEST_LENGTH; ++for_loop)
                 {
                   if(msg.sha1_send[for_loop]!=digest[for_loop])
                   {
                      msg.hdr.opcode=Disc;
                      msg.AllMsg.disconnect.status=1;
                      status = send(cfd, &msg, sizeof(Msg), 0);
                   if (status == -1) {
                      fprintf(stderr, "hi Server error: unable to send\n");
                      return;
                    }
                   }
                 }
                 memset(string_sha1,'\0',strlen(string_sha1));
                 //printf("\n");
               //printf("substitute after %s\n", string_substitute);
                //printf("plaintext : %ld\n",plain);
              /* Check the status of REP message */
             /* if (msg.AllMsg.r.status) 
                printf("Message REQ has received successfully by the server\n");
              else    
               printf("Message REQ has NOT received successfully by the server\n");*/
              break; 
  case REQCOM:
               if(msg.AllMsg.reqcom.status==1)
               {
                msg.hdr.opcode=Disc;
                msg.AllMsg.disconnect.status=1;
                fptr1 = fopen(agrv_filename,"w");
                if (fptr1 == NULL)
                      printf("Error in writing to the file\n");
                fprintf(fptr1, "%s", string_substitute);
                fclose(fptr1);
               }
      printf("file recived complted doing deciphertext opcode is Disconnect: %d\n", msg.hdr.opcode);

               status = send(cfd, &msg, sizeof(Msg), 0);
                   if (status == -1) {
                    printf("Disconnect client opcode: %d\n", msg.hdr.opcode);
                      exit(0);
                    }
              //exit(0);
               break;
                                      
  case Disc :
                  printf("Disconnect client opcode: %d\n", msg.hdr.opcode);
                  exit(0);
                  break;
   default: 
            //printf("default\n");
            printf("message received with opcode: %d\n", msg.hdr.opcode);
            exit(0);  
   }
 }
}

int main ( int argc, char *argv[] )
{
   char sip[16];
   int cfd;
   

   printf("******* This is demo program using sockets ***** \n\n");
   
   strcpy(sip, (argc == 2) ? argv[1] : DEFAULT_SERVER);
   cfd = serverConnect(sip);
   Talk_to_server (cfd,argv[2]);
   close(cfd);
}

/*** End of client.c ***/
