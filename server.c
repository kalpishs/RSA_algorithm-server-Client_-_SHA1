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
#define LARGE 99
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
#define Q_SIZE 5
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
 /*int x;
 int y;
 int check1; /* x AND y*
 int check2;*/ /* x XOR y */
} ReqMsg;

/* REP message */
typedef struct {
 long int chyp;
 //char ch[3];
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
  unsigned char sha1_send [SHA_DIGEST_LENGTH];      
   
   // AllMsg1 AllMsg;    
} Msg;
/***end***************/

int gcd(int a, int b);
long int ModPower(long int x, long int e, long int n);
void decimal_to_binary(long int n,char str[]);
void reverse_string(char x[]);
long int EncryptionAlgorithm(long int M, key pub_key);


/********ends***********/

/* Function prototypes */
int startServer ( );
void Talk_to_client ( int );
void serverLoop ( int );
/********substitute***************/
void substitute(char readbf,char substitution[])
{
  //char substitution[2];
  int value;
    if(readbf==' ')
      value=0;
    else if(readbf==',')
      value=64;
    else if(readbf=='.')
      value=65;
    else if(readbf=='!')
      value=66;
    else if(readbf>='A' && readbf<='Z')
      value=readbf-'A'+1;
    else if(readbf>='a' && readbf<='z')
      value=readbf-'a'+28;
    else if(readbf>='0' && readbf<='9')
      value=readbf-'0'+54;
    
    if(value<10)
    {
      
      substitution[0]='0';
      substitution[1]=value +'0';
      substitution[2]='\0';
      //printf("value is he %s\n",substitution);
    }
    else
    {
      
      substitution[0]=value/10+'0';
      substitution[1]=value%10+'0';
      substitution[2]='\0';
      //printf("value is the %s\n",substitution);
      /*substitution[2*i]='0'+value/10+'0';
      ;
      substitution[2*i+1]='0'+value%10;*/ 
    }
    return;
}
/**********substitute end*************/

/* Start the server: socket(), bind() and listen() */
int startServer ()
{
   int sfd;                    /* for listening to port PORT_NUMBER */
   struct sockaddr_in saddr;   /* address of server */
   int status;


   /* Request for a socket descriptor */
   sfd = socket(AF_INET, SOCK_STREAM, 0);
   if (sfd == -1) {
      fprintf(stderr, "*** Server error: unable to get socket descriptor\n");
      exit(1);
   }

   /* Set the fields of server's internet address structure */
   saddr.sin_family = AF_INET;            /* Default value for most applications */
   saddr.sin_port = htons(SERVICE_PORT);  /* Service port in network byte order */
   saddr.sin_addr.s_addr = INADDR_ANY;    /* Server's local address: 0.0.0.0 (htons not necessary) */
   bzero(&(saddr.sin_zero),8);            /* zero the rest of the structure */

   /* Bind the socket to SERVICE_PORT for listening */
   status = bind(sfd, (struct sockaddr *)&saddr, sizeof(struct sockaddr));
   if (status == -1) {
      fprintf(stderr, "*** Server error: unable to bind to port %d\n", SERVICE_PORT);
      exit(2);
   }

   /* Now listen to the service port */
   status = listen(sfd,Q_SIZE);
   if (status == -1) {
      fprintf(stderr, "*** Server error: unable to listen\n");
      exit(3);
   }

   fprintf(stderr, "+++ Server successfully started, listening to port %hd\n", SERVICE_PORT);
   return sfd;
}


/* Accept connections from clients, spawn a child process for each request */
void serverLoop ( int sfd )
{
   int cfd;                    /* for communication with clients */
   struct sockaddr_in caddr;   /* address of client */
   int size;


    while (1) {
      /* accept connection from clients */
      cfd = accept(sfd, (struct sockaddr *)&caddr, &size);
      if (cfd == -1) {
         fprintf(stderr, "*** Server error: unable to accept request\n");
         continue;
      }

     printf("**** Connected with %d\n",inet_ntoa(caddr.sin_addr));
     
      /* fork a child to process request from client */
      if (!fork()) {
         Talk_to_client (cfd);
         fprintf(stderr, "**** Closed connection with %d\n",inet_ntoa(caddr.sin_addr));
         close(cfd);
         exit(0);
      }

      /* parent (server) does not talk with clients */
      close(cfd);

      /* parent waits for termination of child processes */
      while (waitpid(-1,NULL,WNOHANG) > 0);
   }
}
/******RSA_Things_continued********/
long int EncryptionAlgorithm(long int M, key pub_key)
{
// Alice computes ciphertext as C := M^e(mod n) to Bob.
long int C;
if(print_flag1)
printf("\n Encryption keys= ( %ld,%ld)\n\r",pub_key.public_key.n,pub_key.public_key.e);
C = ModPower(M, pub_key.public_key.e, pub_key.public_key.n);
return C;
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
/******RSA_ENDS*******/

/* Interaction of the child process with the client */
void Talk_to_client ( int cfd )
{

    FILE *fp;
   int n,e; 
   int status;
   int nbytes;
   int src_addr, dest_addr;
   int chk1, chk2; 
   int n_block,t_block;
   char substitution_of_sent[STACK_SIZE];
   RepMsg send_msg;
   ReqMsg recv_msg;
   // Encryption Algorithm(E)
   Msg msg;
   key pub_key;

   size_t num;
   char buff[STACK_SIZE];


   dest_addr = inet_addr("127.0.0.5");
   src_addr = inet_addr(DEFAULT_SERVER);
 nbytes = recv(cfd, &msg, sizeof(Msg), 0);
   if (nbytes == -1) {
      fprintf(stderr, "*** Server error: unable to receive\n");
      return;
   }
   if(msg.hdr.opcode==Pubkey)
   {

    printf("your n for pubkey is n %ld\n",msg.AllMsg.pubkey.n );
    printf("your e  is n %ld\n",msg.AllMsg.pubkey.e);
    pub_key.public_key.e=msg.AllMsg.pubkey.e;
    pub_key.public_key.n=msg.AllMsg.pubkey.n;
    t_block=66,n_block=0;
    while(t_block<pub_key.public_key.n)
    {
      t_block=66+t_block*100;
      ++n_block;
    }
  
   }
   

   while (1) {

    nbytes = recv(cfd, &msg, sizeof(Msg), 0);
   if (nbytes == -1) {
      fprintf(stderr, "*** Server error: unable to receive\n");
      return;
   }
  //printf("this is the opcode%d\n",msg.hdr.opcode );
   /* Receive response from server */
   switch ( msg.hdr.opcode ) {
   case REQ : /* Request message */
               /* Request message */
                    //SHA1Context sha;
                      printf("Message:: with opcode %d (REQ) received from source (%d)\n", msg.hdr.opcode, msg.hdr.src_addr);  
                      
                       
                      printf("Received values in REQ message are: \n");
                      printf("Recived file name is %s\n", msg.AllMsg.req.filename);
                       fp = fopen(msg.AllMsg.req.filename, "r");
                       if(!fp || fp==NULL)
                       {
                        msg.hdr.opcode = Disc ;
                        msg.hdr.src_addr = src_addr ;        
                        msg.hdr.dest_addr = dest_addr; 

                        status = send(cfd, &msg, sizeof(Msg), 0);
                       if (status == -1) {
                        fprintf(stderr, "*** Client error: unable to send\n");
                        return;
                        }
                        printf("No such file Found Disconnect sent\n");
                        printf("#Closed connection with %d\n",inet_ntoa(msg.hdr.dest_addr));
                        exit(0);
                       }
                       msg.hdr.opcode=REP;
                       msg.hdr.src_addr = src_addr ;        
                       msg.hdr.dest_addr = dest_addr;

                       while(!feof(fp))
                        {
                           memset(buff,'\0',STACK_SIZE);
                          num = fread(buff, sizeof(char), n_block, fp);
                          buff[num * sizeof(char)] = '\0';
                          int temp_size= num * sizeof(char);
                          int i;
                          //SHA1Reset(&sha);
                          //SHA1Input(&sha, (const unsigned char *) TESTA, strlen(TESTA));
                         memset(substitution_of_sent,'\0',STACK_SIZE);
                          //strcpy(substitution_of_sent,"");
                          for (i = 0; i < temp_size; ++i)
                          {
                           char substitution[3];
                           //printf("buff[%d] is%c",i,buff[i]);
                            substitute(buff[i],substitution);
                            strcat(substitution_of_sent,substitution);
                          }
                          //printf("\n");
                          //printf("\nsha:-");
                          unsigned char digest[SHA_DIGEST_LENGTH];
                          memset(digest,'\0',SHA_DIGEST_LENGTH);
                          SHA1(buff,temp_size,digest);
                          int for_loop;
                          memset(msg.sha1_send,'\0',SHA_DIGEST_LENGTH);
                          //printf("size : %d\nText : #%s#", temp_size, buff);

                          for (for_loop = 0; for_loop < SHA_DIGEST_LENGTH; ++for_loop)
                          {
                            msg.sha1_send[for_loop]=digest[for_loop];
                          }
                         
                            //strcpy(msg.AllMsg.rep.ch,substitution);
                           msg.AllMsg.rep.chyp= EncryptionAlgorithm(atoi(substitution_of_sent), pub_key);
                           //printf("ciphertext : %ld\n",msg.AllMsg.rep.chyp);
                           if(send(cfd, &msg, sizeof(Msg), 0)<0)
                           {
                            fprintf(stderr, "*** Client error: unable to send\n");
                            return;
                           } 
                          
                          /*printf("cont of file are:-\n"); 
                          printf("%s", buff);*/

                        }
                        msg.hdr.opcode=REQCOM;
                        msg.AllMsg.reqcom.status=1;
                        printf("Sending the reply message Reqcom to the client , opcode is  %d\n",msg.hdr.opcode); 
                         if(send(cfd, &msg, sizeof(Msg), 0)<0)
                           {
                            fprintf(stderr, "*** Client error: unable to send\n");
                            return;
                           }   
                      
                     break;
     case Disc:
              msg.hdr.opcode=Disc;
              printf("recived Disconnect from client\n");
              msg.AllMsg.disconnect.status=1;
              status = send(cfd, &msg, sizeof(Msg), 0);
               if (status == -1) {
                  fprintf(stderr, "*** Server error: unable to send\n");
                  return;
                }   
               exit(0); 
                break;             
    default: 
           printf("message received with opcode: %d\n", msg.hdr.opcode);
           exit(0);  
   }
 }
}

int main ()
{
   int sfd;
   sfd = startServer();   
   serverLoop(sfd);
}

/*** End of server.c ***/     

