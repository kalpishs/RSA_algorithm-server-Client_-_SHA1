# RSA_algorithm-server-Client_SHA1
Using a client-server programming model with RSA public key cryptosystem along with SHA-1 hash function
____________________________________________________________________________________________________________________________________________

Kalpish Singhal
____________________________________________________________________________________________________________________________________________

==============================================================================================================================
#Implemented RSA with SHA-1 Hash for a client server architecture in C
==============================================================================================================================
-> Implemented RSA with client server architecture to send a file requested by client.

-> SHA-1 library fuction is used to implement the hash digest of at both client and server end.

-> Secure comunication is conducted b/w client and server using assymetric key cryptography.

==============================================================================================================================
#Compilation and running 
==============================================================================================================================
-> Compiling client and server we need to comlie using -lm and -lcrypto eg."gcc client.c -lm -lcrypto" to have math and crptography

   libray compilation for sqrt and SHA1 functions respectively.

	i) gcc client.c -lm -lcrypto

	ii)gcc server.c -lm -lcrypto

-> run server with executable file normally.

-> client contains 2 argument 
			    
			      1) local host address i.e 127.0.0.1

			      2) file name to be found in server 
#Assumptions:-

	i) client is always given 2 arguments mentioned above

	ii) file to be found at server side is present in current directory 
	
	iii) Server and client programs are in different directory to avoid overwriting 

