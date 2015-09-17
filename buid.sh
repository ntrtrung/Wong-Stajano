rm *.o
rm ./client
rm ./server
gcc -c *.c
gcc -o server example-server.o sha2.o hmac_sha2.o uECC.o
gcc -o client example-client.o hmac_sha2.o sha2.o uECC.o
