CC=gcc
INC=-I. -I../include -I../../include

all:
	${CC} -Wall -o mkclient ../../src/mk_mdns_client.c ./*.c ${INC}
clean:
	rm -r mkclient
