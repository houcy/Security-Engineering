all: ssl_client ssl_server part1

ssl_client: ssl_client.c
	gcc ssl_client.c -o client -lssl -lcrypto

ssl_server: ssl_server.c
	gcc ssl_server.c -o server -lssl -lcrypto

part1: part1.c
	gcc part1.c -o part1 -fno-stack-protector

clean:
	rm server
	rm client
	rm part1

