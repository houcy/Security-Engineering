all: encrypt decrypt

encrypt: encrypt.c
	cc encrypt.c -o encrypt -lcrypto

decrypt: decrypt.c
	cc decrypt.c -o decrypt -lcrypto

clean:
	rm encrypt
	rm decrypt
	
	
