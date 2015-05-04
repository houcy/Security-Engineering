all: part2 rand_gen

part2: part2.c
	cc -o part2 part2.c -lcrypto -std=c99 -w
	
rand_gen: rand_gen.c
	cc -o rand_gen rand_gen.c -lcrypto


clean:
	rm part2
	rm rand_gen
	
