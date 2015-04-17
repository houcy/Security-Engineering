all: part2 part3 part3_vul

part2 : part2.c
	cc -g -Wall -fno-stack-protector -z execstack part2.c -o part2

part3 : part3.c
	cc -fno-stack-protector -z execstack part3.c -o part3

part3_vul : part3_vul.c
	cc -fno-stack-protector -z execstack part3_vul.c -o part3_vul
clean:
	rm part2 
	rm part3
	rm part3_vul
