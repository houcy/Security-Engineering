#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void function1()
{
  	unsigned char buff[256];
	memset(buff,0,256);
	gets(buff);
	printf("Inside function1. Must not return to main()\n");
	printf("String:%s\n",buff);
}

void target()
{
	printf("This is the target function\n");
	exit(0);
}
int main(int argc, unsigned char **argv)
{
	//unsigned char buff[256];
	//memset(buff,0,256);
	//printf("Input string:");
	//gets(argv[0]);
	//strcpy(buff,argv[1]);
	function1();
	printf("back to main!\n");
	return 0;
}

// 0x0000000000400675
//echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
//echo 2 | sudo tee /proc/sys/kernel/randomize_va_space

