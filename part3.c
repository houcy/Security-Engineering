#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void function1(unsigned char *ptr)
{
	char charbuf[80]; //line1
	//int *pointer; 
	//*pointer = charbuf + 17; 
	//*pointer -= 118; //line4
	(*(unsigned long *)(charbuf + 80 + 8)) = (unsigned long *)0x0000000000400614;
	printf("Inside function1. Must not return to main()\n");
	printf("String:%s\n",ptr);
}

void target()
{
	printf("This is the target function\n");
	exit(0);
}
int main(int argc, unsigned char **argv)
{
	unsigned char buff[256];
	memset(buff,0,256);
	printf("Input string:");
	gets(buff);
	function1(buff);
	printf("back to main!\n");
	return 0;
}


//echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
//echo 2 | sudo tee /proc/sys/kernel/randomize_va_space

