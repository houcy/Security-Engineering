#include <stdio.h>
#include <stdlib.h>
void main()
{
        char name[64];
        printf("buffer address: %p\n", name);  //print address of buffer
        gets(name);
    	printf("%s\n", name);
   	exit(1);
}
