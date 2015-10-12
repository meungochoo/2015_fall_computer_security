#include <stdio.h>

int main(int argn, char* argv[])
{
	printf("argn : %d\n", argn);

	for(int i = 0; i < argn; ++i)
	{
		printf("argv[%d] : %s\n", i, argv[i]);
	}

	return 0;
}
