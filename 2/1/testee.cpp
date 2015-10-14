#include <iostream>

int main(int argn, char* argv[])
{
	std::cout << "argn : " << argn << std::endl;

	for(int i = 0; i < argn; ++i)
	{
		std::cout << "argv[" << i << "] : " << argv[i] << std::endl;
	}

	return 0;
}
