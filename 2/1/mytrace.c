#include <stdio.h>

#include <getopt.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

//#include "messages.h"

int run_child(const char* path, char* argv[])
{
	if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1)
	{
		// Some error happend with ptrace
		return -1;
	}

	execvp(path, argv);

	// Failed to execute
	return -1;
}

int main(int argn, char* argv[])
{
	// TODO : Use getopt to support policy file or other options

	if(argn < 2)
	{
		printf("Usage : mytrace [-options] PROG ARGS\n");
		return 0;
	}

	pid_t child_pid = fork();

	if(child_pid == 0)
	{
		// Run given process
		return run_child(argv[1], &argv[1]);
	}
	else
	{
		// Trace it! fuck yeah!	
	}

	return 0;
}
