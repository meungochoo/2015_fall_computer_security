#include <iostream>
#include <string>
#include <vector>

#include <boost/program_options.hpp>

#include <getopt.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

//#include "messages.h"

namespace po = boost::program_options;

int run_child(const std::string& path, char* argv[])
{
	if(ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1)
	{
		// Some error happend with ptrace
		return -1;
	}

	execvp(path.c_str(), argv);

	// Failed to execute
	return -1;
}

po::variables_map parse_program_options(int argn, char* argv[])
{
	po::options_description desc("Allowed options");
	desc.add_options()
		("help,h", "Help messages.")
		("commands,c", po::value<std::vector<std::string>>()->required(), "Commands to trace. Include execution path and arguments.");

	po::positional_options_description p_desc;
	p_desc.add("commands", -1);

	po::variables_map vm;
	std::stringstream help_msg;
	help_msg << "Usage : mytrace [-options] commands\n" << desc << std::endl;

	try
	{
		po::store(po::command_line_parser(argn, argv).options(desc).positional(p_desc).run(), vm);
		po::notify(vm);
	}
	catch(po::required_option &e)
	{
		std::cout << help_msg.str();
	}
	catch(po::error &e)
	{
		std::cout << help_msg.str();
	}

	if(vm.count("help") && vm.count("commands"))
	{
		std::cout << help_msg.str();
	}

	return vm;
}

int main(int argn, char* argv[])
{
	po::variables_map vm = parse_program_options(argn, argv);

	if(vm.empty() || vm.count("help"))
	{
		return 0;
	}

	pid_t child_pid = fork();

	if(child_pid == 0)
	{
		// Make args string vector into null-terminated char* array
		std::vector<std::string> args_vec = vm["commands"].as<std::vector<std::string>>();
		std::vector<char*> args;

		for(auto& arg : args_vec)
		{
			args.push_back(const_cast<char*>(arg.c_str()));
		}

		args.push_back(nullptr);

		// Run given process
		return run_child(args_vec.front(), args.data());
	}
	else
	{
		// Trace it! fuck yeah!	
	}

	return 0;
}
