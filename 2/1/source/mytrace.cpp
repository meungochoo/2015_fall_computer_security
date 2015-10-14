#include <iostream>
#include <string>
#include <vector>

#include <boost/program_options.hpp>

#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

namespace po = boost::program_options;

bool run_child(const std::string& path, char* argv[])
{
	if(ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1)
	{
		// Some error happend with ptrace
		return false;
	}

	execvp(path.c_str(), argv);

	// Failed to execute
	return false;
}

bool continue_trace_syscall(int child_pid)
{
	if(ptrace(PTRACE_SYSCALL, child_pid, nullptr, nullptr) == -1)
	{
		std::cerr << "Error : Failed to continue tracing." << std::endl;
		return false;
	}

	return true;
}

int do_trace(int child_pid, po::variables_map& vm)
{
	int status;
	bool is_in_syscall = false, is_child_executed = false;
	user_regs_struct regs;

	// Trace syscalls until child process ends
	while(true)
	{
		waitpid(child_pid, &status, 0);

		if(WIFEXITED(status) || WIFSIGNALED(status))
		{
			break;
		}

		is_in_syscall = !is_in_syscall;

		if(ptrace(PTRACE_GETREGS, child_pid, nullptr, &regs) == -1)
		{
			std::cerr << "Error : Failed to get register info." << std::endl;
			break;
		}

		// TODO : Ignore syscalls until function main is called
		
		// TODO : Implement additional features...
		if(!is_in_syscall)
		{
			// Entered to syscall: modify syscall number if needed
		}
		else
		{
			// Returned from syscall: get return value
			std::cerr << "syscall[" << regs.orig_rax << "](unimplemented) = ";
			fprintf(stderr, (static_cast<long long>(regs.rax) > 1024 ? "0x%llx\n" : "%lld\n"), static_cast<long long>(regs.rax));
		}

		if(!continue_trace_syscall(child_pid))
		{
			break;
		}
	}

	return 0;
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
		if(!run_child(args_vec.front(), args.data()))
		{
			std::cerr << "Error : Failed to execute and trace the given commands." << std::endl;
		}
	}
	else if(child_pid == -1)
	{
		std::cerr << "Error : Failed to execute the given commands." << std::endl;
	}
	else
	{
		do_trace(child_pid, vm);
	}

	return 0;
}
