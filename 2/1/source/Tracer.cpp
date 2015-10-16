#include "Tracer.h"

#include <cstdio>

#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include "syscallent.h"

typedef user_regs_struct Regs;

bool Tracer::continue_trace_syscall(int child_pid)
{
        if(ptrace(PTRACE_SYSCALL, child_pid, nullptr, nullptr) == -1)
        {
                std::cerr << "Error : Failed to continue tracing." << std::endl;
                return false;
        }

        return true;
}

int Tracer::do_trace(int child_pid, po::variables_map& /*vm*/)
{
        int status;
        bool is_in_syscall = false/*, is_child_executed = false*/;
        Regs regs;

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
                        ptrace(PTRACE_SETREGS, child_pid, nullptr, &regs);

                }
                else
                {
                        // Returned from syscall: get return value
			print_syscall(regs);
                }

                if(!continue_trace_syscall(child_pid))
                {
                        break;
                }
        }

        return 0;
}

void pretty_print_register(unsigned long long reg)
{
	fprintf(stderr, (static_cast<long long>(reg) > 0xffff ? "0x%llx" : "%lld"), static_cast<long long>(reg));
}

void Tracer::print_syscall(Regs& regs)
{
	auto syscall_itr = syscall_table.find(regs.orig_rax);
	SyscallInfo syscall_info = (syscall_itr == syscall_table.end() ? SyscallInfo(0, 0, "sys_unknown") : syscall_itr->second);

	std::cerr << syscall_info.name() << "(";
	std::array<unsigned long long, 6> args = {{regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9}};

	for(int i = 0; i < syscall_info.arg_num(); ++i)
	{
		pretty_print_register(args[i]);

		if(i != syscall_info.arg_num() - 1)
		{
			std::cerr << ", ";
		}
	}

	std::cerr << ") = ";
	pretty_print_register(regs.rax);
	std::cerr << std::endl;
}
