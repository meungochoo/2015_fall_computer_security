#pragma once

#include <iostream>

#include <boost/program_options.hpp>

namespace po = boost::program_options;

struct user_regs_struct;
typedef user_regs_struct Regs;

class Tracer
{
public:
	static bool continue_trace_syscall(int child_pid);
	int do_trace(int child_pid, po::variables_map& vm);
	

private:
	void print_syscall(Regs& regs);
};
