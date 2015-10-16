#pragma once

#include <map>
#include <string>

static const int TD = 1;	// TRACE_DESC
static const int TF = 2;	// TRACE_FILE
static const int TI = 4;	// TRACE_IPC
static const int TN = 8;	// TRACE_NETWORK
static const int TP = 16;	// TRACE_PROCESS
static const int TS = 32;	// TRACE_SIGNAL
static const int TM = 64;	// TRACE_MEMORY
static const int NF = 128;	// SYSCALL_NEVER_FAILS
static const int MA = 256;	// MAX_ARGS
static const int SI = 512;	// STACKTRACE_INVALIDATE_CACHE
static const int SE = 1024;	// STACKTRACE_CAPTURE_ON_ENTER

static bool is_td(int type)
{
	return (type | TD) > 0;
}

static bool is_tf(int type)
{
	return (type | TF) > 0;
}

static bool is_ti(int type)
{
	return (type | TI) > 0;
}

static bool is_tn(int type)
{
	return (type | TN) > 0;
}

static bool is_tp(int type)
{
	return (type | TP) > 0;
}

static bool is_ts(int type)
{
	return (type | TS) > 0;
}

static bool is_tm(int type)
{
	return (type | TM) > 0;
}

static bool is_nf(int type)
{
	return (type | NF) > 0;
}

static bool is_ma(int type)
{
	return (type | MA) > 0;
}

static bool is_si(int type)
{
	return (type | SI) > 0;
}

static bool is_se(int type)
{
	return (type | SE) > 0;
}

class SyscallInfo
{
public:
	SyscallInfo(int arg_num, int type, const std::string& name)
		: arg_num_(arg_num)
		, type_(type)
		, name_(name)
	{
	}

	int arg_num() const
	{
		return arg_num_;
	}

	int type() const
	{
		return type_;
	}

	std::string name() const
	{
		return name_;
	}

private:
	int arg_num_;
	int type_;
	std::string name_;
};

static const std::map<int, SyscallInfo> syscall_table = {
{  0, SyscallInfo(3,	TD,		"read"			)},
{  1, SyscallInfo(3,	TD,		"write"			)},
{  2, SyscallInfo(3,	TD|TF,		"open"			)},
{  3, SyscallInfo(1,	TD,		"close"			)},
{  4, SyscallInfo(2,	TF,		"stat"			)},
{  5, SyscallInfo(2,	TD,		"fstat"			)},
{  6, SyscallInfo(2,	TF,		"lstat"			)},
{  7, SyscallInfo(3,	TD,		"poll"			)},
{  8, SyscallInfo(3,	TD,		"lseek"			)},
{  9, SyscallInfo(6,	TD|TM|SI,	"mmap"			)},
{ 10, SyscallInfo(3,	TM|SI,		"mprotect"		)},
{ 11, SyscallInfo(2,	TM|SI,		"munmap"		)},
{ 12, SyscallInfo(1,	TM|SI,		"brk"			)},
{ 13, SyscallInfo(4,	TS,		"rt_sigaction"		)},
{ 14, SyscallInfo(4,	TS,		"rt_sigprocmask"	)},
{ 15, SyscallInfo(0,	TS,		"rt_sigreturn"		)},
{ 16, SyscallInfo(3,	TD,		"ioctl"			)},
{ 17, SyscallInfo(4,	TD,		"pread"			)},
{ 18, SyscallInfo(4,	TD,		"pwrite"		)},
{ 19, SyscallInfo(3,	TD,		"readv"			)},
{ 20, SyscallInfo(3,	TD,		"writev"		)},
{ 21, SyscallInfo(2,	TF,		"access"		)},
{ 22, SyscallInfo(1,	TD,		"pipe"			)},
{ 23, SyscallInfo(5,	TD,		"select"		)},
{ 24, SyscallInfo(0,	0,		"sched_yield"		)},
{ 25, SyscallInfo(5,	TM|SI,		"mremap"		)},
{ 26, SyscallInfo(3,	TM,		"msync"			)},
{ 27, SyscallInfo(3,	TM,		"mincore"		)},
{ 28, SyscallInfo(3,	TM,		"madvise"		)},
{ 29, SyscallInfo(3,	TI,		"shmget"		)},
{ 30, SyscallInfo(3,	TI|TM|SI,	"shmat"			)},
{ 31, SyscallInfo(3,	TI,		"shmctl"		)},
{ 32, SyscallInfo(1,	TD,		"dup"			)},
{ 33, SyscallInfo(2,	TD,		"dup2"			)},
{ 34, SyscallInfo(0,	TS,		"pause"			)},
{ 35, SyscallInfo(2,	0,		"nanosleep"		)},
{ 36, SyscallInfo(2,	0,		"getitimer"		)},
{ 37, SyscallInfo(1,	0,		"alarm"			)},
{ 38, SyscallInfo(3,	0,		"setitimer"		)},
{ 39, SyscallInfo(0,	0,		"getpid"		)},
{ 40, SyscallInfo(4,	TD|TN,		"sendfile"		)},
{ 41, SyscallInfo(3,	TN,		"socket"		)},
{ 42, SyscallInfo(3,	TN,		"connect"		)},
{ 43, SyscallInfo(3,	TN,		"accept"		)},
{ 44, SyscallInfo(6,	TN,		"sendto"		)},
{ 45, SyscallInfo(6,	TN,		"recvfrom"		)},
{ 46, SyscallInfo(3,	TN,		"sendmsg"		)},
{ 47, SyscallInfo(3,	TN,		"recvmsg"		)},
{ 48, SyscallInfo(2,	TN,		"shutdown"		)},
{ 49, SyscallInfo(3,	TN,		"bind"			)},
{ 50, SyscallInfo(2,	TN,		"listen"		)},
{ 51, SyscallInfo(3,	TN,		"getsockname"		)},
{ 52, SyscallInfo(3,	TN,		"getpeername"		)},
{ 53, SyscallInfo(4,	TN,		"socketpair"		)},
{ 54, SyscallInfo(5,	TN,		"setsockopt"		)},
{ 55, SyscallInfo(5,	TN,		"getsockopt"		)},
{ 56, SyscallInfo(5,	TP,		"clone"			)},
{ 57, SyscallInfo(0,	TP,		"fork"			)},
{ 58, SyscallInfo(0,	TP,		"vfork"			)},
{ 59, SyscallInfo(3,	TF|TP|SE|SI,	"execve"		)},
{ 60, SyscallInfo(1,	TP|SE,		"_exit"			)},
{ 61, SyscallInfo(4,	TP,		"wait4"			)},
{ 62, SyscallInfo(2,	TS,		"kill"			)},
{ 63, SyscallInfo(1,	0,		"uname"			)},
{ 64, SyscallInfo(3,	TI,		"semget"		)},
{ 65, SyscallInfo(3,	TI,		"semop"			)},
{ 66, SyscallInfo(4,	TI,		"semctl"		)},
{ 67, SyscallInfo(1,	TI|TM|SI,	"shmdt"			)},
{ 68, SyscallInfo(2,	TI,		"msgget"		)},
{ 69, SyscallInfo(4,	TI,		"msgsnd"		)},
{ 70, SyscallInfo(5,	TI,		"msgrcv"		)},
{ 71, SyscallInfo(3,	TI,		"msgctl"		)},
{ 72, SyscallInfo(3,	TD,		"fcntl"			)},
{ 73, SyscallInfo(2,	TD,		"flock"			)},
{ 74, SyscallInfo(1,	TD,		"fsync"			)},
{ 75, SyscallInfo(1,	TD,		"fdatasync"		)},
{ 76, SyscallInfo(2,	TF,		"truncate"		)},
{ 77, SyscallInfo(2,	TD,		"ftruncate"		)},
{ 78, SyscallInfo(3,	TD,		"getdents"		)},
{ 79, SyscallInfo(2,	TF,		"getcwd"		)},
{ 80, SyscallInfo(1,	TF,		"chdir"			)},
{ 81, SyscallInfo(1,	TD,		"fchdir"		)},
{ 82, SyscallInfo(2,	TF,		"rename"		)},
{ 83, SyscallInfo(2,	TF,		"mkdir"			)},
{ 84, SyscallInfo(1,	TF,		"rmdir"			)},
{ 85, SyscallInfo(2,	TD|TF,		"creat"			)},
{ 86, SyscallInfo(2,	TF,		"link"			)},
{ 87, SyscallInfo(1,	TF,		"unlink"		)},
{ 88, SyscallInfo(2,	TF,		"symlink"		)},
{ 89, SyscallInfo(3,	TF,		"readlink"		)},
{ 90, SyscallInfo(2,	TF,		"chmod"			)},
{ 91, SyscallInfo(2,	TD,		"fchmod"		)},
{ 92, SyscallInfo(3,	TF,		"chown"			)},
{ 93, SyscallInfo(3,	TD,		"fchown"		)},
{ 94, SyscallInfo(3,	TF,		"lchown"		)},
{ 95, SyscallInfo(1,	0,		"umask"			)},
{ 96, SyscallInfo(2,	0,		"gettimeofday"		)},
{ 97, SyscallInfo(2,	0,		"getrlimit"		)},
{ 98, SyscallInfo(2,	0,		"getrusage"		)},
{ 99, SyscallInfo(1,	0,		"sysinfo"		)},
{100, SyscallInfo(1,	0,		"times"			)},
{101, SyscallInfo(4,	0,		"ptrace"		)},
{102, SyscallInfo(0,	NF,		"getuid"		)},
{103, SyscallInfo(3,	0,		"syslog"		)},
{104, SyscallInfo(0,	NF,		"getgid"		)},
{105, SyscallInfo(1,	0,		"setuid"		)},
{106, SyscallInfo(1,	0,		"setgid"		)},
{107, SyscallInfo(0,	NF,		"geteuid"		)},
{108, SyscallInfo(0,	NF,		"getegid"		)},
{109, SyscallInfo(2,	0,		"setpgid"		)},
{110, SyscallInfo(0,	0,		"getppid"		)},
{111, SyscallInfo(0,	0,		"getpgrp"		)},
{112, SyscallInfo(0,	0,		"setsid"		)},
{113, SyscallInfo(2,	0,		"setreuid"		)},
{114, SyscallInfo(2,	0,		"setregid"		)},
{115, SyscallInfo(2,	0,		"getgroups"		)},
{116, SyscallInfo(2,	0,		"setgroups"		)},
{117, SyscallInfo(3,	0,		"setresuid"		)},
{118, SyscallInfo(3,	0,		"getresuid"		)},
{119, SyscallInfo(3,	0,		"setresgid"		)},
{120, SyscallInfo(3,	0,		"getresgid"		)},
{121, SyscallInfo(1,	0,		"getpgid"		)},
{122, SyscallInfo(1,	NF,		"setfsuid"		)},
{123, SyscallInfo(1,	NF,		"setfsgid"		)},
{124, SyscallInfo(1,	0,		"getsid"		)},
{125, SyscallInfo(2,	0,		"capget"		)},
{126, SyscallInfo(2,	0,		"capset"		)},
{127, SyscallInfo(2,	TS,		"rt_sigpending"		)},
{128, SyscallInfo(4,	TS,		"rt_sigtimedwait"	)},
{129, SyscallInfo(3,	TS,		"rt_sigqueueinfo"	)},
{130, SyscallInfo(2,	TS,		"rt_sigsuspend"		)},
{131, SyscallInfo(2,	TS,		"sigaltstack"		)},
{132, SyscallInfo(2,	TF,		"utime"			)},
{133, SyscallInfo(3,	TF,		"mknod"			)},
{134, SyscallInfo(1,	TF,		"uselib"		)},
{135, SyscallInfo(1,	0,		"personality"		)},
{136, SyscallInfo(2,	0,		"ustat"			)},
{137, SyscallInfo(2,	TF,		"statfs"		)},
{138, SyscallInfo(2,	TD,		"fstatfs"		)},
{139, SyscallInfo(3,	0,		"sysfs"			)},
{140, SyscallInfo(2,	0,		"getpriority"		)},
{141, SyscallInfo(3,	0,		"setpriority"		)},
{142, SyscallInfo(2,	0,		"sched_setparam"	)},
{143, SyscallInfo(2,	0,		"sched_getparam"	)},
{144, SyscallInfo(3,	0,		"sched_setscheduler"	)},
{145, SyscallInfo(1,	0,		"sched_getscheduler"	)},
{146, SyscallInfo(1,	0,		"sched_get_priority_max")},
{147, SyscallInfo(1,	0,		"sched_get_priority_min")},
{148, SyscallInfo(2,	0,		"sched_rr_get_interval"	)},
{149, SyscallInfo(2,	TM,		"mlock"			)},
{150, SyscallInfo(2,	TM,		"munlock"		)},
{151, SyscallInfo(1,	TM,		"mlockall"		)},
{152, SyscallInfo(0,	TM,		"munlockall"		)},
{153, SyscallInfo(0,	0,		"vhangup"		)},
{154, SyscallInfo(3,	0,		"modify_ldt"		)},
{155, SyscallInfo(2,	TF,		"pivot_root"		)},
{156, SyscallInfo(1,	0,		"_sysctl"		)},
{157, SyscallInfo(5,	0,		"prctl"			)},
{158, SyscallInfo(2,	TP,		"arch_prctl"		)},
{159, SyscallInfo(1,	0,		"adjtimex"		)},
{160, SyscallInfo(2,	0,		"setrlimit"		)},
{161, SyscallInfo(1,	TF,		"chroot"		)},
{162, SyscallInfo(0,	0,		"sync"			)},
{163, SyscallInfo(1,	TF,		"acct"			)},
{164, SyscallInfo(2,	0,		"settimeofday"		)},
{165, SyscallInfo(5,	TF,		"mount"			)},
{166, SyscallInfo(2,	TF,		"umount2"		)},
{167, SyscallInfo(2,	TF,		"swapon"		)},
{168, SyscallInfo(1,	TF,		"swapoff"		)},
{169, SyscallInfo(4,	0,		"reboot"		)},
{170, SyscallInfo(2,	0,		"sethostname"		)},
{171, SyscallInfo(2,	0,		"setdomainname"		)},
{172, SyscallInfo(1,	0,		"iopl"			)},
{173, SyscallInfo(3,	0,		"ioperm"		)},
{174, SyscallInfo(2,	0,		"create_module"		)},
{175, SyscallInfo(3,	0,		"init_module"		)},
{176, SyscallInfo(2,	0,		"delete_module"		)},
{177, SyscallInfo(1,	0,		"get_kernel_syms"	)},
{178, SyscallInfo(5,	0,		"query_module"		)},
{179, SyscallInfo(4,	TF,		"quotactl"		)},
{180, SyscallInfo(3,	0,		"nfsservctl"		)},
{181, SyscallInfo(5,	0,		"getpmsg"		)},
{182, SyscallInfo(5,	0,		"putpmsg"		)},
{183, SyscallInfo(5,	0,		"afs_syscall"		)},
{184, SyscallInfo(3,	0,		"tuxcall"		)},
{185, SyscallInfo(3,	0,		"security"		)},
{186, SyscallInfo(0,	0,		"gettid"		)},
{187, SyscallInfo(3,	TD,		"readahead"		)},
{188, SyscallInfo(5,	TF,		"setxattr"		)},
{189, SyscallInfo(5,	TF,		"lsetxattr"		)},
{190, SyscallInfo(5,	TD,		"fsetxattr"		)},
{191, SyscallInfo(4,	TF,		"getxattr"		)},
{192, SyscallInfo(4,	TF,		"lgetxattr"		)},
{193, SyscallInfo(4,	TD,		"fgetxattr"		)},
{194, SyscallInfo(3,	TF,		"listxattr"		)},
{195, SyscallInfo(3,	TF,		"llistxattr"		)},
{196, SyscallInfo(3,	TD,		"flistxattr"		)},
{197, SyscallInfo(2,	TF,		"removexattr"		)},
{198, SyscallInfo(2,	TF,		"lremovexattr"		)},
{199, SyscallInfo(2,	TD,		"fremovexattr"		)},
{200, SyscallInfo(2,	TS,		"tkill"			)},
{201, SyscallInfo(1,	0,		"time"			)},
{202, SyscallInfo(6,	0,		"futex"			)},
{203, SyscallInfo(3,	0,		"sched_setaffinity"	)},
{204, SyscallInfo(3,	0,		"sched_getaffinity"	)},
{205, SyscallInfo(1,	0,		"set_thread_area"	)},
{206, SyscallInfo(2,	0,		"io_setup"		)},
{207, SyscallInfo(1,	0,		"io_destroy"		)},
{208, SyscallInfo(5,	0,		"io_getevents"		)},
{209, SyscallInfo(3,	0,		"io_submit"		)},
{210, SyscallInfo(3,	0,		"io_cancel"		)},
{211, SyscallInfo(1,	0,		"get_thread_area"	)},
{212, SyscallInfo(3,	0,		"lookup_dcookie"	)},
{213, SyscallInfo(1,	TD,		"epoll_create"		)},
{214, SyscallInfo(4,	0,		"epoll_ctl_old"		)},
{215, SyscallInfo(4,	0,		"epoll_wait_old"	)},
{216, SyscallInfo(5,	TM|SI,		"remap_file_pages"	)},
{217, SyscallInfo(3,	TD,		"getdents64"		)},
{218, SyscallInfo(1,	0,		"set_tid_address"	)},
{219, SyscallInfo(0,	0,		"restart_syscall"	)},
{220, SyscallInfo(4,	TI,		"semtimedop"		)},
{221, SyscallInfo(4,	TD,		"fadvise64"		)},
{222, SyscallInfo(3,	0,		"timer_create"		)},
{223, SyscallInfo(4,	0,		"timer_settime"		)},
{224, SyscallInfo(2,	0,		"timer_gettime"		)},
{225, SyscallInfo(1,	0,		"timer_getoverrun"	)},
{226, SyscallInfo(1,	0,		"timer_delete"		)},
{227, SyscallInfo(2,	0,		"clock_settime"		)},
{228, SyscallInfo(2,	0,		"clock_gettime"		)},
{229, SyscallInfo(2,	0,		"clock_getres"		)},
{230, SyscallInfo(4,	0,		"clock_nanosleep"	)},
{231, SyscallInfo(1,	TP|SE,		"exit_group"		)},
{232, SyscallInfo(4,	TD,		"epoll_wait"		)},
{233, SyscallInfo(4,	TD,		"epoll_ctl"		)},
{234, SyscallInfo(3,	TS,		"tgkill"		)},
{235, SyscallInfo(2,	TF,		"utimes"		)},
{236, SyscallInfo(5,	0,		"vserver"		)},
{237, SyscallInfo(6,	TM,		"mbind"			)},
{238, SyscallInfo(3,	TM,		"set_mempolicy"		)},
{239, SyscallInfo(5,	TM,		"get_mempolicy"		)},
{240, SyscallInfo(4,	0,		"mq_open"		)},
{241, SyscallInfo(1,	0,		"mq_unlink"		)},
{242, SyscallInfo(5,	0,		"mq_timedsend"		)},
{243, SyscallInfo(5,	0,		"mq_timedreceive"	)},
{244, SyscallInfo(2,	0,		"mq_notify"		)},
{245, SyscallInfo(3,	0,		"mq_getsetattr"		)},
{246, SyscallInfo(4,	0,		"kexec_load"		)},
{247, SyscallInfo(5,	TP,		"waitid"		)},
{248, SyscallInfo(5,	0,		"add_key"		)},
{249, SyscallInfo(4,	0,		"request_key"		)},
{250, SyscallInfo(5,	0,		"keyctl"		)},
{251, SyscallInfo(3,	0,		"ioprio_set"		)},
{252, SyscallInfo(2,	0,		"ioprio_get"		)},
{253, SyscallInfo(0,	TD,		"inotify_init"		)},
{254, SyscallInfo(3,	TD,		"inotify_add_watch"	)},
{255, SyscallInfo(2,	TD,		"inotify_rm_watch"	)},
{256, SyscallInfo(4,	TM,		"migrate_pages"		)},
{257, SyscallInfo(4,	TD|TF,		"openat"		)},
{258, SyscallInfo(3,	TD|TF,		"mkdirat"		)},
{259, SyscallInfo(4,	TD|TF,		"mknodat"		)},
{260, SyscallInfo(5,	TD|TF,		"fchownat"		)},
{261, SyscallInfo(3,	TD|TF,		"futimesat"		)},
{262, SyscallInfo(4,	TD|TF,		"newfstatat"		)},
{263, SyscallInfo(3,	TD|TF,		"unlinkat"		)},
{264, SyscallInfo(4,	TD|TF,		"renameat"		)},
{265, SyscallInfo(5,	TD|TF,		"linkat"		)},
{266, SyscallInfo(3,	TD|TF,		"symlinkat"		)},
{267, SyscallInfo(4,	TD|TF,		"readlinkat"		)},
{268, SyscallInfo(3,	TD|TF,		"fchmodat"		)},
{269, SyscallInfo(3,	TD|TF,		"faccessat"		)},
{270, SyscallInfo(6,	TD,		"pselect6"		)},
{271, SyscallInfo(5,	TD,		"ppoll"			)},
{272, SyscallInfo(1,	TP,		"unshare"		)},
{273, SyscallInfo(2,	0,		"set_robust_list"	)},
{274, SyscallInfo(3,	0,		"get_robust_list"	)},
{275, SyscallInfo(6,	TD,		"splice"		)},
{276, SyscallInfo(4,	TD,		"tee"			)},
{277, SyscallInfo(4,	TD,		"sync_file_range"	)},
{278, SyscallInfo(4,	TD,		"vmsplice"		)},
{279, SyscallInfo(6,	TM,		"move_pages"		)},
{280, SyscallInfo(4,	TD|TF,		"utimensat"		)},
{281, SyscallInfo(6,	TD,		"epoll_pwait"		)},
{282, SyscallInfo(3,	TD|TS,		"signalfd"		)},
{283, SyscallInfo(2,	TD,		"timerfd_create"	)},
{284, SyscallInfo(1,	TD,		"eventfd"		)},
{285, SyscallInfo(4,	TD,		"fallocate"		)},
{286, SyscallInfo(4,	TD,		"timerfd_settime"	)},
{287, SyscallInfo(2,	TD,		"timerfd_gettime"	)},
{288, SyscallInfo(4,	TN,		"accept4"		)},
{289, SyscallInfo(4,	TD|TS,		"signalfd4"		)},
{290, SyscallInfo(2,	TD,		"eventfd2"		)},
{291, SyscallInfo(1,	TD,		"epoll_create1"		)},
{292, SyscallInfo(3,	TD,		"dup3"			)},
{293, SyscallInfo(2,	TD,		"pipe2"			)},
{294, SyscallInfo(1,	TD,		"inotify_init1"		)},
{295, SyscallInfo(4,	TD,		"preadv"		)},
{296, SyscallInfo(4,	TD,		"pwritev"		)},
{297, SyscallInfo(4,	TP|TS,		"rt_tgsigqueueinfo"	)},
{298, SyscallInfo(5,	TD,		"perf_event_open"	)},
{299, SyscallInfo(5,	TN,		"recvmmsg"		)},
{300, SyscallInfo(2,	TD,		"fanotify_init"		)},
{301, SyscallInfo(5,	TD|TF,		"fanotify_mark"		)},
{302, SyscallInfo(4,	0,		"prlimit64"		)},
{303, SyscallInfo(5,	TD|TF,		"name_to_handle_at"	)},
{304, SyscallInfo(3,	TD,		"open_by_handle_at"	)},
{305, SyscallInfo(2,	0,		"clock_adjtime"		)},
{306, SyscallInfo(1,	TD,		"syncfs"		)},
{307, SyscallInfo(4,	TN,		"sendmmsg"		)},
{308, SyscallInfo(2,	TD,		"setns"			)},
{309, SyscallInfo(3,	0,		"getcpu"		)},
{310, SyscallInfo(6,	0,		"process_vm_readv"	)},
{311, SyscallInfo(6,	0,		"process_vm_writev"	)},
{312, SyscallInfo(5,	0,		"kcmp"			)},
{313, SyscallInfo(3,	TD,		"finit_module"		)},
{314, SyscallInfo(3,	0,		"sched_setattr"		)},
{315, SyscallInfo(4,	0,		"sched_getattr"		)},
{316, SyscallInfo(5,	TD|TF,		"renameat2"		)},
{317, SyscallInfo(3,	0,		"seccomp"		)},
{318, SyscallInfo(3,	0,		"getrandom"		)},
{319, SyscallInfo(2,	TD,		"memfd_create"		)},
{320, SyscallInfo(5,	TD,		"kexec_file_load"	)},
{321, SyscallInfo(3,	TD,		"bpf"			)},
{322, SyscallInfo(5,	TD|TF|TP|SE|SI,	"execveat"		)}};
