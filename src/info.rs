//! Structures that aid in producing human-readable trace data from intercepted
//! syscalls.
use std::collections::HashMap;

/// Valid FormatSpecifiers.
///
/// Unless otherwise specified, values are formatted before syscall execution
/// and not updated after syscall execution (the same value is output).
pub enum FmtSpec {
    /// Hex is just a hexadecimal number.
    Hex,

    /// Oct is just an octal number.
    Oct,

    /// FD is a file descriptor.
    FD,

    // ReadBuffer is a buffer for a read-style call. The syscall return
    // value is used for the length.
    /// Formatted after syscall execution.
    ReadBuffer,

    /// WriteBuffer is a buffer for a write-style call. The following arg is
    /// used for the length.
    ///
    /// Contents omitted after syscall execution.
    WriteBuffer,

    /// ReadIOVec is a pointer to a struct iovec for a writev-style call.
    /// The following arg is used for the length. The return value is used
    /// for the total length.
    ///
    /// Complete contents only formatted after syscall execution.
    ReadIOVec,

    /// WriteIOVec is a pointer to a struct iovec for a writev-style call.
    /// The following arg is used for the length.
    ///
    /// Complete contents only formatted before syscall execution, omitted
    /// after.
    WriteIOVec,

    /// IOVec is a generic pointer to a struct iovec. Contents are not dumped.
    IOVec,

    /// SendMsgHdr is a pointer to a struct msghdr for a sendmsg-style call.
    /// Contents formatted only before syscall execution, omitted after.
    SendMsgHdr,

    /// RecvMsgHdr is a pointer to a struct msghdr for a recvmsg-style call.
    /// Contents formatted only after syscall execution.
    RecvMsgHdr,

    /// Path is a pointer to a char* path.
    Path,

    /// PostPath is a pointer to a char* path, formatted after syscall
    /// execution.
    PostPath,

    /// ExecveStringVector is a NULL-terminated array of strings. Enforces
    /// the maximum execve array length.
    ExecveStringVector,

    /// PipeFDs is an array of two FDs, formatted after syscall execution.
    PipeFDs,

    /// Uname is a pointer to a struct uname, formatted after syscall execution.
    Uname,

    /// Stat is a pointer to a struct stat, formatted after syscall execution.
    Stat,

    /// SockAddr is a pointer to a struct sockaddr. The following arg is
    /// used for length.
    SockAddr,

    /// PostSockAddr is a pointer to a struct sockaddr, formatted after
    /// syscall execution. The following arg is a pointer to the socklen_t
    /// length.
    PostSockAddr,

    /// SockLen is a pointer to a socklen_t, formatted before and after
    /// syscall execution.
    SockLen,

    /// SockFamily is a socket protocol family value.
    SockFamily,

    /// SockType is a socket type and flags value.
    SockType,

    /// SockProtocol is a socket protocol value. Argument n-2 is the socket
    /// protocol family.
    SockProtocol,

    /// SockFlags are socket flags.
    SockFlags,

    /// Timespec is a pointer to a struct timespec.
    Timespec,

    /// PostTimespec is a pointer to a struct timespec, formatted after
    /// syscall execution.
    PostTimespec,

    /// UTimeTimespec is a pointer to a struct timespec. Formatting includes
    /// UTIME_NOW and UTIME_OMIT.
    UTimeTimespec,

    /// ItimerVal is a pointer to a struct itimerval.
    ItimerVal,

    /// PostItimerVal is a pointer to a struct itimerval, formatted after
    /// syscall execution.
    PostItimerVal,

    /// ItimerSpec is a pointer to a struct itimerspec.
    ItimerSpec,

    /// PostItimerSpec is a pointer to a struct itimerspec, formatted after
    /// syscall execution.
    PostItimerSpec,

    /// Timeval is a pointer to a struct timeval, formatted before and after
    /// syscall execution.
    Timeval,

    /// Utimbuf is a pointer to a struct utimbuf.
    Utimbuf,

    /// Rusage is a struct rusage, formatted after syscall execution.
    Rusage,

    /// CloneFlags are clone(2) flags.
    CloneFlags,

    /// OpenFlags are open(2) flags.
    OpenFlags,

    /// Mode is a mode_t.
    Mode,

    /// FutexOp is the futex(2) operation.
    FutexOp,

    /// PtraceRequest is the ptrace(2) request.
    PtraceRequest,

    /// ItimerType is an itimer type (ITIMER_REAL, etc).
    ItimerType,

    /// Signal is a signal number.
    Signal,

    /// SignalMaskAction is a signal mask action passed to rt_sigprocmask(2).
    SignalMaskAction,

    /// SigSet is a signal set.
    SigSet,

    /// PostSigSet is a signal set, formatted after syscall execution.
    PostSigSet,

    /// SigAction is a struct sigaction.
    SigAction,

    /// PostSigAction is a struct sigaction, formatted after syscall execution.
    PostSigAction,

    /// CapHeader is a cap_user_header_t.
    CapHeader,

    /// CapData is the data argument to capget(2)/capset(2). The previous
    /// argument must be CapHeader.
    CapData,

    /// PostCapData is the data argument to capget(2)/capset(2), formatted
    /// after syscall execution. The previous argument must be CapHeader.
    PostCapData,

    /// PollFDs is an array of struct pollfd. The number of entries in the
    /// array is in the next argument.
    PollFDs,

    /// SelectFDSet is an fd_set argument in select(2)/pselect(2). The
    /// number of FDs represented must be the first argument.
    SelectFDSet,

    /// GetSockOptVal is the optval argument in getsockopt(2).
    ///
    /// Formatted after syscall execution.
    GetSockOptVal,

    /// SetSockOptVal is the optval argument in setsockopt(2).
    ///
    /// Contents omitted after syscall execution.
    SetSockOptVal,

    /// SockOptLevel is the level argument in getsockopt(2) and
    /// setsockopt(2).
    SockOptLevel,

    /// SockOptLevel is the optname argument in getsockopt(2) and
    /// setsockopt(2).
    SockOptName,

    /// EpollCtlOp is the op argument to epoll_ctl(2).
    EpollCtlOp,

    /// EpollEvent is the event argument in epoll_ctl(2).
    EpollEvent,

    /// EpollEvents is an array of struct epoll_event. It is the events
    /// argument in epoll_wait(2)/epoll_pwait(2).
    EpollEvents,

    /// MmapProt is the protection argument in mmap(2).
    MmapProt,

    /// MmapFlags is the flags argument in mmap(2).
    MmapFlags,

    /// CloseRangeFlags are close_range(2) flags.
    CloseRangeFlags,
}

use self::FmtSpec::*;

lazy_static! {
    /// Map from a syscall's number to its name and a vector of its argument formats.
    pub static ref SYSCALL_MAP: HashMap<u64, (&'static str, Vec<FmtSpec>)> = {
        HashMap::from([
            (0, ("read", vec![FD, ReadBuffer, Hex])),
            (1, ("write", vec![FD, WriteBuffer, Hex])),
            (2, ("open", vec![Path, OpenFlags, Mode])),
            (3, ("close", vec![FD])),
            (4, ("stat", vec![Path, Stat])),
            (5, ("fstat", vec![FD, Stat])),
            (6, ("lstat", vec![Path, Stat])),
            (7, ("poll", vec![PollFDs, Hex, Hex])),
            (8, ("lseek", vec![Hex, Hex, Hex])),
            (9, ("mmap", vec![Hex, Hex, MmapProt, MmapFlags, FD, Hex])),
            (10, ("mprotect", vec![Hex, Hex, Hex])),
            (11, ("munmap", vec![Hex, Hex])),
            (12, ("brk", vec![Hex])),
            (13, ("rt_sigaction", vec![Signal, SigAction, PostSigAction, Hex])),
            (14, ("rt_sigprocmask", vec![SignalMaskAction, SigSet, PostSigSet, Hex])),
            (15, ("rt_sigreturn", vec![])),
            (16, ("ioctl", vec![FD, Hex, Hex])),
            (17, ("pread64", vec![FD, ReadBuffer, Hex, Hex])),
            (18, ("pwrite64", vec![FD, WriteBuffer, Hex, Hex])),
            (19, ("readv", vec![FD, ReadIOVec, Hex])),
            (20, ("writev", vec![FD, WriteIOVec, Hex])),
            (21, ("access", vec![Path, Oct])),
            (22, ("pipe", vec![PipeFDs])),
            (23, ("select", vec![Hex, SelectFDSet, SelectFDSet, SelectFDSet, Timeval])),
            (24, ("sched_yield", vec![])),
            (25, ("mremap", vec![Hex, Hex, Hex, Hex, Hex])),
            (26, ("msync", vec![Hex, Hex, Hex])),
            (27, ("mincore", vec![Hex, Hex, Hex])),
            (28, ("madvise", vec![Hex, Hex, Hex])),
            (29, ("shmget", vec![Hex, Hex, Hex])),
            (30, ("shmat", vec![Hex, Hex, Hex])),
            (31, ("shmctl", vec![Hex, Hex, Hex])),
            (32, ("dup", vec![FD])),
            (33, ("dup2", vec![FD, FD])),
            (34, ("pause", vec![])),
            (35, ("nanosleep", vec![Timespec, PostTimespec])),
            (36, ("getitimer", vec![ItimerType, PostItimerVal])),
            (37, ("alarm", vec![Hex])),
            (38, ("setitimer", vec![ItimerType, ItimerVal, PostItimerVal])),
            (39, ("getpid", vec![])),
            (40, ("sendfile", vec![FD, FD, Hex, Hex])),
            (41, ("socket", vec![SockFamily, SockType, SockProtocol])),
            (42, ("connect", vec![FD, SockAddr, Hex])),
            (43, ("accept", vec![FD, PostSockAddr, SockLen])),
            (44, ("sendto", vec![FD, Hex, Hex, Hex, SockAddr, Hex])),
            (45, ("recvfrom", vec![FD, Hex, Hex, Hex, PostSockAddr, SockLen])),
            (46, ("sendmsg", vec![FD, SendMsgHdr, Hex])),
            (47, ("recvmsg", vec![FD, RecvMsgHdr, Hex])),
            (48, ("shutdown", vec![FD, Hex])),
            (49, ("bind", vec![FD, SockAddr, Hex])),
            (50, ("listen", vec![FD, Hex])),
            (51, ("getsockname", vec![FD, PostSockAddr, SockLen])),
            (52, ("getpeername", vec![FD, PostSockAddr, SockLen])),
            (53, ("socketpair", vec![SockFamily, SockType, SockProtocol, Hex])),
            (54, ("setsockopt", vec![FD, SockOptLevel, SockOptName, SetSockOptVal, Hex])),
            (55, ("getsockopt", vec![FD, SockOptLevel, SockOptName, GetSockOptVal, SockLen])),
            (56, ("clone", vec![CloneFlags, Hex, Hex, Hex, Hex])),
            (57, ("fork", vec![])),
            (58, ("vfork", vec![])),
            (59, ("execve", vec![Path, ExecveStringVector, ExecveStringVector])),
            (60, ("exit", vec![Hex])),
            (61, ("wait4", vec![Hex, Hex, Hex, Rusage])),
            (62, ("kill", vec![Hex, Signal])),
            (63, ("uname", vec![Uname])),
            (64, ("semget", vec![Hex, Hex, Hex])),
            (65, ("semop", vec![Hex, Hex, Hex])),
            (66, ("semctl", vec![Hex, Hex, Hex, Hex])),
            (67, ("shmdt", vec![Hex])),
            (68, ("msgget", vec![Hex, Hex])),
            (69, ("msgsnd", vec![Hex, Hex, Hex, Hex])),
            (70, ("msgrcv", vec![Hex, Hex, Hex, Hex, Hex])),
            (71, ("msgctl", vec![Hex, Hex, Hex])),
            (72, ("fcntl", vec![FD, Hex, Hex])),
            (73, ("flock", vec![FD, Hex])),
            (74, ("fsync", vec![FD])),
            (75, ("fdatasync", vec![FD])),
            (76, ("truncate", vec![Path, Hex])),
            (77, ("ftruncate", vec![FD, Hex])),
            (78, ("getdents", vec![FD, Hex, Hex])),
            (79, ("getcwd", vec![PostPath, Hex])),
            (80, ("chdir", vec![Path])),
            (81, ("fchdir", vec![FD])),
            (82, ("rename", vec![Path, Path])),
            (83, ("mkdir", vec![Path, Oct])),
            (84, ("rmdir", vec![Path])),
            (85, ("creat", vec![Path, Oct])),
            (86, ("link", vec![Path, Path])),
            (87, ("unlink", vec![Path])),
            (88, ("symlink", vec![Path, Path])),
            (89, ("readlink", vec![Path, ReadBuffer, Hex])),
            (90, ("chmod", vec![Path, Mode])),
            (91, ("fchmod", vec![FD, Mode])),
            (92, ("chown", vec![Path, Hex, Hex])),
            (93, ("fchown", vec![FD, Hex, Hex])),
            (94, ("lchown", vec![Path, Hex, Hex])),
            (95, ("umask", vec![Hex])),
            (96, ("gettimeofday", vec![Timeval, Hex])),
            (97, ("getrlimit", vec![Hex, Hex])),
            (98, ("getrusage", vec![Hex, Rusage])),
            (99, ("sysinfo", vec![Hex])),
            (100, ("times", vec![Hex])),
            (101, ("ptrace", vec![PtraceRequest, Hex, Hex, Hex])),
            (102, ("getuid", vec![])),
            (103, ("syslog", vec![Hex, Hex, Hex])),
            (104, ("getgid", vec![])),
            (105, ("setuid", vec![Hex])),
            (106, ("setgid", vec![Hex])),
            (107, ("geteuid", vec![])),
            (108, ("getegid", vec![])),
            (109, ("setpgid", vec![Hex, Hex])),
            (110, ("getppid", vec![])),
            (111, ("getpgrp", vec![])),
            (112, ("setsid", vec![])),
            (113, ("setreuid", vec![Hex, Hex])),
            (114, ("setregid", vec![Hex, Hex])),
            (115, ("getgroups", vec![Hex, Hex])),
            (116, ("setgroups", vec![Hex, Hex])),
            (117, ("setresuid", vec![Hex, Hex, Hex])),
            (118, ("getresuid", vec![Hex, Hex, Hex])),
            (119, ("setresgid", vec![Hex, Hex, Hex])),
            (120, ("getresgid", vec![Hex, Hex, Hex])),
            (121, ("getpgid", vec![Hex])),
            (122, ("setfsuid", vec![Hex])),
            (123, ("setfsgid", vec![Hex])),
            (124, ("getsid", vec![Hex])),
            (125, ("capget", vec![CapHeader, PostCapData])),
            (126, ("capset", vec![CapHeader, CapData])),
            (127, ("rt_sigpending", vec![Hex])),
            (128, ("rt_sigtimedwait", vec![SigSet, Hex, Timespec, Hex])),
            (129, ("rt_sigqueueinfo", vec![Hex, Signal, Hex])),
            (130, ("rt_sigsuspend", vec![Hex])),
            (131, ("sigaltstack", vec![Hex, Hex])),
            (132, ("utime", vec![Path, Utimbuf])),
            (133, ("mknod", vec![Path, Mode, Hex])),
            (134, ("uselib", vec![Hex])),
            (135, ("personality", vec![Hex])),
            (136, ("ustat", vec![Hex, Hex])),
            (137, ("statfs", vec![Path, Hex])),
            (138, ("fstatfs", vec![FD, Hex])),
            (139, ("sysfs", vec![Hex, Hex, Hex])),
            (140, ("getpriority", vec![Hex, Hex])),
            (141, ("setpriority", vec![Hex, Hex, Hex])),
            (142, ("sched_setparam", vec![Hex, Hex])),
            (143, ("sched_getparam", vec![Hex, Hex])),
            (144, ("sched_setscheduler", vec![Hex, Hex, Hex])),
            (145, ("sched_getscheduler", vec![Hex])),
            (146, ("sched_get_priority_max", vec![Hex])),
            (147, ("sched_get_priority_min", vec![Hex])),
            (148, ("sched_rr_get_interval", vec![Hex, Hex])),
            (149, ("mlock", vec![Hex, Hex])),
            (150, ("munlock", vec![Hex, Hex])),
            (151, ("mlockall", vec![Hex])),
            (152, ("munlockall", vec![])),
            (153, ("vhangup", vec![])),
            (154, ("modify_ldt", vec![Hex, Hex, Hex])),
            (155, ("pivot_root", vec![Path, Path])),
            (156, ("_sysctl", vec![Hex])),
            (157, ("prctl", vec![Hex, Hex, Hex, Hex, Hex])),
            (158, ("arch_prctl", vec![Hex, Hex])),
            (159, ("adjtimex", vec![Hex])),
            (160, ("setrlimit", vec![Hex, Hex])),
            (161, ("chroot", vec![Path])),
            (162, ("sync", vec![])),
            (163, ("acct", vec![Hex])),
            (164, ("settimeofday", vec![Timeval, Hex])),
            (165, ("mount", vec![Path, Path, Path, Hex, Path])),
            (166, ("umount2", vec![Path, Hex])),
            (167, ("swapon", vec![Hex, Hex])),
            (168, ("swapoff", vec![Hex])),
            (169, ("reboot", vec![Hex, Hex, Hex, Hex])),
            (170, ("sethostname", vec![Hex, Hex])),
            (171, ("setdomainname", vec![Hex, Hex])),
            (172, ("iopl", vec![Hex])),
            (173, ("ioperm", vec![Hex, Hex, Hex])),
            (174, ("create_module", vec![Path, Hex])),
            (175, ("init_module", vec![Hex, Hex, Hex])),
            (176, ("delete_module", vec![Hex, Hex])),
            (177, ("get_kernel_syms", vec![Hex])),
            // 178: query_module (only present in Linux < 2.6)
            (179, ("quotactl", vec![Hex, Hex, Hex, Hex])),
            (180, ("nfsservctl", vec![Hex, Hex, Hex])),
            // 181: getpmsg (not implemented in the Linux kernel)
            // 182: putpmsg (not implemented in the Linux kernel)
            // 183: afs_syscall (not implemented in the Linux kernel)
            // 184: tuxcall (not implemented in the Linux kernel)
            // 185: security (not implemented in the Linux kernel)
            (186, ("gettid", vec![])),
            (187, ("readahead", vec![Hex, Hex, Hex])),
            (188, ("setxattr", vec![Path, Path, Hex, Hex, Hex])),
            (189, ("lsetxattr", vec![Path, Path, Hex, Hex, Hex])),
            (190, ("fsetxattr", vec![FD, Path, Hex, Hex, Hex])),
            (191, ("getxattr", vec![Path, Path, Hex, Hex])),
            (192, ("lgetxattr", vec![Path, Path, Hex, Hex])),
            (193, ("fgetxattr", vec![FD, Path, Hex, Hex])),
            (194, ("listxattr", vec![Path, Path, Hex])),
            (195, ("llistxattr", vec![Path, Path, Hex])),
            (196, ("flistxattr", vec![FD, Path, Hex])),
            (197, ("removexattr", vec![Path, Path])),
            (198, ("lremovexattr", vec![Path, Path])),
            (199, ("fremovexattr", vec![FD, Path])),
            (200, ("tkill", vec![Hex, Signal])),
            (201, ("time", vec![Hex])),
            (202, ("futex", vec![Hex, FutexOp, Hex, Timespec, Hex, Hex])),
            (203, ("sched_setaffinity", vec![Hex, Hex, Hex])),
            (204, ("sched_getaffinity", vec![Hex, Hex, Hex])),
            (205, ("set_thread_area", vec![Hex])),
            (206, ("io_setup", vec![Hex, Hex])),
            (207, ("io_destroy", vec![Hex])),
            (208, ("io_getevents", vec![Hex, Hex, Hex, Hex, Timespec])),
            (209, ("io_submit", vec![Hex, Hex, Hex])),
            (210, ("io_cancel", vec![Hex, Hex, Hex])),
            (211, ("get_thread_area", vec![Hex])),
            (212, ("lookup_dcookie", vec![Hex, Hex, Hex])),
            (213, ("epoll_create", vec![Hex])),
            // 214: epoll_ctl_old (not implemented in the Linux kernel)
            // 215: epoll_wait_old (not implemented in the Linux kernel)
            (216, ("remap_file_pages", vec![Hex, Hex, Hex, Hex, Hex])),
            (217, ("getdents64", vec![FD, Hex, Hex])),
            (218, ("set_tid_address", vec![Hex])),
            (219, ("restart_syscall", vec![])),
            (220, ("semtimedop", vec![Hex, Hex, Hex, Hex])),
            (221, ("fadvise64", vec![FD, Hex, Hex, Hex])),
            (222, ("timer_create", vec![Hex, Hex, Hex])),
            (223, ("timer_settime", vec![Hex, Hex, ItimerSpec, PostItimerSpec])),
            (224, ("timer_gettime", vec![Hex, PostItimerSpec])),
            (225, ("timer_getoverrun", vec![Hex])),
            (226, ("timer_delete", vec![Hex])),
            (227, ("clock_settime", vec![Hex, Timespec])),
            (228, ("clock_gettime", vec![Hex, PostTimespec])),
            (229, ("clock_getres", vec![Hex, PostTimespec])),
            (230, ("clock_nanosleep", vec![Hex, Hex, Timespec, PostTimespec])),
            (231, ("exit_group", vec![Hex])),
            (232, ("epoll_wait", vec![FD, EpollEvents, Hex, Hex])),
            (233, ("epoll_ctl", vec![FD, EpollCtlOp, FD, EpollEvent])),
            (234, ("tgkill", vec![Hex, Hex, Signal])),
            (235, ("utimes", vec![Path, Timeval])),
            // 236: vserver (not implemented in the Linux kernel)
            (237, ("mbind", vec![Hex, Hex, Hex, Hex, Hex, Hex])),
            (238, ("set_mempolicy", vec![Hex, Hex, Hex])),
            (239, ("get_mempolicy", vec![Hex, Hex, Hex, Hex, Hex])),
            (240, ("mq_open", vec![Hex, Hex, Hex, Hex])),
            (241, ("mq_unlink", vec![Hex])),
            (242, ("mq_timedsend", vec![Hex, Hex, Hex, Hex, Hex])),
            (243, ("mq_timedreceive", vec![Hex, Hex, Hex, Hex, Hex])),
            (244, ("mq_notify", vec![Hex, Hex])),
            (245, ("mq_getsetattr", vec![Hex, Hex, Hex])),
            (246, ("kexec_load", vec![Hex, Hex, Hex, Hex])),
            (247, ("waitid", vec![Hex, Hex, Hex, Hex, Rusage])),
            (248, ("add_key", vec![Hex, Hex, Hex, Hex, Hex])),
            (249, ("request_key", vec![Hex, Hex, Hex, Hex])),
            (250, ("keyctl", vec![Hex, Hex, Hex, Hex, Hex])),
            (251, ("ioprio_set", vec![Hex, Hex, Hex])),
            (252, ("ioprio_get", vec![Hex, Hex])),
            (253, ("inotify_init", vec![])),
            (254, ("inotify_add_watch", vec![Hex, Path, Hex])),
            (255, ("inotify_rm_watch", vec![Hex, Hex])),
            (256, ("migrate_pages", vec![Hex, Hex, Hex, Hex])),
            (257, ("openat", vec![FD, Path, OpenFlags, Mode])),
            (258, ("mkdirat", vec![FD, Path, Hex])),
            (259, ("mknodat", vec![FD, Path, Mode, Hex])),
            (260, ("fchownat", vec![FD, Path, Hex, Hex, Hex])),
            (261, ("futimesat", vec![FD, Path, Hex])),
            (262, ("newfstatat", vec![FD, Path, Stat, Hex])),
            (263, ("unlinkat", vec![FD, Path, Hex])),
            (264, ("renameat", vec![FD, Path, Hex, Path])),
            (265, ("linkat", vec![FD, Path, Hex, Path, Hex])),
            (266, ("symlinkat", vec![Path, FD, Path])),
            (267, ("readlinkat", vec![FD, Path, ReadBuffer, Hex])),
            (268, ("fchmodat", vec![FD, Path, Mode])),
            (269, ("faccessat", vec![FD, Path, Oct, Hex])),
            (270, ("pselect6", vec![Hex, SelectFDSet, SelectFDSet, SelectFDSet, Timespec, SigSet])),
            (271, ("ppoll", vec![PollFDs, Hex, Timespec, SigSet, Hex])),
            (272, ("unshare", vec![CloneFlags])),
            (273, ("set_robust_list", vec![Hex, Hex])),
            (274, ("get_robust_list", vec![Hex, Hex, Hex])),
            (275, ("splice", vec![FD, Hex, FD, Hex, Hex, Hex])),
            (276, ("tee", vec![FD, FD, Hex, Hex])),
            (277, ("sync_file_range", vec![FD, Hex, Hex, Hex])),
            (278, ("vmsplice", vec![FD, Hex, Hex, Hex])),
            (279, ("move_pages", vec![Hex, Hex, Hex, Hex, Hex, Hex])),
            (280, ("utimensat", vec![FD, Path, UTimeTimespec, Hex])),
            (281, ("epoll_pwait", vec![FD, EpollEvents, Hex, Hex, SigSet, Hex])),
            (282, ("signalfd", vec![Hex, Hex, Hex])),
            (283, ("timerfd_create", vec![Hex, Hex])),
            (284, ("eventfd", vec![Hex])),
            (285, ("fallocate", vec![FD, Hex, Hex, Hex])),
            (286, ("timerfd_settime", vec![FD, Hex, ItimerSpec, PostItimerSpec])),
            (287, ("timerfd_gettime", vec![FD, PostItimerSpec])),
            (288, ("accept4", vec![FD, PostSockAddr, SockLen, SockFlags])),
            (289, ("signalfd4", vec![Hex, Hex, Hex, Hex])),
            (290, ("eventfd2", vec![Hex, Hex])),
            (291, ("epoll_create1", vec![Hex])),
            (292, ("dup3", vec![FD, FD, Hex])),
            (293, ("pipe2", vec![PipeFDs, Hex])),
            (294, ("inotify_init1", vec![Hex])),
            (295, ("preadv", vec![FD, ReadIOVec, Hex, Hex])),
            (296, ("pwritev", vec![FD, WriteIOVec, Hex, Hex])),
            (297, ("rt_tgsigqueueinfo", vec![Hex, Hex, Signal, Hex])),
            (298, ("perf_event_open", vec![Hex, Hex, Hex, Hex, Hex])),
            (299, ("recvmmsg", vec![FD, Hex, Hex, Hex, Hex])),
            (300, ("fanotify_init", vec![Hex, Hex])),
            (301, ("fanotify_mark", vec![Hex, Hex, Hex, Hex, Hex])),
            (302, ("prlimit64", vec![Hex, Hex, Hex, Hex])),
            (303, ("name_to_handle_at", vec![FD, Hex, Hex, Hex, Hex])),
            (304, ("open_by_handle_at", vec![FD, Hex, Hex])),
            (305, ("clock_adjtime", vec![Hex, Hex])),
            (306, ("syncfs", vec![FD])),
            (307, ("sendmmsg", vec![FD, Hex, Hex, Hex])),
            (308, ("setns", vec![FD, Hex])),
            (309, ("getcpu", vec![Hex, Hex, Hex])),
            (310, ("process_vm_readv", vec![Hex, ReadIOVec, Hex, IOVec, Hex, Hex])),
            (311, ("process_vm_writev", vec![Hex, IOVec, Hex, WriteIOVec, Hex, Hex])),
            (312, ("kcmp", vec![Hex, Hex, Hex, Hex, Hex])),
            (313, ("finit_module", vec![Hex, Hex, Hex])),
            (314, ("sched_setattr", vec![Hex, Hex, Hex])),
            (315, ("sched_getattr", vec![Hex, Hex, Hex])),
            (316, ("renameat2", vec![FD, Path, Hex, Path, Hex])),
            (317, ("seccomp", vec![Hex, Hex, Hex])),
            (318, ("getrandom", vec![Hex, Hex, Hex])),
            (319, ("memfd_create", vec![Path, Hex])),
            (320, ("kexec_file_load", vec![FD, FD, Hex, Hex, Hex])),
            (321, ("bpf", vec![Hex, Hex, Hex])),
            (322, ("execveat", vec![FD, Path, ExecveStringVector, ExecveStringVector, Hex])),
            (323, ("userfaultfd", vec![Hex])),
            (324, ("membarrier", vec![Hex, Hex])),
            (325, ("mlock2", vec![Hex, Hex, Hex])),
            (326, ("copy_file_range", vec![FD, Hex, FD, Hex, Hex, Hex])),
            (327, ("preadv2", vec![FD, ReadIOVec, Hex, Hex, Hex])),
            (328, ("pwritev2", vec![FD, WriteIOVec, Hex, Hex, Hex])),
            (329, ("pkey_mprotect", vec![Hex, Hex, Hex, Hex])),
            (330, ("pkey_alloc", vec![Hex, Hex])),
            (331, ("pkey_free", vec![Hex])),
            (332, ("statx", vec![FD, Path, Hex, Hex, Hex])),
            (333, ("io_pgetevents", vec![Hex, Hex, Hex, Hex, Timespec, SigSet])),
            (334, ("rseq", vec![Hex, Hex, Hex, Hex])),
            (424, ("pidfd_send_signal", vec![FD, Signal, Hex, Hex])),
            (425, ("io_uring_setup", vec![Hex, Hex])),
            (426, ("io_uring_enter", vec![FD, Hex, Hex, Hex, SigSet, Hex])),
            (427, ("io_uring_register", vec![FD, Hex, Hex, Hex])),
            (428, ("open_tree", vec![FD, Path, Hex])),
            (429, ("move_mount", vec![FD, Path, FD, Path, Hex])),
            (430, ("fsopen", vec![Path, Hex])),
            (431, ("fsconfig", vec![FD, Hex, Hex, Hex, Hex])),
            (432, ("fsmount", vec![FD, Hex, Hex])),
            (433, ("fspick", vec![FD, Path, Hex])),
            (434, ("pidfd_open", vec![Hex, Hex])),
            (435, ("clone3", vec![Hex, Hex])),
            (436, ("close_range", vec![FD, FD, CloseRangeFlags])),
            (439, ("faccessat2", vec![FD, Path, Oct, Hex])),
            (441, ("epoll_pwait2", vec![FD, EpollEvents, Hex, Timespec, SigSet])),
        ])
    };
}
