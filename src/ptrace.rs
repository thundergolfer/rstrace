//! Rust bindings and utility functions for the POSIX ptrace API.
#![allow(missing_docs)]
use std::default::Default;
use std::io::Error;
use std::mem;
use std::ptr;
use std::vec::Vec;

use num::FromPrimitive;

pub type Address = u64;
pub type Word = u64;

#[derive(Copy, Clone)]
pub enum Action {
    Allow,
    Kill,
}

#[derive(Hash, Eq, PartialEq, Copy, Clone, Debug, FromPrimitive)]
pub enum Signal {
    None = 0,
    Hup,
    Int,
    Quit,
    Ill,
    Trap,
    Abrt,
    Bus,
    Fpe,
    Kill,
    Usr1,
    Segv,
    Usr2,
    Pipe,
    Alrm,
    Term,
    StkFlt,
    Chld,
    Cont,
    Stop,
    Tstp,
    Ttin,
    Ttou,
    Urg,
    XCpu,
    Xfsz,
    Vtalrm,
    Prof,
    Winch,
    Io,
    Pwr,
    Sys,
}

#[derive(Debug, Copy, Clone)]
pub enum Request {
    TraceMe = 0,
    PeekText = 1,
    PeekData = 2,
    PeekUser = 3,
    PokeText = 4,
    PokeData = 5,
    PokeUser = 6,
    Continue = 7,
    Kill = 8,
    SingleStep = 9,
    GetRegs = 12,
    SetRegs = 13,
    Attach = 16,
    Detatch = 17,
    Syscall = 24,
    SetOptions = 0x4200,
    Seize = 0x4206,
}

#[derive(Copy, Clone, Debug, FromPrimitive)]
pub enum Event {
    Fork = 1,
    VFork = 2,
    Clone = 3,
    Exec = 4,
    VForkDone = 5,
    Exit = 6,
    Seccomp = 7,
    Stop = 128,
}

impl Event {
    pub fn from_wait_status(st: i32) -> Option<Event> {
        let e: Option<Event> = FromPrimitive::from_i32(((st >> 8) & !5) >> 8);
        return e;
    }
}

#[derive(Copy, Clone, Default, Debug)]
pub struct Registers {
    pub r15: Word,
    pub r14: Word,
    pub r13: Word,
    pub r12: Word,
    pub rbp: Word,
    pub rbx: Word,
    pub r11: Word,
    pub r10: Word,
    pub r9: Word,
    pub r8: Word,
    pub rax: Word,
    pub rcx: Word,
    pub rdx: Word,
    pub rsi: Word,
    pub rdi: Word,
    pub orig_rax: Word,
    pub rip: Word,
    pub cs: Word,
    pub eflags: Word,
    pub rsp: Word,
    pub ss: Word,
    pub fs_base: Word,
    pub gs_base: Word,
    pub ds: Word,
    pub es: Word,
    pub fs: Word,
    pub gs: Word,
}

bitflags! {
  pub struct Options: u32 {
    const SysGood = 1;
    const TraceFork = 1 << 1;
    const TraceVFork = 1 << 2;
    const TraceClone = 1 << 3;
    const TraceExec = 1 << 4;
    const TraceVForkDone = 1 << 5;
    const TraceExit = 1 << 6;
    const TraceSeccomp = 1 << 7;
    const ExitKill = 1 << 20;
  }
}

pub fn syscall(pid: libc::pid_t) -> Result<libc::c_long, i32> {
    unsafe { _ptrace(Request::Syscall, pid, ptr::null_mut(), ptr::null_mut()) }
}

pub fn setoptions(pid: libc::pid_t, opts: Options) -> Result<libc::c_long, i32> {
    unsafe {
        _ptrace(
            Request::SetOptions,
            pid,
            ptr::null_mut(),
            opts.bits() as *mut libc::c_void,
        )
    }
}

pub fn getregs(pid: libc::pid_t) -> Result<Registers, i32> {
    let mut buf: Registers = Default::default();
    let buf_mut: *mut Registers = &mut buf;

    match unsafe {
        _ptrace(
            Request::GetRegs,
            pid,
            ptr::null_mut(),
            buf_mut as *mut libc::c_void,
        )
    } {
        Ok(_) => Ok(buf),
        Err(e) => Err(e),
    }
}

pub fn setregs(pid: libc::pid_t, regs: &Registers) -> Result<libc::c_long, i32> {
    unsafe {
        let buf: *mut libc::c_void = mem::transmute(regs);
        _ptrace(Request::SetRegs, pid, ptr::null_mut(), buf)
    }
}

pub fn seize(pid: libc::pid_t) -> Result<libc::c_long, i32> {
    unsafe { _ptrace(Request::Seize, pid, ptr::null_mut(), ptr::null_mut()) }
}

pub fn attach(pid: libc::pid_t) -> Result<libc::c_long, i32> {
    unsafe { _ptrace(Request::Attach, pid, ptr::null_mut(), ptr::null_mut()) }
}

pub fn release(pid: libc::pid_t, signal: Signal) -> Result<libc::c_long, i32> {
    unsafe {
        _ptrace(
            Request::Detatch,
            pid,
            ptr::null_mut(),
            (signal as u32) as *mut libc::c_void,
        )
    }
}

pub fn cont(pid: libc::pid_t, signal: Signal) -> Result<libc::c_long, i32> {
    unsafe {
        _ptrace(
            Request::Continue,
            pid,
            ptr::null_mut(),
            (signal as u32) as *mut libc::c_void,
        )
    }
}

pub fn traceme() -> Result<libc::c_long, i32> {
    unsafe { _ptrace(Request::TraceMe, 0, ptr::null_mut(), ptr::null_mut()) }
}

unsafe fn _ptrace(
    request: Request,
    pid: libc::pid_t,
    addr: *mut libc::c_void,
    data: *mut libc::c_void,
) -> Result<libc::c_long, i32> {
    let v = ptrace(request as libc::c_int, pid, addr, data);
    match v {
        -1 => Result::Err(Error::last_os_error().raw_os_error().unwrap()),
        _ => Result::Ok(v),
    }
}

extern "C" {
    fn ptrace(
        request: libc::c_int,
        pid: libc::pid_t,
        addr: *mut libc::c_void,
        data: *mut libc::c_void,
    ) -> libc::c_long;
}

#[derive(Copy, Clone, Debug)]
pub struct Syscall {
    pub args: [Word; 6],
    pub call: u64,
    pub pid: libc::pid_t,
    pub return_val: Word,
}

impl Syscall {
    pub fn from_pid(pid: libc::pid_t) -> Result<Syscall, i32> {
        match getregs(pid) {
            Ok(regs) => Ok(Syscall {
                pid: pid,
                call: regs.orig_rax,
                args: [regs.rdi, regs.rsi, regs.rdx, regs.rcx, regs.r8, regs.r9],
                return_val: 0,
            }),
            Err(e) => Err(e),
        }
    }

    pub fn write(&self) -> Result<libc::c_long, i32> {
        match getregs(self.pid) {
            Ok(mut regs) => {
                regs.rdi = self.args[0];
                regs.rsi = self.args[1];
                regs.rdx = self.args[2];
                regs.rcx = self.args[3];
                regs.r8 = self.args[4];
                regs.r9 = self.args[5];
                regs.orig_rax = self.call;
                regs.rax = self.return_val;
                setregs(self.pid, &regs)
            }
            Err(e) => Err(e),
        }
    }
}

#[derive(Copy, Clone)]
pub struct Reader {
    pub pid: libc::pid_t,
}

#[derive(Copy, Clone)]
pub struct Writer {
    pub pid: libc::pid_t,
}

impl Writer {
    pub fn new(pid: libc::pid_t) -> Self {
        Writer { pid: pid }
    }

    pub fn poke_data(&self, address: Address, data: Word) -> Result<Word, i32> {
        match unsafe {
            _ptrace(
                Request::PokeData,
                self.pid,
                address as *mut libc::c_void,
                data as *mut libc::c_void,
            )
        } {
            Err(e) => Err(e),
            Ok(r) => Ok(r as Word),
        }
    }

    pub fn write_object<T: Sized>(&self, address: Address, data: &T) -> Result<(), i32> {
        let _ = address;
        let mut buf = Vec::with_capacity(mem::size_of::<T>());
        unsafe {
            let tptr: *const T = data;
            let p: *const u8 = mem::transmute(tptr);
            for i in 0..buf.capacity() {
                buf.push(*p.offset(i as isize));
            }
        }

        Ok(())
    }

    pub fn write_data(&self, address: Address, buf: &Vec<u8>) -> Result<(), i32> {
        // The end of our range
        let max_addr = address + buf.len() as Address;
        // The last word we can completely overwrite
        let align_end = max_addr - (max_addr % mem::size_of::<Word>() as Address);
        for write_addr in (address..align_end).step_by(mem::size_of::<Word>() as usize) {
            let mut d: Word = 0;
            let buf_idx = (write_addr - address) as usize;
            for word_idx in 0..mem::size_of::<Word>() {
                d = set_byte(d, word_idx, buf[buf_idx + word_idx]);
            }
            match self.poke_data(write_addr, d) {
                Ok(_) => {}
                Err(e) => return Err(e),
            }
        }
        // Handle a partial word overwrite
        if max_addr > align_end {
            let buf_start = buf.len() - (max_addr - align_end) as usize;
            let r = Reader::new(self.pid);
            let mut d = match r.peek_data(align_end) {
                Ok(v) => v,
                Err(e) => return Err(e),
            };
            for word_idx in 0..mem::size_of::<Word>() - 2 {
                let buf_idx = buf_start + word_idx;
                d = set_byte(d, word_idx, buf[buf_idx]);
            }
            match self.poke_data(align_end, d) {
                Ok(_) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

impl Reader {
    pub fn new(pid: libc::pid_t) -> Reader {
        Reader { pid: pid }
    }

    pub fn peek_data(&self, address: Address) -> Result<Word, i32> {
        let l;
        unsafe {
            l = _ptrace(
                Request::PeekData,
                self.pid,
                address as *mut libc::c_void,
                ptr::null_mut(),
            )
        }
        match l {
            Result::Err(e) => Result::Err(e),
            _ => Result::Ok(l.unwrap() as Word),
        }
    }

    pub fn read_string(&self, address: Address, size: usize) -> Result<Vec<u8>, i32> {
        let mut end_of_str = false;
        let mut buf: Vec<u8> = Vec::with_capacity(size);
        let max_addr = address + buf.capacity() as Address;
        let align_end = max_addr - (max_addr % mem::size_of::<Word>() as Address);
        'finish: for read_addr in (address..align_end).step_by(mem::size_of::<Word>() as usize) {
            let d;
            match self.peek_data(read_addr) {
                Ok(v) => d = v,
                Err(e) => return Err(e),
            }
            for word_idx in 0..mem::size_of::<Word>() {
                let chr = get_byte(d, word_idx);
                if chr == 0 {
                    end_of_str = true;
                    break 'finish;
                }
                buf.push(chr);
            }
        }
        if !end_of_str {
            let d;
            match self.peek_data(align_end) {
                Ok(v) => d = v,
                Err(e) => return Err(e),
            }
            for word_idx in 0..mem::size_of::<Word>() {
                let chr = get_byte(d, word_idx);
                if chr == 0 {
                    break;
                }
                buf.push(chr);
            }
        }
        return Ok(buf);
    }
}

fn get_byte(d: Word, byte_idx: usize) -> u8 {
    assert!(byte_idx < mem::size_of::<Word>() * 8);
    ((d >> (byte_idx * 8)) & 0xff) as u8
}

fn set_byte(d: Word, byte_idx: usize, value: u8) -> Word {
    assert!(byte_idx < mem::size_of::<Word>() * 8);
    let shift = mem::size_of::<u8>() * 8 * byte_idx;
    let mask = 0xff << shift;
    (d & !mask) | (((value as Word) << shift) & mask)
}

#[test]
pub fn test_set_byte() {
    assert_eq!(set_byte(0, 0, 0), 0);
    assert_eq!(set_byte(0xffffffffffff, 0, 0xff), 0xffffffffffff);
    assert_eq!(set_byte(0xffffffffffff, 0, 0), 0xffffffffff00);
    assert_eq!(set_byte(0xffffffffffff, 0, 0xaa), 0xffffffffffaa);
    assert_eq!(set_byte(0xffffffffffff, 1, 0x00), 0xffffffff00ff);
    assert_eq!(set_byte(0xffffffffffff, 4, 0xaa), 0xffaaffffffff);
}

#[test]
pub fn test_get_byte() {
    assert_eq!(get_byte(0, 0), 0);
    assert_eq!(get_byte(0xffffffffffff, 0), 0xff);
    assert_eq!(get_byte(0xffffffffffff, 8), 0xff);
    assert_eq!(get_byte(0xffffffffffaa, 0), 0xaa);
    assert_eq!(get_byte(0x0123456789ab, 1), 0x89);
    assert_eq!(get_byte(0x0123456789ab, 4), 0x23);
}
