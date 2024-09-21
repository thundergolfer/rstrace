<p align="center">
  <img height="250em" src="https://i.imgur.com/DmVRIUz.png"/>
</p>

<h1 align="center">rstrace</h1>

rstrace is a Rust implementation of `strace`. It allows the user to trace system calls of a process or command.

## Usage

```bash
rstrace ls /tmp/
```

To get a quick overview, use `rstrace --help`

```bash
Usage: rstrace [OPTIONS] <ARGS>...

Arguments:
  <ARGS>...  Arguments for the program to trace. e.g. 'ls /tmp/'

Options:
  -o, --output <OUTPUT>  send trace output to FILE instead of stderr
  -t, --timestamp...     Print absolute timestamp. -tt includes microseconds, -ttt uses UNIX timestamps
  -c, --summary-only     Count time, calls, and errors for each syscall and report summary
  -j, --summary-json     Count time, calls, and errors for each syscall and report summary in JSON format
      --cuda             Enable CUDA ioctl sniffing. [Requires 'cuda_sniff' feature]
  -h, --help             Print help
  -V, --version          Print version
```

## cuda_sniff extension

`cuda_sniff` is an extension to strace-rs that allows the user to trace CUDA API calls. It is based on
https://github.com/geohot/cuda_ioctl_sniffer by George Hotz.

`gvisor` has an alternative implementation called [ioct_sniffer](https://pkg.go.dev/gvisor.dev/gvisor/tools/ioctl_sniffer#section-readme) which uses `LD_PRELOAD` to intercept calls,
unlike `strace-rs` which uses ptrace.

## Alternatives

- https://github.com/JakWai01/lurk

- https://github.com/strace/strace
