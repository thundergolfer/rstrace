# rstrace

rstrace is a Rust implementation of `strace`. It allows the user to trace system calls of a process or command.

## Usage

```bash
rstrace ls /tmp/
```

## cuda_sniff extension

`cuda_sniff` is an extension to strace-rs that allows the user to trace CUDA API calls. It is based on
https://github.com/geohot/cuda_ioctl_sniffer by George Hotz.

`gvisor` has an alternative implementation called [ioct_sniffer](https://pkg.go.dev/gvisor.dev/gvisor/tools/ioctl_sniffer#section-readme) which uses `LD_PRELOAD` to intercept calls,
unlike `strace-rs` which uses ptrace.

## Alternatives

- https://github.com/JakWai01/lurk

- https://github.com/strace/strace
