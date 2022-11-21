# eLogJ

![alt text](https://github.com/WillGAndre/eLogJ/blob/main/elogj.png?raw=true=250x250)

## 0.1
Rulesets are still hardcoded, check ref (trf-ebpf/src/main.rs).
> cd src/

### Build Userspace:
> cargo build

### Build Kernelspace:
> cargo xtask build-ebpf

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag

### Run:
> cargo xtask run