<img src="https://github.com/WillGAndre/eLogJ/blob/main/elogj.png" width="250">

# eLogJ
extended Log4j observability tool used to detect and prevent malicious JNDI (/LDAP) lookups. Currently tested in a controlled environment.<br>
- Developed with aya (https://github.com/aya-rs/aya) a Rust eBPF library.<br>
- Use in tandem with https://github.com/christophetd/log4shell-vulnerable-app (baseline).

0.1.2: Rulesets added as static file (logger-info).

### Dependencies
rust stable toolchain: `rustup install stable`
<br>
or
<br>
rust nightly toolchain: `rustup install nightly`
<br>
bpf-linker: `cargo install bpf-linker`

### Build Userspace:
> cargo build

### Build Kernelspace:
> cargo xtask build-ebpf

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag

### Run:
> cargo xtask run

### Verbose:
> RUST_LOG=info cargo xtask run

<br>
Note: 
 Heavily WIP, deps/wiki/docs to be added soon.
