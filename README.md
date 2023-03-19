<img src="https://github.com/WillGAndre/eLogJ/blob/main/elogj.png" width="250">

# eLogJ
extended Log4j observability tool used to detect and prevent malicious JNDI (/LDAP) lookups. Currently tested in a controlled environment.<br>
- Developed with aya (https://github.com/aya-rs/aya) a Rust eBPF library.<br>
- Use in tandem with https://github.com/christophetd/log4shell-vulnerable-app (baseline).

### Dependencies
Rust stable and nightly toolchain: 
<br>
`rustup install stable`
<br>
`rustup toolchain install nightly --component rust-src`
<br>
bpf-linker:
<br>
`cargo install bpf-linker`
<br>
Ref: https://aya-rs.dev/book/start/development/#how-to-use-this-guide

### Build Userspace:
> cargo build

### Build Kernelspace:
> cargo xtask build-ebpf

### (Optional) Change Config:
Default config: draft-rule-set-default.yml
> cat logger-info/src/draft-rule-set-v1.yml

### Run:
> cargo xtask run

### Verbose:
> RUST_LOG=info cargo xtask run

<br>
