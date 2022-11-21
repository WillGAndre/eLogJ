<img src="https://github.com/WillGAndre/eLogJ/blob/main/elogj.png" width="250">

# eLogJ
extended Log4j observability tool used to detect and prevent malicious JNDI (/LDAP) lookups.<br>
Developed with aya (https://github.com/aya-rs/aya) a Rust eBPF library.<br>
Used in tandem with https://github.com/christophetd/log4shell-vulnerable-app (baseline).

0.1: Rulesets are still hardcoded, check ref (trf-ebpf/src/main.rs).

### Build Userspace:
> cargo build

### Build Kernelspace:
> cargo xtask build-ebpf

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag

### Run:
> cargo xtask run

<br><br>
Note: 
 Heavily WIP, deps/wiki/docs to be added soon.
 Suggestions are appreciated.
