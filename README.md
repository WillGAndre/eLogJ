<img src="https://github.com/WillGAndre/eLogJ/blob/main/elogj.png" width="250">

# eLogJ
extended Log4j observability tool used to detect and prevent malicious JNDI (/LDAP) lookups. Currently tested in a controlled environment.<br>
- Developed with aya (https://github.com/aya-rs/aya) a Rust eBPF library.<br>
- Use in tandem with https://github.com/christophetd/log4shell-vulnerable-app (baseline).

<pre>
0.1.2: Rulesets added as static file (logger-info).
  .
  . revised overall event data structures
  .     \ - rulesets, EventLog
  . added experimental LSM module (bpf syscall -- blackbox eLogJ)
  .
0.1.5: Rulesets configured using yaml file.
0.1.6: "file"/"local" log_type (yaml)
0.1.7: Added whitelist to yaml & LDAP Response tracing
0.1.8: Remote Agent-less logging (Wazuh Manager)
</pre>

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

WIP, Check out the wiki!
