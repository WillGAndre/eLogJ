use aya::{include_bytes_aligned, Bpf, Btf};
use anyhow::Context;
use aya::util::online_cpus;
use aya::maps::HashMap;
use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::{tc, SchedClassifier, TcAttachType, Xdp, XdpFlags, Lsm};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn};
use tokio::{signal, task};
use trf_common::EventLog;
use logger_info::{__config_logger_yml};
use std::net::Ipv4Addr;
use bytes::BytesMut;
use rsyslogger::{info_log, __init_rsysloggerd};

// Interface where services are exposed (docker {springboot} {LDAP} - docker0)
#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "docker0")] // wlp2s0
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let config: (String,Vec<u32>) = __config_logger_yml("draft-rule-set-default.yml");
    let log_type: String = config.0;

    // Create Rsysloggerd
    let rsyslogd = __init_rsysloggerd(log_type.clone());
    let opt = Opt::parse();

    env_logger::init();
    
    let mut bpf = Bpf::load(include_bytes_aligned!(
            "../../target/bpfel-unknown-none/debug/trf"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/trf"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // Load ingress filter (XDP)
    let program: &mut Xdp = bpf.program_mut("intrf").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;
    // ----

    // Load egress filter (tc - traffic control)
    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    let _ = tc::qdisc_add_clsact(&opt.iface);
    let program: &mut SchedClassifier = bpf.program_mut("egtrf").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, TcAttachType::Egress)?;
    // ----

    // Whitelist ex
    let mut whlist: HashMap<_, u32, u32> = HashMap::try_from(bpf.map_mut("WHLIST")?)?;
    for host in config.1 {
        whlist.insert(host, 1, 0)?;
    }
    // ----

    // LSM
    // btf is used to load /vmlinux metadata; Ref: https://docs.rs/aya/0.10.2/src/aya/obj/btf/btf.rs.html#91-93
    let btf = Btf::from_sys_fs()?;
    let program: &mut Lsm = bpf.program_mut("bpflsm").unwrap().try_into()?;
    program.load("bpf", &btf)?;
    program.attach()?;
    // ----

    // Events - TODO: mid-level parsing; parse events -- distinguish between action and info events
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS")?)?;
    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;
        let log_type: String = log_type.clone();

        task::spawn(async move {
            // buffer has the same capacity as event map
            let mut buffer = (0..10) // 2^10
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();
            
            loop {
                let events = buf.read_events(&mut buffer).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut buffer[i];
                    let ptr = buf.as_ptr() as *const EventLog;
                    let data = unsafe { ptr.read_unaligned() }; // read_unaligned --> reads data to EventLog

                    let traffic_type = data.etype; // 0 => Outbound (XDP) ; 1 => Inbound (TC)
                    let saddr = Ipv4Addr::from(data.eroute[0]);
                    let daddr = Ipv4Addr::from(data.eroute[1]);
                    let mut msg = format!("{} --> {}", saddr, daddr);
                    
                    let action: [u32;2usize] = data.eaction;
                    let levls: [u32;3usize] = data.elvls;

                    if action[0] == 1 { // DROP
                        msg.push_str(&" - DROP");
                    } else if action[1] == 1 { // OVERRIDE
                        msg.push_str(&" - PASS**");
                    } else {
                        msg.push_str(&" - PASS");
                    }

                    msg.push_str(&" - LOG:");
                    match traffic_type {
                        0 => { // Outbound (XDP)
                            if levls[0] == 1 { // TCP
                                msg.push_str(&" TCP Traffic;");
                            }
                            if levls[1] == 1 { // HTTP: GET
                                msg.push_str(&" HTTP GET;");
                            } else if levls[1] == 2 { // HTTP: Resp
                                msg.push_str(&" HTTP Resp;");
                            }
                            if levls[2] != 0 { // LDAP Response
                                let data_size = levls[1].to_string();
                                match levls[2] {
                                    97 => msg.push_str(&" bindResponse"),
                                    100 => msg.push_str(&" searchResEntry"), 
                                    101 => msg.push_str(&" searchResDone"),
                                    _ => {}
                                }
                                msg.push_str(&format!(" - size: {} bytes;", data_size));
                            }
                        },
                        1 => { // Inbound (TC)
                            if levls[2] == 1 {
                                msg.push_str(&" `${jndi:ldap` match;");
                            } else if levls[1] == 1 {
                                msg.push_str(&" `${jndi` match;");
                            } else if levls[0] == 1 {
                                msg.push_str(&" `${` match;");
                            }
                        },
                        _ => {}
                    } 

                    // debug
                    if log_type == String::from("manager") {
                        info!("{}", msg.clone());
                    }
                    
                    if log_type == String::from("local"){
                        info!("{}", msg);
                    } else {
                        info_log(msg);
                    }
                }
            }
        });
    }
    // ----

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    rsyslogd.__purge();
    info!("Exiting...");

    Ok(())
}
