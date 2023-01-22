use aya::{include_bytes_aligned, Bpf, Btf};
use anyhow::Context;
use aya::util::online_cpus;
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
use rsyslogger::{remote_log, local_info_log};

// Interface where services are exposed (docker {springboot} {LDAP} - docker0)
#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "docker0")] // wlp2s0
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    __config_logger_yml("draft-rule-set-default.yml");
    let opt = Opt::parse();
    
    // debug
    //remote_log();
    //local_info_log("elogj-sample-info-test");

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
    // let mut whlist: HashMap<_, u32, u32> = HashMap::try_from(bpf.map_mut("WHLIST")?)?;
    // let temp_addr: u32 = Ipv4Addr::new(1, 1, 1, 1).try_into()?;
    // whlist.insert(temp_addr, 1, 0)?;
    // ----

    // LSM
    // btf is used to load /vmlinux metadata; Ref: https://docs.rs/aya/0.10.2/src/aya/obj/btf/btf.rs.html#91-93
    let btf = Btf::from_sys_fs()?;
    let program: &mut Lsm = bpf.program_mut("bpflsm").unwrap().try_into()?;
    program.load("bpf", &btf)?;
    program.attach()?;
    // ----

    // Events - TODO: mid-level parsing; send event as json
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS")?)?;
    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;

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

                    let saddr = Ipv4Addr::from(data.eroute[0]);
                    let daddr = Ipv4Addr::from(data.eroute[1]);
                    
                    match data.etype {
                        0 => info!("ig: {} --> {} elvls: {:?} action: {:?}", saddr, daddr, data.elvls, data.eaction),
                        1 => info!("eg: {} --> {} elvls: {:?} action: {:?}", saddr, daddr, data.elvls, data.eaction),
                        _ => {},
                    }
                }
            }
        });
    }
    // ----

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
