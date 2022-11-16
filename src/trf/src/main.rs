use aya::{include_bytes_aligned, BpfLoader};
use anyhow::Context;
use aya::util::online_cpus;
use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::{tc, SchedClassifier, TcAttachType, Xdp, XdpFlags};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn};
use tokio::{signal, task};
use trf_common::EventLog;
// use http_parser::{parse_header};
use std::net::Ipv4Addr;
use bytes::BytesMut;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "docker0")] // wlp2s0
    iface: String,
    #[clap(short, long, default_value = "1")]
    mode: u8,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    
    env_logger::init();

    // test
    // parse_header("http://127.0.0.1".to_string(), "x-api-version".to_string()).await;
    // ----

    let mode = opt.mode as u8;
    let mut bpf = BpfLoader::new().set_global("MODE", &mode).load(
        include_bytes_aligned!(
            "../../target/bpfel-unknown-none/debug/trf"
        ),
    )?;
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

    // Events
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

                    let saddr = Ipv4Addr::from(data.saddr);
                    let daddr = Ipv4Addr::from(data.daddr);
                    
                    match data.etype {
                        0 => {
                            info!("ig: {} --> {} drop: {}", saddr, daddr, data.edrop);
                        },
                        1 => info!("eg: {} --> {} drop: {} JNDI: {}", saddr, daddr, data.edrop, data.einfo),
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
