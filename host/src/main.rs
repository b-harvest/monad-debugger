#[cfg(target_os = "linux")]
use anyhow::{anyhow, Context, Result};
#[cfg(target_os = "linux")]
use aya::{
    include_bytes_aligned,
    maps::perf::{AsyncPerfEventArray, Events},
    programs::{Xdp, XdpFlags},
    util::online_cpus,
    Ebpf,
};
#[cfg(target_os = "linux")]
use aya_log::EbpfLogger;
#[cfg(target_os = "linux")]
use bytes::BytesMut;
#[cfg(target_os = "linux")]
use monad_debugger_common::PacketEvent;
#[cfg(target_os = "linux")]
use tracing_subscriber::EnvFilter;

#[cfg(target_os = "linux")]
const BPF_OBJECT: &[u8] =
    include_bytes_aligned!(concat!(env!("OUT_DIR"), "/monad-debugger-ebpf.bpf.o"));

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();

    let iface = std::env::args()
        .nth(1)
        .context("usage: monad-debugger-host <IFACE>")?;

    let mut bpf = Ebpf::load(BPF_OBJECT)?;
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        tracing::warn!(error = ?e, "failed to initialize eBPF logger");
    }

    let program: &mut Xdp = bpf
        .program_mut("capture")
        .context("failed to find XDP program 'capture'")?
        .try_into()
        .context("program 'capture' is not an XDP program")?;
    program.load()?;
    let _link = program.attach(&iface, XdpFlags::default())?;

    let map = bpf
        .take_map("PACKET_EVENTS")
        .ok_or_else(|| anyhow!("PACKET_EVENTS map not found"))?;
    let mut events = AsyncPerfEventArray::try_from(map)?;

    let cpus = online_cpus().map_err(|(msg, err)| anyhow!("{msg}: {err}"))?;
    for cpu_id in cpus {
        let mut buf = events
            .open(cpu_id, None)
            .with_context(|| format!("failed to open perf buffer on CPU {cpu_id}"))?;

        tokio::spawn(async move {
            let mut buffers = (0..16)
                .map(|_| BytesMut::with_capacity(core::mem::size_of::<PacketEvent>()))
                .collect::<Vec<_>>();

            loop {
                let Events { read, lost } = match buf.read_events(&mut buffers).await {
                    Ok(events) => events,
                    Err(e) => {
                        tracing::error!(error = ?e, "perf buffer read failure");
                        continue;
                    }
                };

                if lost > 0 {
                    tracing::warn!(lost, "perf buffer lost events");
                }

                for buffer in buffers.iter_mut().take(read) {
                    let len = buffer.len();
                    if len < core::mem::size_of::<PacketEvent>() {
                        tracing::warn!(
                            len,
                            expected = core::mem::size_of::<PacketEvent>(),
                            "perf buffer returned undersized payload"
                        );
                        buffer.clear();
                        continue;
                    }

                    let event = unsafe { (buffer.as_ptr() as *const PacketEvent).read_unaligned() };

                    tracing::info!(
                        timestamp_ns = event.timestamp_ns,
                        length = event.length,
                        direction = event.direction,
                        transport_hint = event.transport_hint,
                        "packet captured"
                    );

                    buffer.clear();
                }
            }
        });
    }

    tracing::info!("attached XDP program on interface {iface}");
    tokio::signal::ctrl_c()
        .await
        .context("failed while waiting for ctrl-c")?;

    tracing::info!("shutting down");

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("monad-debugger-host currently supports Linux only.");
}
