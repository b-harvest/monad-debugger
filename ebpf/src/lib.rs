#![cfg_attr(
    not(any(target_arch = "bpf", target_arch = "bpfeb", target_arch = "bpfel")),
    compile_error!("monad-debugger-ebpf must be built for a BPF target")
)]
#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::PerfEventArray,
    programs::XdpContext,
};
use monad_debugger_common::PacketEvent;

#[map(name = "PACKET_EVENTS")]
static mut PACKET_EVENTS: PerfEventArray<PacketEvent> = PerfEventArray::new(0);

#[xdp(name = "capture")]
pub fn capture(ctx: XdpContext) -> u32 {
    match try_capture(&ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_capture(ctx: &XdpContext) -> Result<u32, u32> {
    let length = ctx.data_end().saturating_sub(ctx.data());
    let event = PacketEvent {
        timestamp_ns: unsafe { bpf_ktime_get_ns() } as u64,
        length: length as u32,
        direction: 0,
        transport_hint: 0,
        _reserved: 0,
    };

    unsafe {
        PACKET_EVENTS
            .output(ctx, &event, 0)
            .map_err(|_| xdp_action::XDP_ABORTED)?;
    }

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
