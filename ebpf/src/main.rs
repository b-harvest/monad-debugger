#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", no_main)]

#[cfg(not(target_arch = "bpf"))]
fn main() {}

#[cfg(target_arch = "bpf")]
use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::PerfEventArray,
    programs::XdpContext,
};
#[cfg(target_arch = "bpf")]
use monad_debugger_common::PacketEvent;

#[cfg(target_arch = "bpf")]
#[map(name = "PACKET_EVENTS")]
static mut PACKET_EVENTS: PerfEventArray<PacketEvent> = PerfEventArray::new(0);

#[cfg(target_arch = "bpf")]
#[xdp]
pub fn capture(ctx: XdpContext) -> u32 {
    match try_capture(&ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[cfg(target_arch = "bpf")]
#[allow(static_mut_refs)]
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
        PACKET_EVENTS.output(ctx, &event, 0);
    }

    Ok(xdp_action::XDP_PASS)
}

#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
