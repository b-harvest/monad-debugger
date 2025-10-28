#![cfg_attr(not(feature = "std"), no_std)]

/// eBPF → 유저 공간으로 전달되는 패킷 메타데이터.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PacketEvent {
    pub timestamp_ns: u64,
    pub length: u32,
    pub direction: u8,
    pub transport_hint: u8,
    pub _reserved: u16,
}
