#![no_main]

use std::hint::black_box;

use libfuzzer_sys::fuzz_target;
use pnet::packet::Packet;
use pnet::packet::vlan::VlanPacket;

fuzz_target!(|data: &[u8]| {
	if let Some(vlan) = VlanPacket::new(data) {
		for b in vlan.payload().iter() {
			black_box(*b);
		}
	}
});
