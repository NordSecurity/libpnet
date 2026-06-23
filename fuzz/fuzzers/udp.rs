#![no_main]

use std::hint::black_box;

use libfuzzer_sys::fuzz_target;
use pnet::packet::udp::UdpPacket;
use pnet::packet::{FromPacket, Packet, PacketSize};

fuzz_target!(|data: &[u8]| {
	if let Some(udp) = UdpPacket::new(data) {
		black_box(udp.get_source());
		black_box(udp.get_destination());
		black_box(udp.get_length());
		black_box(udp.get_checksum());

		for b in udp.payload().iter() {
			black_box(*b);
		}
		black_box(udp.packet_size());
		black_box(udp.from_packet());
	}
});
