#![no_main]

use std::hint::black_box;

use libfuzzer_sys::fuzz_target;
use pnet::packet::ipv4::{self, Ipv4Packet};
use pnet::packet::{FromPacket, Packet, PacketSize};

fuzz_target!(|data: &[u8]| {
	if let Some(ipv4) = Ipv4Packet::new(data) {
		// Every fixed-header getter.
		black_box(ipv4.get_version());
		black_box(ipv4.get_header_length());
		black_box(ipv4.get_dscp());
		black_box(ipv4.get_ecn());
		black_box(ipv4.get_total_length());
		black_box(ipv4.get_identification());
		black_box(ipv4.get_flags());
		black_box(ipv4.get_fragment_offset());
		black_box(ipv4.get_ttl());
		black_box(ipv4.get_next_level_protocol());
		black_box(ipv4.get_checksum());
		black_box(ipv4.get_source());
		black_box(ipv4.get_destination());

		// Variable-length options: raw bytes, parsed Vec, and iterator.
		for b in ipv4.get_options_raw().iter() {
			black_box(*b);
		}
		for opt in ipv4.get_options() {
			black_box(&opt);
		}
		for opt in ipv4.get_options_iter() {
			black_box(opt.packet_size());
			for b in opt.payload().iter() {
				black_box(*b);
			}
		}

		// Payload, computed size, owned conversion and checksum.
		for b in ipv4.payload().iter() {
			black_box(*b);
		}
		black_box(ipv4.packet_size());
		black_box(ipv4.from_packet());
		black_box(ipv4::checksum(&ipv4));
	}
});
