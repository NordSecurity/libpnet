#![no_main]

use std::hint::black_box;

use libfuzzer_sys::fuzz_target;
use pnet::packet::gre::GrePacket;

fuzz_target!(|data: &[u8]| {
	if let Some(gre) = GrePacket::new(data) {
		for b in gre.get_checksum_raw().iter() {
			black_box(*b);
		}

		for b in gre.get_offset_raw().iter() {
			black_box(*b);
		}

		for b in gre.get_key_raw().iter() {
			black_box(*b);
		}

		for b in gre.get_sequence_raw().iter() {
			black_box(*b);
		}

		for b in gre.get_routing_raw().iter() {
			black_box(*b);
		}
	}
});
