#![no_main]

use std::hint::black_box;

use libfuzzer_sys::fuzz_target;
use pnet::packet::Packet;
use pnet::packet::ethernet::EthernetPacket;

fuzz_target!(|data: &[u8]| {
	if let Some(eth) = EthernetPacket::new(data) {
		black_box(eth.get_source());
		black_box(eth.get_destination());
		black_box(eth.get_ethertype());
		for b in eth.payload().iter() {
			black_box(*b);
		}
	}
});
