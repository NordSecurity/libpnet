#![no_main]

use std::hint::black_box;

use libfuzzer_sys::fuzz_target;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::{FromPacket, Packet, PacketSize};

fuzz_target!(|data: &[u8]| {
	if let Some(tcp) = TcpPacket::new(data) {
		// Every fixed-header getter.
		black_box(tcp.get_source());
		black_box(tcp.get_destination());
		black_box(tcp.get_sequence());
		black_box(tcp.get_acknowledgement());
		black_box(tcp.get_data_offset());
		black_box(tcp.get_reserved());
		black_box(tcp.get_flags());
		black_box(tcp.get_window());
		black_box(tcp.get_checksum());
		black_box(tcp.get_urgent_ptr());

		// Variable-length options: raw bytes, parsed Vec, and iterator.
		for b in tcp.get_options_raw().iter() {
			black_box(*b);
		}
		for opt in tcp.get_options() {
			black_box(&opt);
		}
		for opt in tcp.get_options_iter() {
			black_box(opt.get_number());
			black_box(opt.packet_size());
			for b in opt.payload().iter() {
				black_box(*b);
			}
		}

		// Payload, computed size and owned conversion.
		for b in tcp.payload().iter() {
			black_box(*b);
		}
		black_box(tcp.packet_size());
		black_box(tcp.from_packet());
	}
});
