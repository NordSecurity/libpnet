#![no_main]

use std::hint::black_box;

use libfuzzer_sys::fuzz_target;
use pnet::packet::icmp::destination_unreachable::DestinationUnreachablePacket;
use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use pnet::packet::icmp::echo_request::EchoRequestPacket;
use pnet::packet::icmp::time_exceeded::TimeExceededPacket;
use pnet::packet::icmp::{self, IcmpPacket};
use pnet::packet::{FromPacket, Packet, PacketSize};

fuzz_target!(|data: &[u8]| {
	if let Some(icmp) = IcmpPacket::new(data) {
		black_box(icmp.get_icmp_type());
		black_box(icmp.get_icmp_code());
		black_box(icmp.get_checksum());
		for b in icmp.payload().iter() {
			black_box(*b);
		}
		black_box(icmp.packet_size());
		black_box(icmp.from_packet());
		black_box(icmp::checksum(&icmp));
	}

	// Drive every type-specific ICMP parser from the same buffer.
	if let Some(p) = EchoReplyPacket::new(data) {
		black_box(p.get_icmp_type());
		black_box(p.get_icmp_code());
		black_box(p.get_checksum());
		black_box(p.get_identifier());
		black_box(p.get_sequence_number());
		for b in p.payload().iter() {
			black_box(*b);
		}
		black_box(p.packet_size());
		black_box(p.from_packet());
	}

	if let Some(p) = EchoRequestPacket::new(data) {
		black_box(p.get_icmp_type());
		black_box(p.get_icmp_code());
		black_box(p.get_checksum());
		black_box(p.get_identifier());
		black_box(p.get_sequence_number());
		for b in p.payload().iter() {
			black_box(*b);
		}
		black_box(p.packet_size());
		black_box(p.from_packet());
	}

	if let Some(p) = DestinationUnreachablePacket::new(data) {
		black_box(p.get_icmp_type());
		black_box(p.get_icmp_code());
		black_box(p.get_checksum());
		black_box(p.get_unused());
		black_box(p.get_next_hop_mtu());
		for b in p.payload().iter() {
			black_box(*b);
		}
		black_box(p.packet_size());
		black_box(p.from_packet());
	}

	if let Some(p) = TimeExceededPacket::new(data) {
		black_box(p.get_icmp_type());
		black_box(p.get_icmp_code());
		black_box(p.get_checksum());
		black_box(p.get_unused());
		for b in p.payload().iter() {
			black_box(*b);
		}
		black_box(p.packet_size());
		black_box(p.from_packet());
	}
});
