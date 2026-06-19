#![no_main]

use std::hint::black_box;

use libfuzzer_sys::fuzz_target;
use pnet::packet::icmpv6::ndp::{
	NdpOptionPacket, NeighborAdvertPacket, NeighborSolicitPacket, RedirectPacket,
	RouterAdvertPacket, RouterSolicitPacket,
};
use pnet::packet::icmpv6::echo_reply::EchoReplyPacket;
use pnet::packet::icmpv6::echo_request::EchoRequestPacket;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::{FromPacket, Packet, PacketSize};

/// Drive every read path of a single NDP option.
fn drive_option(opt: &NdpOptionPacket) {
	black_box(opt.get_option_type());
	black_box(opt.get_length());
	black_box(opt.packet_size());
	for b in opt.payload().iter() {
		black_box(*b);
	}
}

fuzz_target!(|data: &[u8]| {
	if let Some(icmpv6) = Icmpv6Packet::new(data) {
		black_box(icmpv6.get_icmpv6_type());
		black_box(icmpv6.get_icmpv6_code());
		black_box(icmpv6.get_checksum());
		for b in icmpv6.payload().iter() {
			black_box(*b);
		}
		black_box(icmpv6.packet_size());
		black_box(icmpv6.from_packet());
	}

	if let Some(p) = NdpOptionPacket::new(data) {
		drive_option(&p);
		black_box(p.from_packet());
	}

	if let Some(p) = RouterSolicitPacket::new(data) {
		black_box(p.get_icmpv6_type());
		black_box(p.get_icmpv6_code());
		black_box(p.get_checksum());
		black_box(p.get_reserved());
		for opt in p.get_options_iter() {
			drive_option(&opt);
		}
		black_box(p.get_options());
		for b in p.payload().iter() {
			black_box(*b);
		}
		black_box(p.packet_size());
		black_box(p.from_packet());
	}

	if let Some(p) = RouterAdvertPacket::new(data) {
		black_box(p.get_icmpv6_type());
		black_box(p.get_icmpv6_code());
		black_box(p.get_checksum());
		black_box(p.get_hop_limit());
		black_box(p.get_flags());
		black_box(p.get_lifetime());
		black_box(p.get_reachable_time());
		black_box(p.get_retrans_time());
		for opt in p.get_options_iter() {
			drive_option(&opt);
		}
		black_box(p.get_options());
		for b in p.payload().iter() {
			black_box(*b);
		}
		black_box(p.packet_size());
		black_box(p.from_packet());
	}

	if let Some(p) = NeighborSolicitPacket::new(data) {
		black_box(p.get_icmpv6_type());
		black_box(p.get_icmpv6_code());
		black_box(p.get_checksum());
		black_box(p.get_reserved());
		black_box(p.get_target_addr());
		for opt in p.get_options_iter() {
			drive_option(&opt);
		}
		black_box(p.get_options());
		for b in p.payload().iter() {
			black_box(*b);
		}
		black_box(p.packet_size());
		black_box(p.from_packet());
	}

	if let Some(p) = NeighborAdvertPacket::new(data) {
		black_box(p.get_icmpv6_type());
		black_box(p.get_icmpv6_code());
		black_box(p.get_checksum());
		black_box(p.get_flags());
		black_box(p.get_reserved());
		black_box(p.get_target_addr());
		for opt in p.get_options_iter() {
			drive_option(&opt);
		}
		black_box(p.get_options());
		for b in p.payload().iter() {
			black_box(*b);
		}
		black_box(p.packet_size());
		black_box(p.from_packet());
	}

	if let Some(p) = RedirectPacket::new(data) {
		black_box(p.get_icmpv6_type());
		black_box(p.get_icmpv6_code());
		black_box(p.get_checksum());
		black_box(p.get_reserved());
		black_box(p.get_target_addr());
		black_box(p.get_dest_addr());
		for opt in p.get_options_iter() {
			drive_option(&opt);
		}
		black_box(p.get_options());
		for b in p.payload().iter() {
			black_box(*b);
		}
		black_box(p.packet_size());
		black_box(p.from_packet());
	}

	if let Some(p) = EchoReplyPacket::new(data) {
		black_box(p.get_icmpv6_type());
		black_box(p.get_icmpv6_code());
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
		black_box(p.get_icmpv6_type());
		black_box(p.get_icmpv6_code());
		black_box(p.get_checksum());
		black_box(p.get_identifier());
		black_box(p.get_sequence_number());
		for b in p.payload().iter() {
			black_box(*b);
		}
		black_box(p.packet_size());
		black_box(p.from_packet());
	}
});
