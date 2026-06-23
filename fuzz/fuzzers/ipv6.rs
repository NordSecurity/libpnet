#![no_main]

use std::hint::black_box;

use libfuzzer_sys::fuzz_target;
use pnet::packet::ipv6::{ExtensionPacket, FragmentPacket, Ipv6Packet, RoutingPacket};
use pnet::packet::{FromPacket, Packet, PacketSize};

fuzz_target!(|data: &[u8]| {
	if let Some(ipv6) = Ipv6Packet::new(data) {
		black_box(ipv6.get_version());
		black_box(ipv6.get_traffic_class());
		black_box(ipv6.get_flow_label());
		black_box(ipv6.get_payload_length());
		black_box(ipv6.get_next_header());
		black_box(ipv6.get_hop_limit());
		black_box(ipv6.get_source());
		black_box(ipv6.get_destination());

		for b in ipv6.payload().iter() {
			black_box(*b);
		}
		black_box(ipv6.packet_size());
		black_box(ipv6.from_packet());
	}

	// Drive the IPv6 extension-header parsers from the same buffer.
	if let Some(ext) = ExtensionPacket::new(data) {
		black_box(ext.get_next_header());
		black_box(ext.get_hdr_ext_len());
		for b in ext.payload().iter() {
			black_box(*b);
		}
		black_box(ext.packet_size());
		black_box(ext.from_packet());
	}

	if let Some(routing) = RoutingPacket::new(data) {
		black_box(routing.get_next_header());
		black_box(routing.get_hdr_ext_len());
		black_box(routing.get_routing_type());
		black_box(routing.get_segments_left());
		for b in routing.payload().iter() {
			black_box(*b);
		}
		black_box(routing.packet_size());
		black_box(routing.from_packet());
	}

	if let Some(fragment) = FragmentPacket::new(data) {
		black_box(fragment.get_next_header());
		black_box(fragment.get_reserved());
		black_box(fragment.get_fragment_offset_with_flags());
		black_box(fragment.get_id());
		for b in fragment.payload().iter() {
			black_box(*b);
		}
		black_box(fragment.packet_size());
		black_box(fragment.from_packet());
	}
});
