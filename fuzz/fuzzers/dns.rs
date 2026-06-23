#![no_main]

use std::hint::black_box;

use libfuzzer_sys::fuzz_target;
use pnet::packet::dns::{DnsPacket, DnsQuery, DnsResponse};
use pnet::packet::{FromPacket, Packet, PacketSize};

fn drive_query(q: &DnsQuery) {
	for b in q.qname.iter() {
		black_box(*b);
	}
	black_box(q.qtype);
	black_box(q.qclass);
	for b in q.payload.iter() {
		black_box(*b);
	}
	// Unchecked label parsing: indexes/slices `qname` and unwraps from_utf8.
	black_box(q.get_qname_parsed());
}

fn drive_response(r: &DnsResponse) {
	black_box(r.name_tag);
	black_box(r.rtype);
	black_box(r.rclass);
	black_box(r.ttl);
	black_box(r.data_len);
	for b in r.data.iter() {
		black_box(*b);
	}
	for b in r.payload.iter() {
		black_box(*b);
	}
}

fuzz_target!(|data: &[u8]| {
	if let Some(dns) = DnsPacket::new(data) {
		// Fixed header. get_opcode()/get_rcode() map a u4 onto a small enum and
		// panic (unreachable!) on unmapped values; get_*_count drive the
		// variable-length section parsers below.
		black_box(dns.get_id());
		black_box(dns.get_is_response());
		black_box(dns.get_opcode());
		black_box(dns.get_is_authoriative());
		black_box(dns.get_is_truncated());
		black_box(dns.get_is_recursion_desirable());
		black_box(dns.get_is_recursion_available());
		black_box(dns.get_zero_reserved());
		black_box(dns.get_is_answer_authenticated());
		black_box(dns.get_is_non_authenticated_data());
		black_box(dns.get_rcode());
		black_box(dns.get_query_count());
		black_box(dns.get_response_count());
		black_box(dns.get_authority_rr_count());
		black_box(dns.get_additional_rr_count());

		// Variable-length sections. Each call parses the section and the
		// per-record label/length fields.
		for q in dns.get_queries() {
			drive_query(&q);
		}
		for r in dns.get_responses() {
			drive_response(&r);
		}
		for r in dns.get_authorities() {
			drive_response(&r);
		}
		for r in dns.get_additional() {
			drive_response(&r);
		}

		for b in dns.payload().iter() {
			black_box(*b);
		}
		black_box(dns.packet_size());
		black_box(dns.from_packet());
	}
});
