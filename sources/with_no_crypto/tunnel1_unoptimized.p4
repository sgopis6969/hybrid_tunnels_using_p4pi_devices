/* Minimal P4 skeleton code adapted from example in
  https://opennetworking.org/news-and-events/blog/getting-started-with-p4/
*/

#include <core.p4>
#include <v1model.p4>

typedef bit<48> EthernetAddress;
typedef bit<32> IPv4Address;

/* HEADER DEFINITIONS */

header ethernet_t {
    EthernetAddress dst_addr;
    EthernetAddress src_addr;
    bit<16>         ether_type;
}

header ipv4_t {
    bit<4>      version;
    bit<4>      ihl;
    bit<8>      diffserv;
    bit<16>     total_len;
    bit<16>     identification;
    bit<3>      flags;
    bit<13>     frag_offset;
    bit<8>      ttl;
    bit<8>      protocol;
    bit<16>     hdr_checksum;
    IPv4Address src_addr;
    IPv4Address dst_addr;
}

/********************
 ARP header declaration by S.Gopinath (SXG) 
Reference - Geeks, Google search Gemini but field names 
are my own.

This header is harded to IPv4 and Ethernet
******************** */

header arp_t {
	bit<16> hw_type; 
	bit<16> arp_proto_type; 
	bit<8> hw_addr_length; /*in bytes*/ 
	bit<8> proto_addr_length; /*in bytes*/ 
	bit<16> opcode; /*Request-1 Reply-2*/ 
	bit<48> send_mac;
	bit<32> send_proto_address;
	bit<48> target_mac;
	bit<32> target_proto_address;
	}


/******Label *****/

header label_t {

	bit<16> magic_number ; /* Identify the tag */
	bit<16> label_id;  /***unique label identifies the custom tunnel */
	bit<16> original_ether_type;  /*Original payload ethertype */
	bit<16> flow_id; /*** Inspired by IPv6 *** but at lower level ***/
	bit<8> exp; /*** Like MPLS Exp tag ***/
}

struct headers_t {
    ethernet_t ethernet;
    /* Added by SXG */
    arp_t	arp;
    arp_t	payload_arp;
    label_t     label;
    ipv4_t     ipv4;
    ethernet_t  payload_ethernet;
    ipv4_t  payload_ipv4;
    ethernet_t  transport_ethernet;
    ipv4_t  transport_ipv4;
}

struct metadata_t {
bit<32> dst_ipv4;
bool is_tunneled;
bit <4> packet_type;
}

error {
    IPv4IncorrectVersion,
    IPv4OptionsNotSupported
}

/* PARSER */

parser my_parser(packet_in packet,
                out headers_t hd,
                inout metadata_t meta,
                inout standard_metadata_t standard_meta)
{
    	state start {

	meta.is_tunneled = false;

	packet.extract(hd.ethernet); 

	transition select(hd.ethernet.ether_type ) {
		0x0800  : parse_ipv4;  /*** We parse here for later ACL in the table control***/
		0x0806  : parse_arp;
		default : accept; /* dont worry about any other frames */
				 /* lets us pass all other frames blindly now */
        	}

	  }


	state parse_ipv4 {
		log_msg("Debug: inside parse_ipv4");
	packet.extract(hd.ipv4);

	meta.packet_type = (bit<4>) 1; /* if it is tunnelled then, later */
                                       /* it will be set to 4 in parse_label */
                                      /* otherwise, it stays at 1 */

	verify(hd.ipv4.version == 4w4,  error.IPv4IncorrectVersion);
	verify(hd.ipv4.ihl == 4w5,  error.IPv4OptionsNotSupported); 

/***anything other than 20 bytes 5 x 32 bits = 20 bytes ***/

		meta.dst_ipv4 = hd.ipv4.dst_addr ; /***Plan to use in ACL table ***/

		transition select(hd.ipv4.protocol) {

		0xFF : parse_label; /* Its a tunneled packet*/
		default: accept;
		}
	}

		state parse_arp {

		log_msg("Debug: inside parse_arp");
		packet.extract(hd.arp);
		meta.dst_ipv4 = hd.arp.target_proto_address ; /***Plan to use in ACL table ***/
		meta.packet_type = (bit<4>) 0;
		transition accept;
		}


		state parse_label {
		packet.extract(hd.label);
		meta.is_tunneled = true;
		meta.packet_type = (bit<4>) 4;
		transition accept;
		}

}  /*** End of parser ***/

/* DEPARSER */

control my_deparser(packet_out packet,
                   in headers_t hdr)
{
    apply {
	
	/***  respective headers are emitted only if the hidden valid bit is set ***/
	packet.emit(hdr.ethernet);
	packet.emit(hdr.ipv4);
	packet.emit(hdr.transport_ethernet);
	packet.emit(hdr.transport_ipv4);
	packet.emit(hdr.label);
	packet.emit(hdr.payload_ethernet);
	packet.emit(hdr.payload_arp);
	packet.emit(hdr.payload_ipv4);

	}
}

/* CHECKSUM CALCULATION AND VERIFICATION */

control my_verify_checksum(inout headers_t hdr,
                         inout metadata_t meta)
{
    apply { 

	verify_checksum(
		hdr.ipv4.isValid(),
			{
			hdr.ipv4.version,
			hdr.ipv4.ihl,
			hdr.ipv4.diffserv,
			hdr.ipv4.total_len,
			hdr.ipv4.identification,
			hdr.ipv4.flags,
			hdr.ipv4.frag_offset,
			hdr.ipv4.ttl,
			hdr.ipv4.protocol,
			hdr.ipv4.src_addr,
			hdr.ipv4.dst_addr 
			},
			hdr.ipv4.hdr_checksum,
			HashAlgorithm.csum16);

		} 

} 


control my_compute_checksum(inout headers_t hdr,
                          inout metadata_t meta)
{
    apply { 

		update_checksum(

			hdr.transport_ipv4.isValid(),
			{
			hdr.transport_ipv4.version,
			hdr.transport_ipv4.ihl,
			hdr.transport_ipv4.diffserv,
			hdr.transport_ipv4.total_len,
			hdr.transport_ipv4.identification,
			hdr.transport_ipv4.flags,
			hdr.transport_ipv4.frag_offset,
			hdr.transport_ipv4.ttl,
			hdr.transport_ipv4.protocol,
			hdr.transport_ipv4.src_addr,
			hdr.transport_ipv4.dst_addr
			},
			hdr.transport_ipv4.hdr_checksum,
			HashAlgorithm.csum16);

	} /***snd of apply ***/


} /*** end of my_compute ***/

/* INGRESS PIPELINE */

control my_ingress(inout headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t standard_metadata)
{

		action drop_action() {

			/* This is a inbuilt primitive action
			that sets egress_spec to a special value to drop***/
			mark_to_drop(standard_metadata);
		}


					

		action payload_encap( bit<16> label_tag) {

		/* Add a label and copy the source ethernet and ipv4 
                   headers */

		hdr.label.setValid(); /*** This makes header included in deparser***/

		hdr.label.magic_number = 0xAFFB;
	        hdr.label.label_id = label_tag ; /*** Assign from the table***/
		hdr.label.original_ether_type = hdr.ethernet.ether_type;
		hdr.label.flow_id = 0;
		hdr.label.exp = 0; /*** flow-id and exp are not yet used***/

		
			/*Untunnelled ARP packet */

			/*** Make new inner/payload headers valid ***/
			hdr.payload_ethernet.setValid();

			/***copying entire header ***/
			hdr.payload_ethernet = hdr.ethernet;


			if(hdr.arp.isValid()){

			hdr.payload_arp = hdr.arp;
			}


			/*Untunneled IPv4 packet */

			
			if(hdr.ipv4.isValid()){

			/***copying entire header ***/

			/*** Make new inner/payload headers valid ***/

			hdr.payload_ipv4 = hdr.ipv4;

		/* As the payload ip segment crosses our P4 switch..decrement the ttl */
			/*hdr.payload_ipv4.ttl = hdr.payload_ipv4.ttl -1 ; */
			}

		} /* end of action block */




                action transport_encap(bit<48> tsrc_mac, bit<48> tdst_mac,
					  bit<32> tsrc_ipv4, bit<32> tdst_ipv4,
					  bit<9> port) {

		          hdr.transport_ethernet.setValid();
		          hdr.transport_ipv4.setValid();

			  hdr.ethernet.setInvalid();
			  hdr.ipv4.setInvalid();

			  /* Ethernet frame construction*/
		          hdr.transport_ethernet.dst_addr = tdst_mac;
		          hdr.transport_ethernet.src_addr = tsrc_mac;
				/* No arp is required*/
			  hdr.transport_ethernet.ether_type = 0x0800;

                          /* Ipv4 construction */

		hdr.transport_ipv4.version = (bit<4>) 4;
		hdr.transport_ipv4.ihl = (bit<4>) 5;
		hdr.transport_ipv4.diffserv = (bit<8>) 0;
		hdr.transport_ipv4.total_len =  (bit <16>) 9 + (bit<16>) 20 + (bit <16>) standard_metadata.packet_length;
		hdr.transport_ipv4.identification =  (bit<16>) 0;
		hdr.transport_ipv4.flags =  (bit<3>) 0;
		hdr.transport_ipv4.frag_offset =  (bit<13>) 0;
		hdr.transport_ipv4.ttl =  (bit<8>) 255;
		hdr.transport_ipv4.protocol =  (bit<8>) 0xFF;
		hdr.transport_ipv4.src_addr = tsrc_ipv4;
		hdr.transport_ipv4.dst_addr = tdst_ipv4;


			standard_metadata.egress_spec = port; 

		} /* end of action block */



		action transport_decap(bit<9> port) {

			hdr.ethernet.setInvalid();
			hdr.ipv4.setInvalid();
			hdr.label.setInvalid();
		
			standard_metadata.egress_spec = port; 
		}
			



		table payload_encap_table {

			key = {
				standard_metadata.ingress_port :exact;
				meta.dst_ipv4: lpm ;

		/* Dst ip addrr means the Ip address of the other end */
		/* ingress port through which packet arrives */
			}


			actions =  {

				payload_encap;
				drop_action;
			}
		size = 512;
		default_action = drop_action;

	  	} /***End of table definition***/

		


		table transport_encap_table {

			 key = {
				hdr.label.label_id: exact;
			}

			actions =  {
				transport_encap;
				drop_action;
			}

		size = 512;
		default_action = drop_action;

		} /*** End of table definition***/


		table transport_decap_table {

			 key = {
				hdr.label.label_id: exact ;
			}
			
			actions = {

				transport_decap;
				drop_action;
			}
		size = 512;
		default_action = drop_action;

		} /*** End of table definition***/

		





    apply {

		if(meta.is_tunneled == true) {
		transport_decap_table.apply();
			}



		else if(meta.is_tunneled == false){ 
				payload_encap_table.apply();
				transport_encap_table.apply();
				/*transport_encap_table.apply();*/
			}

				
    	} /* end of apply() */

} /* end of ingress pipeline processing*/

/* EGRESS PIPELINE */
control my_egress(inout headers_t hdr,
                 inout metadata_t meta,
                 inout standard_metadata_t standard_metadata)
{
    apply { }
}

/* SWITCH PACKAGE DEFINITION */

V1Switch(my_parser(),
         my_verify_checksum(),
         my_ingress(),
         my_egress(),
         my_compute_checksum(),
         my_deparser()) main;

