//#[derive(Debug)]
use pnet::datalink;
use pnet::packet::Packet;
use pnet::datalink::NetworkInterface;
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv4::MutableIpv4Packet;

mod enc_dec;

fn main() {


    let interfaces = datalink::interfaces();

    let mut my_interface :NetworkInterface = interfaces[0].clone();
                    //println!("{:#?}",my_interface);


    for iface in interfaces {

            //println!("{:#?}",iface);

            if iface.name == "veth5-1".to_string() {

                    //Copy it
                    my_interface  = iface.clone();
                    //println!("{:#?}",my_interface);
            }
    }
            

        //channel is a function defined in datalink module. It takes & interface 
        //as one parameter cna Config (struct in datalink)  instance as another 
        //parameter. Default::default() -> instance of Config.
        //
        //
        //channel returns enum Channel 
        let dlink_channel = datalink::channel(&my_interface, Default::default()); 


               let  (mut tx, mut rx) = match dlink_channel {
                                Ok(Ethernet(tx, rx)) => (tx, rx),
                                Ok(_) => panic!("Not supported channel"),
                                Err(e) => panic!("could not get the channel"),
               };


                // I dont understand rx is a trait or trait object
                // but follow the example.

                loop {
                let frame_result  =  rx.next(); //This returns Result<&[u8], Error)

                let mut packet = match frame_result {

                        Ok(packet) => packet,
                        Err(e) => panic!("Error in receiving the Ethernet frame"),
                };

                    //println!("Length : {}",packet.len());

                    let ethernet_packet = EthernetPacket::new(packet).unwrap();

                    let ether_type = ethernet_packet.get_ethertype();

                    //println!("Ethertype: {:x}", ether_type.0);


                    if ether_type == EtherTypes::Ipv4  {

                            // Ipv4 packet and we need to process this

                    let ethernet_packet_payload = ethernet_packet.payload();

                    let ipv4_packet = Ipv4Packet::new(& ethernet_packet_payload).unwrap();

                        
                    //println!("IPSource: {}", ipv4_packet.get_source());
                    //println!("IPDestination: {}", ipv4_packet.get_destination());

                    let ipv4_protocol = ipv4_packet.get_next_level_protocol().0;

                    //Let us create a new vector for our jewel

                    //In-efficient way of doing
                    let tunnel_payload = Vec::from(ipv4_packet.payload());

                    let mut ipv4_packet_raw = Vec::from(ipv4_packet.packet());
                    //let mut tx_ipv4_packet = MutableIpv4Packet::new(& mut ipv4_packet_raw).unwrap();

                     
                    let mut ether_packet_raw =  Vec::from(ethernet_packet.packet());

                    //let mut tx_ethernet_packet = MutableEthernetPacket::new(& mut ether_packet_raw).unwrap();

                    // Split in to various components.
                    
                    if ipv4_protocol == 0xFF {
                    let mut tag_header = tunnel_payload.clone();

                    //The tunnel_payload has label-tag(9bytes) and end_layer2
                    let end_layer2 = tag_header.split_off(9); 
            
                    let mut enc_end_layer2 = enc_dec::payload_encrypt(&end_layer2);

                    tag_header.append(& mut enc_end_layer2); // this contains tag + enc layer2

                    let mut enc_tunnel_payload = tag_header; //moved. tag_header no longer valid 


                     //Process the IP Packet

                     let mut ipv4_header = ipv4_packet_raw.clone();

                     //spliting off 20 bytes leave it ipv4_header

                     let mut ipv4_payload1 = ipv4_header.split_off(20); //Ipv4 header split

                     ipv4_payload1.clear(); // throw this away
                     ipv4_header.append(& mut enc_tunnel_payload); 

                     let mut ipv4_packet_raw1 = ipv4_header; //Moved

              //let mut tx_ipv4_packet = MutableIpv4Packet::new(& mut ipv4_packet_raw1).unwrap();


                     //Process the Ethernetpacket

                      let mut ether_header = ether_packet_raw.clone();
                      //Splitting off 14 bytes leave it to ether_header

                      let mut ether_payload1 = ether_header.split_off(14);
                      ether_payload1.clear();
                      ether_header.append(& mut ipv4_packet_raw1);

                      let mut ether_packet_raw1 = ether_header; // moved


                    tx.send_to(&ether_packet_raw1,Some(my_interface.clone())); 

                    } //end if

                    }


                } //end of loop
                    

}
