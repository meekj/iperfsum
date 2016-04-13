// Summarize packet capture data from iperf tests
// Jon Meek - 2016-03-26


// License: BSD Three Clause - To match libpcap and Flags.hh
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
//   1. Redistributions of source code must retain the above copyright
//      notice, this list of conditions and the following disclaimer.
//   2. Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the following disclaimer in
//      the documentation and/or other materials provided with the
//      distribution.
//   3. The names of the authors may not be used to endorse or promote
//      products derived from this software without specific prior
//      written permission.
//
// THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.


// Development file: $Id: iperfsum.cpp,v 1.6 2016/04/08 13:31:07 meekj Exp $

// MacOS X
// clang++ -lpcap -o iperfsum iperfsum.cpp -std=c++11

// Ubuntu Linux
// clang++-3.6 -std=c++11 -o iperfsum iperfsum.cpp -lpcap

// Voyage Linux, clang had linking issues
// g++ -o iperfsum iperfsum.cpp -lpcap -std=c++11

// iperfsum  --filter 'dst port 3000' --file /n2/data/iperf/20100916/t2-127.0.1.1-snd.tcpd

//#include <Rcpp.h> // Remnant of a version that works from R
//using namespace Rcpp;

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>   // IP protocols, standard ports, etc and IPV6
#include <arpa/inet.h>    // Conversions
#include <net/ethernet.h> // Ethertypes, etc

#ifdef __linux__
#include <netinet/ether.h> // Conversions, but not on Mac
#endif

#include <netinet/ip.h>    // IP Header data structures
#include <netinet/ip6.h>

#include <netinet/tcp.h>
#include <netinet/udp.h>

// #include <iomanip> // Future use of put_time
#include <ctime>

#include <iostream>
#include <vector>
#include <string>
#include <ostream>
#include <unordered_map>

#include "Flags.hh" // https://github.com/songgao/flags.hh

#define SIZE_ETHERNET  14     // Ethernet header
#define MAX_802_3_SIZE 0x05dc // To identify 802.3 packets
#define SIZE_8021q     4

#define TCP_FLAG_FIN 0x01 // TCP flag masks, ECE & CWR not in Linux headers, so define our own
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20
#define TCP_FLAG_ECE 0x40
#define TCP_FLAG_CWR 0x80


// C++ side storage - expandable containers
int reserve_size = 10000; // Vector capacity reserve, don't start small, but may not help much

std::vector <double>      pkttime;
std::vector <int>         framesize, ip_id, src_port, dst_port, payload_size, tcp_retrans;
std::vector <u_int>       tcp_seq_num, tcp_ack;
std::vector <std::string> src_mac, dst_mac, src_addr, dst_addr, protocol, tcp_flags;

//std::unordered_map<std::string, int> tcp_hash(size_t size = reserve_size);
std::unordered_map<std::string, int> tcp_hash, direction_hash;

// Vectors and temp vars for per unit time results
std::vector <int>         bin_index, bin_packets, bin_bytes, bin_retrans;
std::vector <double>      bin_kbps;
std::vector <std::string> bin_time;
int t_packets = 0, t_bytes = 0, t_retrans = 0, first_index_offset, last_index;

double kbps;
bool debug = false;
bool gdebug = false; // Global debug flag set from R call arg

char t_timestring[50]; // Temporary time storage
time_t tt;

void decode_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) { // decode packet and stuff data into vectors

  static int count = 0;                       // Packet counter
  const int interrupt_check_interval = 20000; // Check for user interrupt every this many packets

  // Pointers to packet headers
  const struct ether_header *ethernet;  // Ethernet header
  const struct ip           *ip4;       // IPv4 header from netinet/ip.h
  const struct ip6_hdr      *ip6;       // IPv6 header
  const struct tcphdr       *tcp;       // TCP header
  const struct udphdr       *udp;       // UDP header

  int size_frame, size_capture, size_ip, size_tcp, size_payload, ip_protocol, ip_total_length;

  char* mac_ptr; // for MAC address extraction

  char ip_src[INET6_ADDRSTRLEN]; // Use for both v4 & v6
  char ip_dst[INET6_ADDRSTRLEN];
  int port_src, port_dst;
  tcp_seq t_tcp_seq_num, t_tcp_ack;

  std::string t_tcp_flags = "";
  
  std::ostringstream t_tcp_pkt_key("", std::ios::ate);
  std::string tcp_pkt_key = "";

  std::ostringstream t_direction_key("", std::ios::ate);
  std::string direction_key = "";

  int     ts_seconds, ts_useconds, ts_index;
  double  timestamp = 0;
  u_short ethertype = 0;
  int     vlan_tag_length = 0, current_index;

  count++; // Packet counter

  //  if (count % interrupt_check_interval == 0) Rcpp::checkUserInterrupt(); // Check for user intervention

  size_frame   = header->len;      // Actual packet size including Ethernet header
  size_capture = header->caplen;

  ts_seconds  = header->ts.tv_sec; // Packet timestamp
  ts_useconds = header->ts.tv_usec;
  timestamp   = ts_seconds + ts_useconds / 1.0e6;

  if (count == 1) { // Second resolution for now, finer options later
    first_index_offset = ts_seconds;
    last_index = 0;
  }

  current_index = ts_seconds - first_index_offset;
  if (current_index > last_index) { // Save previous bin's data
    tt = first_index_offset + last_index;
    std::strftime(t_timestring, sizeof(t_timestring), "%FT%T", gmtime(&tt));

    kbps = 8 * t_bytes / 1000.0;
    bin_index.push_back(last_index);
    bin_packets.push_back(t_packets);
    bin_bytes.push_back(t_bytes);
    bin_kbps.push_back(kbps);
    bin_retrans.push_back(t_retrans);
    bin_time.push_back(t_timestring);
    t_packets = 0, t_bytes = 0, t_retrans = 0;
  }
  last_index = current_index;

  // Unpack ethernet header
  ethernet = (struct ether_header*)(packet);
  ethertype = ntohs(ethernet->ether_type);

  pkttime.push_back(timestamp); // Packet time & Frame Size for all protocols
  framesize.push_back(size_frame);

  t_packets++; // Per time bin count
  t_bytes += size_frame;

  mac_ptr = ether_ntoa((const struct ether_addr *)&ethernet->ether_shost); // Save MAC addresses
  src_mac.push_back(mac_ptr);

  mac_ptr = ether_ntoa((const struct ether_addr *)&ethernet->ether_dhost);
  dst_mac.push_back(mac_ptr);

  vlan_tag_length = 0; // Be certain

  if (ethertype == ETHERTYPE_VLAN) { // Has 802.1 p/q tag
    if (gdebug) std::cout << "VLAN tagged\n";
    vlan_tag_length = SIZE_8021q;    // Assume no additional tags, set additional offset
    ethertype = ETHERTYPE_IP;        // Then treat as standard IPv4 packet
  }

  if ((ethertype == ETHERTYPE_IP) || (ethertype == ETHERTYPE_IPV6)) { // IP of some version

    switch(ethertype) {

    case ETHERTYPE_IP:
      // define/compute ip header offset
      ip4 = (struct ip*)(packet + SIZE_ETHERNET + vlan_tag_length);

      ip_total_length = ntohs(ip4->ip_len);

      inet_ntop(AF_INET, &(ip4->ip_src), ip_src, INET_ADDRSTRLEN); // Don't use inet_ntoa !
      inet_ntop(AF_INET, &(ip4->ip_dst), ip_dst, INET_ADDRSTRLEN); // Issues with static buffer for output and no IPv6 support

      size_ip = ip4->ip_hl * 4;
      if (size_ip < 20) {
	//	std::cout << std::setprecision(11) << "Invalid IP header length, Packet: " << count << "   " << timestamp << " s   " <<
	std::cout <<  "Invalid IP header length, Packet: " << count << "   " << timestamp << " s   " <<
	  ip_src << " --> " << ip_dst << "  " << size_ip << " bytes" << std::endl;
	return;
      }

      // Save IP header details in vectors
      ip_id.push_back(ntohs(ip4->ip_id));
      src_addr.push_back(ip_src);
      dst_addr.push_back(ip_dst);

      ip_protocol = ip4->ip_p;

      break;

    case ETHERTYPE_IPV6:
      ip6 = (struct ip6_hdr*)(packet + SIZE_ETHERNET + vlan_tag_length);
      // ip6 = (struct ip6_hdr*)(packet + SIZE_ETHERNET);

      ip_total_length = ntohs(ip6->ip6_plen) + 40;

      inet_ntop(AF_INET6, &(ip6->ip6_src), ip_src, INET6_ADDRSTRLEN);
      inet_ntop(AF_INET6, &(ip6->ip6_dst), ip_dst, INET6_ADDRSTRLEN);
      
      src_addr.push_back(ip_src);
      dst_addr.push_back(ip_dst);
      ip_id.push_back(0);
      
      size_ip = 40;          // Fixed size of IPv6 header, should get from .h file
      ip_protocol = ip6->ip6_nxt; // Making a general assumption here

      break;
    }

    // Track packet directions, usually just one for iperf summary
    t_direction_key << std::string(ip_src) << "->" << std::string(ip_dst);
    direction_key = t_direction_key.str(); // Make it a std::string
    direction_hash[direction_key]++;

    switch(ip_protocol) { // Handle each IP protocol

    case IPPROTO_TCP:
	
      // define/compute tcp header offset
      tcp = (struct tcphdr*)(packet + SIZE_ETHERNET + vlan_tag_length + size_ip);
      size_tcp = tcp->th_off*4;
      
      if (size_tcp < 20) {
	//	std::cout << std::setprecision(11) << "Invalid TCP header length, Packet: " << count << "   " << timestamp << " s   " <<
	std::cout <<  "Invalid TCP header length, Packet: " << count << "   " << timestamp << " s   " <<
	  ip_src << " --> " << ip_dst << " bytes  IP header: " <<  size_ip << " TCP header: " << size_tcp << " bytes   VLAN tag length: " << vlan_tag_length <<
	  "  Capture length: " << size_capture << std::endl;
	return;
      }
      port_src = ntohs(tcp->th_sport);
      port_dst = ntohs(tcp->th_dport);

      t_tcp_seq_num = ntohl(tcp->th_seq);
      t_tcp_ack     = ntohl(tcp->th_ack);

      t_tcp_flags = ""; // Build flags string, in a 'nice' order

      if (tcp->th_flags & TCP_FLAG_SYN) {
	t_tcp_flags += 'S';
      }
      if (tcp->th_flags & TCP_FLAG_ACK) {
	t_tcp_flags += 'A';
      }
      if (tcp->th_flags & TCP_FLAG_FIN) {
	t_tcp_flags += 'F';
      }
      if (tcp->th_flags & TCP_FLAG_RST) {
	t_tcp_flags += 'R';
      }
      if (tcp->th_flags & TCP_FLAG_PSH) {
	t_tcp_flags += 'P';
      }
      if (tcp->th_flags & TCP_FLAG_URG) {
	t_tcp_flags += 'U';
      }
      
      if (tcp->th_flags & TCP_FLAG_ECE) { // Not in Linux headers
	t_tcp_flags += 'E';
      }
      if (tcp->th_flags & TCP_FLAG_CWR) {
	t_tcp_flags += 'C';
      }
      
      size_payload = ip_total_length - (size_ip + size_tcp);

      t_tcp_pkt_key << std::string(ip_src) << '-' << port_src << '_' << std::string(ip_dst) << '-' << port_dst << ':' << t_tcp_seq_num;
      tcp_pkt_key = t_tcp_pkt_key.str(); // Make it a std::string


      if (size_payload > 0) {
	tcp_hash[tcp_pkt_key]++;
      }
      
      //      if (gdebug) {std::cout <<  "Key:" << t_tcp_pkt_key.str() << "  Retrans: " << tcp_hash[tcp_pkt_key] << std::endl;}
      if (gdebug & (tcp_hash[tcp_pkt_key] > 1)) {std::cout <<  "Key:" << tcp_pkt_key << "  Retrans: " << tcp_hash[tcp_pkt_key] << std::endl;}
      
      //      tcp_pkt_key = t_tcp_pkt_key;
      
      protocol.push_back("TCP");
      src_port.push_back(port_src);
      dst_port.push_back(port_dst);
      tcp_flags.push_back(t_tcp_flags);
      payload_size.push_back(size_payload);
      tcp_seq_num.push_back(t_tcp_seq_num);
      tcp_ack.push_back(t_tcp_ack);
      if (tcp_hash[tcp_pkt_key] > 0) { // Only packets with a data payload will have a hash entry
	tcp_retrans.push_back(tcp_hash[tcp_pkt_key] - 1);
	if (tcp_hash[tcp_pkt_key] > 1) {t_retrans++;}
      } else {
	tcp_retrans.push_back(0);
      }
      break;

    case IPPROTO_UDP:

      udp = (struct udphdr*)(packet + SIZE_ETHERNET + vlan_tag_length + size_ip);
      size_payload = ip_total_length - (size_ip + 8);

      protocol.push_back("UDP");
      t_tcp_flags = "";
      src_port.push_back(ntohs(udp->uh_sport));
      dst_port.push_back(ntohs(udp->uh_dport));
      tcp_flags.push_back(t_tcp_flags);
      payload_size.push_back(size_payload);
      tcp_seq_num.push_back(0);
      tcp_ack.push_back(0);
      tcp_retrans.push_back(0);

      break;

    case IPPROTO_ICMP:
      t_tcp_flags = "";
      protocol.push_back("ICMP");
      src_port.push_back(0);
      dst_port.push_back(0);
      tcp_flags.push_back(t_tcp_flags);
      payload_size.push_back(0);
      tcp_seq_num.push_back(0);
      tcp_ack.push_back(0);
      tcp_retrans.push_back(0);

      break;

    case IPPROTO_IP:
      t_tcp_flags = "";
      protocol.push_back("IP-IP");
      src_port.push_back(0);
      dst_port.push_back(0);
      tcp_flags.push_back(t_tcp_flags);
      payload_size.push_back(0);
      tcp_seq_num.push_back(0);
      tcp_ack.push_back(0);
      tcp_retrans.push_back(0);
      tcp_retrans.push_back(0);

      break;

    default:
      t_tcp_flags = "";
      protocol.push_back("UNK-IP");
      src_port.push_back(0);
      dst_port.push_back(0);
      tcp_flags.push_back(t_tcp_flags);
      payload_size.push_back(0);
      tcp_seq_num.push_back(0);
      tcp_ack.push_back(0);
      tcp_retrans.push_back(0);

      break;
    }

    return;
  }


  if (ethertype <= MAX_802_3_SIZE) { // Improve this later, includes STP 802.1d
    // printf(" 802.3  %d", size_frame);
    // printf("\n");

    protocol.push_back("802.3");
    ip_id.push_back(0);
    src_addr.push_back("");
    dst_addr.push_back("");

    t_tcp_flags = "";
    src_port.push_back(0);
    dst_port.push_back(0);
    tcp_flags.push_back(t_tcp_flags);
    payload_size.push_back(0);
    tcp_seq_num.push_back(0);
    tcp_ack.push_back(0);
    tcp_retrans.push_back(0);

    return;
  }


  switch(ethertype) { // Other EtherTypes, for now, may need optimization later

  case  ETHERTYPE_ARP:
    protocol.push_back("ARP");
    ip_id.push_back(0);
    src_addr.push_back("");
    dst_addr.push_back("");

    t_tcp_flags = "";
    src_port.push_back(0);
    dst_port.push_back(0);
    tcp_flags.push_back(t_tcp_flags);
    payload_size.push_back(0);
    tcp_seq_num.push_back(0);
    tcp_ack.push_back(0);
    tcp_retrans.push_back(0);

    break;

  case  ETHERTYPE_REVARP:
    protocol.push_back("RARP");
    ip_id.push_back(0);
    src_addr.push_back("");
    dst_addr.push_back("");

    t_tcp_flags = "";
    src_port.push_back(0);
    dst_port.push_back(0);
    tcp_flags.push_back(t_tcp_flags);
    payload_size.push_back(0);
    tcp_seq_num.push_back(0);
    tcp_ack.push_back(0);
    tcp_retrans.push_back(0);

    break;

  case  ETHERTYPE_LOOPBACK:
    protocol.push_back("LOOP");
    ip_id.push_back(0);
    src_addr.push_back("");
    dst_addr.push_back("");

    t_tcp_flags = "";
    src_port.push_back(0);
    dst_port.push_back(0);
    tcp_flags.push_back(t_tcp_flags);
    payload_size.push_back(0);
    tcp_seq_num.push_back(0);
    tcp_ack.push_back(0);
    tcp_retrans.push_back(0);

    break;

  case  ETHERTYPE_PUP:
    protocol.push_back("PUP");
    ip_id.push_back(0);
    src_addr.push_back("");
    dst_addr.push_back("");

    t_tcp_flags = "";
    src_port.push_back(0);
    dst_port.push_back(0);
    tcp_flags.push_back(t_tcp_flags);
    payload_size.push_back(0);
    tcp_seq_num.push_back(0);
    tcp_ack.push_back(0);
    tcp_retrans.push_back(0);

    break;

    // case  ETHERTYPE_AT: // MacOS X headers seem to be missing these
    //   printf(" AT");
    //   printf("\n");
    //   break;

    // case  ETHERTYPE_AARP:
    //   printf(" AARP");
    //   printf("\n");
    //   break;

    // case  ETHERTYPE_IPX:
    //   printf(" IPX");
    //   printf("\n");
    //   break;
    
    // case  ETHERTYPE_SPRITE:
    //   printf(" SPR");
    //   printf("\n");
    //   break;

  default:
    //  printf(" UNK");
    //  printf("\n");

    protocol.push_back("UNK");
    ip_id.push_back(0);
    src_addr.push_back("");
    dst_addr.push_back("");

    t_tcp_flags = "";
    src_port.push_back(0);
    dst_port.push_back(0);
    tcp_flags.push_back(t_tcp_flags);
    payload_size.push_back(0);
    tcp_seq_num.push_back(0);
    tcp_ack.push_back(0);
    tcp_retrans.push_back(0);

    break;
  }
  return;
}

// This program is modified from libpcapR. Some Rcpp related code is left here commented for possible future use

//'Load libpcap data into R data frame
//'
//'@param str input filename, libpcap_filter
//'@return packet data in a data frame
// [[Rcpp::export]]

// DataFrame read_pcap( std::vector< std::string > file_arg, std::vector< std::string > filter_arg, bool debug = false ) {
// DataFrame read_pcap( std::string file_arg, std::string filter_arg, bool debug = false ) {

int main(int argc, char **argv) {

  const std::string rcs_id = "$Id: iperfsum.cpp,v 1.6 2016/04/08 13:31:07 meekj Exp $";
  std::string sfile = "", sfilter = "";
  bool debug, verbose, version, help;

  Flags flags;

  flags.Var(sfile,   'r', "file", std::string(""), "libpcap input file", "Required");
  flags.Var(sfilter, 'f', "filter", std::string(""), "Filter in libpcap format", "Often required but defaults to empty");

  flags.Bool(debug,   'd', "debug", "show debug messsages", "Optional");
  flags.Bool(verbose, 'v', "verbose", "show all packets matching the filter,\n otherwise only the per time bin summary is printed", "Optional");
  flags.Bool(version, 'V', "version", "show version number and exit", "Optional");
  flags.Bool(help,    'h', "help", "show this help and exit", "Optional");

  if (argc < 2) {
    flags.PrintHelp(argv[0]);
    return 1;
  }

   if (!flags.Parse(argc, argv)) {
    flags.PrintHelp(argv[0]);
  } else if (help) {
    flags.PrintHelp(argv[0]);
    return 0;
  } else if (version) {
    std::cout << "Version: " << rcs_id << std::endl;
    return 0;
  }

  if (sfile.length() < 1) { // Filename is required
    flags.PrintHelp(argv[0]);
    return 1;
  }

  char *file = &sfile[0u];
  char *filter_exp = &sfilter[0u];

  std::cout << "File: " << sfile << "   Filter: " << sfilter << "\n";

  //  return 0;

  gdebug = debug;

  char errbuf[PCAP_ERRBUF_SIZE] = {' '}; // error buffer
  pcap_t *handle;			// packet capture file handle

  struct bpf_program fp;		// compiled filter program (expression)
  //  bpf_u_int32 mask;			// subnet mask
  //  bpf_u_int32 net;			// ip Needed if filter is used ?
  int num_packets = 0;			// number of packets to read - 0 read to end of file, probably should be arg

  if (debug) std::cout << "Ready to clear vectors\n";
  
  src_mac.clear();
  dst_mac.clear();

  framesize.clear();  // Clear out data from any previous usage
  pkttime.clear();    // These are global vectors due to the call-back mechanism of libpcap
  protocol.clear();
  src_addr.clear();
  src_port.clear();
  dst_addr.clear();
  dst_port.clear();
  ip_id.clear();
  tcp_flags.clear();
  payload_size.clear();
  tcp_seq_num.clear();
  tcp_ack.clear();
  tcp_retrans.clear();

  if (debug) std::cout << "Ready to reserve vector capacity\n";

  // Start with reasonable vector capacity, no impact with 121k packets and reserve_size = 10k
  framesize.reserve(reserve_size);
  pkttime.reserve(reserve_size);
  protocol.reserve(reserve_size);
  src_addr.reserve(reserve_size);
  src_port.reserve(reserve_size);
  dst_addr.reserve(reserve_size);
  dst_port.reserve(reserve_size);
  ip_id.reserve(reserve_size);
  tcp_flags.reserve(reserve_size);
  payload_size.reserve(reserve_size);
  tcp_seq_num.reserve(reserve_size);
  tcp_ack.reserve(reserve_size);
  tcp_retrans.reserve(reserve_size);

  if (debug) std::cout << "Ready to open file\n";

  // Open packet capture file
  handle = pcap_open_offline(file, errbuf);

  if (handle == NULL) {
    std::cout << "Couldn't open file: " << file << "  " << errbuf << std::endl;
    return 1;
    //    throw Rcpp::exception("File open error");
  }

  if (debug) std::cout << "Ready to compile filter\n";

  // Compile the filter expression
  if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
    std::cout << "Couldn't parse filter: " << filter_exp << "  " << pcap_geterr(handle) << std::endl;
    return 1;
    //    throw Rcpp::exception("Filter parsing error");
  }

  if (debug) std::cout << "Ready to apply filter\n";

  // Apply the compiled filter
  if (pcap_setfilter(handle, &fp) == -1) {
    std::cout << "Could not set the filter: " << filter_exp << "  " << pcap_geterr(handle) << std::endl;
    return 1;
    //    throw Rcpp::exception("Filter set error");
  }

  if (debug) std::cout << "Ready to start loop\n";

  pcap_loop(handle, num_packets, decode_packet, NULL); // Setup the callback function

  if (debug) std::cout << "Back from loop\n";

  pcap_freecode(&fp); // Clean-up
  pcap_close(handle);

  // Debug, in case vector lengths are not equal
  if (debug) 
    std::cout << "Vector Sizes: pkttime " << pkttime.size()    << "  framesize " << framesize.size()
	  << "  protocol " << protocol.size()  << "  src_addr " << src_addr.size() << "  src_port " <<  src_port.size()
	  << "  dst_addr " << dst_addr.size()  << "  dst_port " << dst_port.size()
	  << "  ip_id " << ip_id.size()  << "  tcp_flags " << tcp_flags.size()
	  << "  payload_size " << payload_size.size()
	  << "  tcp_seq_num " << tcp_seq_num.size()
	  << "  tcp_ack " << tcp_ack.size() << "  tcp_retrans " << tcp_retrans.size()
	  << std::endl;

  // Save final time bin data
  tt = first_index_offset + last_index;
  std::strftime(t_timestring, sizeof(t_timestring), "%FT%T", gmtime(&tt));
  kbps = 8 * t_bytes / 1000.0;
  bin_index.push_back(last_index);
  bin_packets.push_back(t_packets);
  bin_bytes.push_back(t_bytes);
  bin_kbps.push_back(kbps);
  bin_retrans.push_back(t_retrans);
  bin_time.push_back(t_timestring);

  std::cout << "Direction: ";
  // Identify iperf direction and start time, usually just one direction, should we warn if not?
  for (auto kv : direction_hash) {
    std::cout << kv.first << " (" << kv.second << ") ";
  }
  std::cout << std::endl;

  tt = first_index_offset;
  std::strftime(t_timestring, sizeof(t_timestring), "%F %T", gmtime(&tt));
  std::cout << "Start: " << t_timestring << std::endl;

  printf("    n  Packets        Bytes      kbps   ReTrans  Time\n");
  int bincount = bin_index.size();
  for (int i = 0; i < bincount; i++) {
    printf("%5d %8d %12d %12.2f %5d  %s\n", 
	   bin_index[i], bin_packets[i], bin_bytes[i], bin_kbps[i], bin_retrans[i], bin_time[i].c_str());
  }

  if (verbose) {
    int pktcount = pkttime.size();
    for (int i = 0; i < pktcount; i++) {
      printf("%5d %f %s %s %s %16s %5d  %16s %5d %8d %4d %12u %4d\n",
	     i+1, pkttime[i], src_mac[i].c_str(), src_mac[i].c_str(),  protocol[i].c_str(), src_addr[i].c_str(), src_port[i],
	     dst_addr[i].c_str(), dst_port[i], ip_id[i], framesize[i], tcp_seq_num[i], tcp_retrans[i]);
    }
  }

  return 0;
}


// iperfsum Benchmark 245,550 Packets

// Xeon E3      1.304 s
// MacBook Pro  2.138
// APU          9.228 s
// RPi3        13.180 s

// tcpd_read - Pure Perl (and it does a bit more session tracking)

// Xeon E3      8.494
// MacBook Pro  9.174
// APU         55.515
// RPi3        80.620



