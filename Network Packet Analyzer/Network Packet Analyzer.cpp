#include <iostream>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <iomanip>
#include <sstream>
#include <fstream>

void printTimestamp(const timeval& timestamp) {
    std::time_t time = timestamp.tv_sec;
    std::cout << "Timestamp: " << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S") << "." << std::setw(6) << std::setfill('0') << timestamp.tv_usec << std::endl;
}

void printPacketInfo(const ip* ipHeader, const tcphdr* tcpHeader, const pcap_pkthdr* header) {
    std::cout << "Packet Info:" << std::endl;
    std::cout << "Source IP: " << inet_ntoa(ipHeader->ip_src) << std::endl;
    std::cout << "Destination IP: " << inet_ntoa(ipHeader->ip_dst) << std::endl;
    
    const ether_header* ethHeader = reinterpret_cast<const ether_header*>(reinterpret_cast<const u_char*>(ipHeader) - sizeof(ether_header));
    std::cout << "Source MAC: " << ether_ntoa(reinterpret_cast<const ether_addr*>(&ethHeader->ether_shost)) << std::endl;
    std::cout << "Destination MAC: " << ether_ntoa(reinterpret_cast<const ether_addr*>(&ethHeader->ether_dhost)) << std::endl;
    
    std::cout << "Packet Length: " << header->len << " bytes" << std::endl;
}

void printProtocol(const ip* ipHeader, const tcphdr* tcpHeader) {
    std::cout << "Protocol: TCP" << std::endl;
    std::cout << "IP Version: IPv" << ipHeader->ip_v << std::endl;
    std::cout << "Header Length: " << ipHeader->ip_hl * 4 << " bytes" << std::endl;
}

void printFlags(const tcphdr* tcpHeader) {
    std::cout << "TCP Flags: ";
    if (tcpHeader->th_flags & TH_FIN)
        std::cout << "FIN ";
    if (tcpHeader->th_flags & TH_SYN)
        std::cout << "SYN ";
    if (tcpHeader->th_flags & TH_RST)
        std::cout << "RST ";
    if (tcpHeader->th_flags & TH_PUSH)
        std::cout << "PUSH ";
    if (tcpHeader->th_flags & TH_ACK)
        std::cout << "ACK ";
    if (tcpHeader->th_flags & TH_URG)
        std::cout << "URG";
    std::cout << std::endl;
}

void printHexDump(const u_char* packetData, int packetLength) {
    std::cout << "Hex Dump:" << std::endl;
    for (int i = 0; i < packetLength; i++) {
        std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(packetData[i]) << " ";
        if ((i + 1) % 16 == 0)
            std::cout << std::endl;
    }
    std::cout << std::dec << std::endl;
}

void savePacketToFile(const u_char* packetData, int packetLength) {
    std::ofstream outputFile("captured_packet.bin", std::ios::out | std::ios::binary);
    if (outputFile.is_open()) {
        outputFile.write(reinterpret_cast<const char*>(packetData), packetLength);
        outputFile.close();
        std::cout << "Packet saved to captured_packet.bin" << std::endl;
    } else {
        std::cerr << "Failed to open file for saving packet" << std::endl;
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;
    const u_char* packetData;
    pcap_pkthdr header;

    // Open the network device
    handle = pcap_open_live("wlan0", BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Failed to open device: " << errbuf << std::endl;
        return 1;
    }

    while (true) {
        packetData = pcap_next(handle, &header);
        if (packetData != nullptr) {
            const ip* ipHeader = reinterpret_cast<const ip*>(packetData + sizeof(ether_header));
            const tcphdr* tcpHeader = reinterpret_cast<const tcphdr*>(reinterpret_cast<const u_char*>(ipHeader) + ipHeader->ip_hl * 4);

            printTimestamp(header.ts);
            printPacketInfo(ipHeader, tcpHeader, &header);
            printProtocol(ipHeader, tcpHeader);
            printFlags(tcpHeader);
            printHexDump(packetData, header.len);
            savePacketToFile(packetData, header.len);

            std::cout << "===============================" << std::endl;
        }
    }

    pcap_close(handle);
    return 0;
}
