#pragma once

#include <pcap.h>
#include "mac.h"
#include "ip.h"
#include <map>
#include <vector>
#include <utility>
#include <string>

using namespace std;

class addressInfo {
public:
    Mac myMac;
    Ip myIp;
    map<string, Mac> arpCache;
    vector<pair<char*, char*> > targetPairs;
    vector<pair<Ip, Ip> > targetPairs_IP_object;

    Mac getMyMac(const char* ifname);
    Ip getMyIp(const char* ifname);

    void printAddressInfo(void){
        printf("myMac: %s\n",myMac.operator string().c_str());
        printf("myIp: %s\n",myIp.operator string().c_str());
        puts("");
    }

    addressInfo(const char* ifname){
        myMac = getMyMac(ifname);
        myIp = getMyIp(ifname);
    };
};

Mac getMacFromIP(pcap_t* handle, const addressInfo &myAddressInfo, const char* ipAddr);

//main function for arp-spoofing, packet relay, and re-infection
void spoofARP(pcap_t* handle, const addressInfo &myAddressInfo);

//infect target's ARP table
void infectArp(pcap_t* handle, const addressInfo &myAddressInfo);
//recover target's ARP table at program termination
void recoverArp(pcap_t* handle, const addressInfo &myAddressInfo);

//send fake arp reply(targetIP - myMac)to senderIP
void sendFakeARP(pcap_t* handle, const addressInfo &myAddressInfo, const char* senderIp, const char*  targetIp);
//send normal arp reply(targetIP - targetMac)to senderIP
void sendNormalARP(pcap_t* handle, const addressInfo &myAddressInfo, const char*  senderIp, const char*  targetIp);