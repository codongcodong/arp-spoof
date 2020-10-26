send-arp
=====

syntax : send-arp \<interface\> \<sender ip\> \<target ip\> \[\<sender ip 2\> \<target ip 2\> ...\]  
sample : send-arp wlan0 192.168.10.2 192.168.10.1

## Example
$ sudo ./send-arp eth0 192.168.0.3 192.168.0.1 192.168.0.6 192.168.0.1  

myMac: AA:AA:AA:AA:AA:AA  
myIp: 192.168.0.5  
  
Sending fake ARP response to sender ip 1: 192.168.0.3  
sender Ip: 192.168.0.3  
sender Mac: BB:BB:BB:BB:BB:BB  
  
target Ip: 192.168.0.1  
target Mac: DD:DD:DD:DD:DD:DD  
  
Sending fake ARP response to sender ip 2: 192.168.0.6  
sender Ip: 192.168.0.6  
sender Mac: CC:CC:CC:CC:CC:CC  
  
taeget Ip: 192.168.0.1  
target Mac: DD:DD:DD:DD:DD:DD  

  
