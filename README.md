arp-spoof
=====

syntax : arp-spoof \<interface\> \<sender ip\> \<target ip\> \[\<sender ip 2\> \<target ip 2\> ...\]  
sample : arp-spoof wlan0 192.168.10.2 192.168.10.1

## Features
- Re-infection in every 5-second time interval  
- ARP table recovery at program termination (press Ctrl+C to exit) 

## Example
$ sudo ./arp-spoof eth0 192.168.0.2 192.168.0.1 192.168.0.1 192.168.0.2 192.168.0.4 192.168.0.1 192.168.0.1 192.168.0.4 

myMac: AA:AA:AA:AA:AA:AA  
myIp: 192.168.0.9  
   
Targets  
Sender0 - Ip: 192.168.0.2, Mac: BB:BB:BB:BB:BB:BB  
Target0 - Ip: 192.168.0.1, Mac: DD:DD:DD:DD:DD:DD   
  
Sender1 - Ip: 192.168.0.1, Mac: DD:DD:DD:DD:DD:DD   
Target1 - Ip: 192.168.0.2, Mac: BB:BB:BB:BB:BB:BB   
  
Sender2 - Ip: 192.168.0.4, Mac: CC:CC:CC:CC:CC:CC   
Target2 - Ip: 192.168.0.1, Mac: DD:DD:DD:DD:DD:DD
  
Sender3 - Ip: 192.168.0.1, Mac: DD:DD:DD:DD:DD:DD  
Target3 - Ip: 192.168.0.4, Mac: CC:CC:CC:CC:CC:CC 

Relaying 98 bytes packet: sender3 - 192.168.0.1 => target3 - 192.168.0.4  
Relaying 98 bytes packet: sender0 - 192.168.0.2 => target0 - 192.168.0.1  
Relaying 98 bytes packet: sender0 - 192.168.0.2 => target0 - 192.168.0.1  
Relaying 98 bytes packet: sender0 - 192.168.0.2 => target0 - 192.168.0.1  
Relaying 98 bytes packet: sender2 - 192.168.0.4 => target2 - 192.168.0.1  
Reinfecting Targets  
Relaying 98 bytes packet: sender0 - 192.168.0.2 => target0 - 192.168.0.1  
Relaying 98 bytes packet: sender0 - 192.168.0.2 => target0 - 192.168.0.1  
Relaying 98 bytes packet: sender1 - 192.168.0.1 => target1 - 192.168.0.2   

^CRecovering Target ARP table   
Terminating Program  
