LDLIBS=-lpcap

all: arp-spoof

arp-spoof: main.o arpspoof.o arphdr.o ethhdr.o ip.o mac.o 
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

main.o: main.cpp arpspoof.h
	g++ -Wall -c -o main.o main.cpp 

arpspoof.o: arpspoof.cpp arpspoof.h
	g++ -Wall -c -o arpspoof.o arpspoof.cpp 

clean:
	rm -f arp-spoof *.o
