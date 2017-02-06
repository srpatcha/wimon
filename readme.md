# Wimon

Wimon was created to take strength measures of neighbouring wifi devices on a determined channel and transmit them to a computer that would use all these information to locate such wifi devices ([Wi-Fi positioning system](https://en.wikipedia.org/wiki/Wi-Fi_positioning_system)).

### Requeriments

You need to install libpcap.

```
sudo apt-get update && sudo apt-get install libpcap-dev
```

#### Compile with:

		gcc -Wall -o wimon wimon.c radiotap.c -lpcap
	
or
	
		make wimon

or
		make all
		

#### Debug leaks with:

	gcc -Wall -g -o wimon wimon.c radiotap.c -lpcap
	valgrind --tool=memcheck --leak-check=yes wimon

or

	make debug

#### First of all, put your card in Monitor mode:

	Cisco Aironet	Echo "mode: y" > '/proc/driver/aironet/<device>/Config'
	HostAP			iwconfig <device> mode monitor
	Orinoco 		(patched)	iwpriv <device> monitor 1 <channel>
	Madwifi			iwconfig <device> mode monitor
	Wlan-ng			wlanctl-ng <device> lnxreq_wlansniff channel=<channel> enable=true
	Radiotap		ifconfig <device> monitor up
	
**The easiest way** to configure your wireless device into monitor mode is to use the tool `airmon-ng` provided on the [aricrack-ng suite](https://www.aircrack-ng.org/). It's easy: download, untar, make, make install and enjoy. After that you should write something like this:

```
sudo airmon-ng start wlan0
```

**IMPORTANT:**

 Take into account that if you want to listen to an specific channel you should configure your wireless adapter by using iwconfig too:

	iwconfig wlan0 mode monitor channel 6
	
or

	sudo airmon-ng start wlan0 6


#### After this, you can start using wimon

	./wimon -i eth1

or

	./wimon -i eth1 -c

or

	./wimon -i eth1 -u 192.168.1.1 -p 80

or

	./wimon -h


# Get IP info (gip)

**gip** is a simple program that tries to figure out the IP of the ethernet interface in which you are connected.

It just listen to the packets that arrives to your network card, and extract its MAC and IP. Another (more effective) way could be to extract the MAC header and send malformed packets to the source MAC address in order to trigger a response.

I did this after a night trying to remember what was the forgotten IP address of a router interface that I had been configuring, but I recommend to use wireshark to obtain more information about the device you're trying to connect to.

#### Compile with:

	gcc -Wall -o gip gip.c radiotap.c -lpcap

or
	
		make gip

or
		make all
		
#### Usage

	./gip -i eth1

or

	./gip -h

or, if you want a continuous stream of IP addresses and macs received by your interface

	./gip -c -i eth1
	
#### References:


[pcap homepage](http://www.tcpdump.org/pcap.html)
	
[libpcap and 802.11 Wireless Networks](http://books.gigatux.nl/mirror/networksecuritytools/0596007949/networkst-CHP-10-SECT-3.html)
	
[libpcap tutorial](http://homes.di.unimi.it/~gfp/SiRe/2002-03/progetti/libpcap-tutorial.html)
	
[Aprendiendo a programar con pcap](http://www.e-ghost.deusto.es/docs/2005/conferencias/pcap.pdf)
	
[Packet Analysis](http://yuba.stanford.edu/~casado/pcap/section4.html)
	
[Getting Started with libpcap](http://books.gigatux.nl/mirror/networksecuritytools/0596007949/networkst-CHP-10-SECT-2.html)
	
[Radiotap git](http://git.sipsolutions.net/?p=radiotap.git;a=tree;h=refs/heads/master;hb=refs/heads/master)
