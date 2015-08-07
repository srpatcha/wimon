# Wimon

Wimon was created to take strength measures of neighbouring wifi devices on a determined channel and transmit them to a computer that would use all these information to locate such wifi devices ([Wi-Fi positioning system](https://en.wikipedia.org/wiki/Wi-Fi_positioning_system)).

#### Compile with:

	gcc -Wall -o wimon wimon.c radiotap.c -lpcap

#### Debug leaks with:

	gcc -Wall -g -o wimon wimon.c radiotap.c -lpcap
	valgrind --tool=memcheck --leak-check=yes wimon

#### First of all, put your card in Monitor mode:

	Cisco Aironet	Echo "mode: y" > '/proc/driver/aironet/<device>/Config'
	HostAP			iwconfig <device> mode monitor
	Orinoco 		(patched)	iwpriv <device> monitor 1 <channel>
	Madwifi			iwconfig <device> mode monitor
	Wlan-ng			wlanctl-ng <device> lnxreq_wlansniff channel=<channel> enable=true
	Radiotap		ifconfig <device> monitor up

**IMPORTANT:**

 Take into account that if you want to listen to an specific channel you should configure your wireless adapter by using iwconfig too:

	iwconfig wlan0 mode monitor channel 6


#### After this, you can start using wimon

	./wimon -i eth1

or

	./wimon -i eth1 -c

or

	./wimon -i eth1 -u 192.168.1.1 -p 80

or

	./wimon -h


#### References:


[pcap homepage](http://www.tcpdump.org/pcap.html)
	
[libpcap and 802.11 Wireless Networks](http://books.gigatux.nl/mirror/networksecuritytools/0596007949/networkst-CHP-10-SECT-3.html)
	
[libpcap tutorial](http://homes.di.unimi.it/~gfp/SiRe/2002-03/progetti/libpcap-tutorial.html)
	
[Aprendiendo a programar con pcap](http://www.e-ghost.deusto.es/docs/2005/conferencias/pcap.pdf)
	
[Packet Analysis](http://yuba.stanford.edu/~casado/pcap/section4.html)
	
[Getting Started with libpcap](http://books.gigatux.nl/mirror/networksecuritytools/0596007949/networkst-CHP-10-SECT-2.html)
	
[Radiotap git](http://git.sipsolutions.net/?p=radiotap.git;a=tree;h=refs/heads/master;hb=refs/heads/master)
