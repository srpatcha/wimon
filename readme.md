##### Compile with:

	gcc -Wall -o wimon wimon.c radiotap.c -lpcap

#### Debug leaks with:

	gcc -Wall -g -o wimon wimon.c radiotap.c -lpcap
	valgrind --tool=memcheck --leak-check=yes wimon

##### First of all, put your card in Monitor mode:

	Cisco Aironet	Echo "mode: y" > '/proc/driver/aironet/<device>/Config'
	HostAP			iwconfig <device> mode monitor
	Orinoco 		(patched)	iwpriv <device> monitor 1 <channel>
	Madwifi			iwconfig <device> mode monitor
	Wlan-ng			wlanctl-ng <device> lnxreq_wlansniff channel=<channel> enable=true
	Radiotap		ifconfig <device> monitor up

**IMPORTANT:**

> Take into account that if you want to listen to an specific channel you should
> configure your wireless adapter by using iwconfig too.

##### Then you start Wimon

	./wimon -i eth1

or

	./wimon -i eth1 -c

or

	./wimon -i eth1 -u 192.168.1.1 -p 80

or

	./wimon -h


References:

	[](http://www.tcpdump.org/pcap.html)
	[](http://books.gigatux.nl/mirror/networksecuritytools/0596007949/networkst-CHP-10-SECT-3.html)
	[](http://homes.di.unimi.it/~gfp/SiRe/2002-03/progetti/libpcap-tutorial.html)
	[](http://www.e-ghost.deusto.es/docs/2005/conferencias/pcap.pdf)
	[](http://yuba.stanford.edu/~casado/pcap/section4.html)
	[](http://books.gigatux.nl/mirror/networksecuritytools/0596007949/networkst-CHP-10-SECT-2.html)
	[](http://git.sipsolutions.net/?p=radiotap.git;a=tree;h=refs/heads/master;hb=refs/heads/master)
