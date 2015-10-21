
// Wimon, A wifi scanner designed to run on arm boards to be used as probes in a location system.

/*
Copyright 2015 Sergio Maeso Jiménez & IMDEA Networks [sergio.maeso@imdea.org]

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

*/

#include "radiotap_iter.h"
#include "platform.h"
#include "radiotap.h"
#include "wimon.h"

char errbuf[PCAP_ERRBUF_SIZE];
pcap_t *handle;

int r;      /* generic return value, we use it in the radiotap iterator*/

char *dev;	// Interface to listen to
int port = 0;
char *ip;
char *mac;

unsigned int output_opt = TERMINAL_OUTPUT;	// show info on the screen or send it over the network
unsigned int daemon_opt = 0;								// run in daemon mode or not
unsigned int color_opt = 0;									// Coloured output option
unsigned int verbose_opt = 0;

int type = 0;		// Packet type , PRISM, AVS or Radiotap
int wired = 0;		// It is wired or not?

int srvr_sock;		// The socket we use to send the information.

int main(int argc, char *argv[]){

	// Parsing the terminal arguments

	int opt;
	while ((opt = getopt(argc, argv, "m:u:i:p:hdcv")) != -1) {
		switch(opt) {
			case 'u':
				ip = optarg;
				output_opt = NETWORK_OUTPUT;
				break;
			case 'i':
				dev = optarg;
				break;
			case 'p':
				port = atoi(optarg);
				output_opt = NETWORK_OUTPUT;
				break;
			case 'h':
				print_help();
				break;
			case 'd':
				daemon_opt = 1;
				break;
			case 'm':
				mac = optarg;
				output_opt = NETWORK_OUTPUT;
				break;
			case 'c':
				color_opt = 1;
				break;
			case 'v':
				verbose_opt = 1;
				break;
		}
	}

	if(output_opt == NETWORK_OUTPUT) {
		if(ip == NULL){
			printf("You must specify an IP Address\n");
			print_help();
		}
		if(port == 0){
			printf("You must specify a Port\n");
			print_help();
		}

	}

	if (dev == NULL) {
			fprintf(stderr, "No device inserted or device %s not valid\n",dev);
			print_help();
	}

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == NULL) {
		 fprintf(stderr, "Couldn't open device %s: %s\n", dev,errbuf);
		 return(2);
	}

	 if(output_opt == NETWORK_OUTPUT){
		printf("Connecting to %s:%d\n", ip, port);
		if((srvr_sock = get_sock(ip, port))==-1){
			printf("Unable to connect to Receiver at %s:%d\n", ip, port);
			exit(1);
		}
		else{
			printf("Connected to %s:%d\n", ip, port);
		}
	 }



	/* setup signal handler so Control-C will gracefully exit */
	signal (SIGINT, ctrl_c);

	if (pcap_set_datalink (handle, DLT_IEEE802_11_RADIO) == -1)
    {
      pcap_perror (handle, "Error on pcap_set_datalink: ");
      printf("Did you check that the interface %s is in Monitor Mode?\n",dev);
      exit (1);
    }


	if (pcap_datalink (handle) == DLT_EN10MB){
		wired = 1;     /* ethernet link */
		printf("This is a wired connection\n");
		exit(1);

	}
	else {
		if (pcap_datalink (handle) == DLT_IEEE802_11_RADIO_AVS){
			wired = 0;  /* wireless */
			type = AVS_TYPE;
		}
		else if(pcap_datalink (handle) == DLT_IEEE802_11_RADIO){
			wired = 0;
			type = RADIOTAP_TYPE;
		}
		else if(pcap_datalink (handle) == DLT_PRISM_HEADER){
			wired = 0;
			type = PRISM_TYPE;
		}
		else {
			fprintf (stderr, "I don't support this interface type: %d\n",pcap_datalink (handle));
			exit (1);
		}
	}

	if ((r = pcap_loop (handle, -1, process_packet, NULL)) < 0){
		if (r == -1){    /* pcap error */
			fprintf (stderr, "%s", pcap_geterr (handle));
			return(1);
		}
	}

	  /* close our devices */
  pcap_close (handle);
	close(srvr_sock);
	return 0;
}


/*
*	Prints a mac address in XX:XX:XX:XX:XX:XX format
*/
void print_mac(char *mac_addr){
	int i = 0;
	for(i=0; i<6;i++){
		if(i==0) {
			//printf("%02X",mac_addr[i]);
			printf("%02X",mac_addr[i] & 0xff);
		}
		else{
	     printf(":%02X",mac_addr[i] & 0xff);
		//printf(":%02x",mac_addr[i]);
		}
	}
}

/*
*	Prints in hexadecimal the content of the variable you give it
*/
void print_mem(void const *vp, size_t n){
	int i=0;
    unsigned char const *p = vp;
    for (i=0; i<n; i++)
        printf("%02x", p[i]);
}
/*
*		gracefully handle a Control C
*/
void ctrl_c ( ){
  printf ("\nExiting\n");
  pcap_breakloop (handle);  /* tell pcap_loop or pcap_dispatch to stop capturing */
  pcap_close(handle);
	close(srvr_sock);
  exit (0);
}
/*
	The radiotap header changes in depending which hardware are we using.
	Actually we take as strength the DBM_ANTSIGNAL field but maybe your
	Wireless card just give you the DB_ANTSIGNAL so you should change the
	getStrength method a little bit.

	This method gives you all the values your card is giving you so you can
	choose what fits best for you.
*/
/*
	 * IEEE80211_RADIOTAP_TSFT              __le64       microseconds
	 * IEEE80211_RADIOTAP_CHANNEL           2 x uint16_t   MHz, bitmap
	 * IEEE80211_RADIOTAP_FHSS              uint16_t       see below
	 * IEEE80211_RADIOTAP_RATE              u8           500kb/s
	 * IEEE80211_RADIOTAP_DBM_ANTSIGNAL     s8           decibels from
	 * IEEE80211_RADIOTAP_DBM_ANTNOISE      s8           decibels from
	 * IEEE80211_RADIOTAP_DB_ANTSIGNAL      u8           decibel (dB)
	 * IEEE80211_RADIOTAP_DB_ANTNOISE       u8           decibel (dB)
	 * IEEE80211_RADIOTAP_LOCK_QUALITY      uint16_t       unitless
	 * IEEE80211_RADIOTAP_TX_ATTENUATION    uint16_t       unitless
	 * IEEE80211_RADIOTAP_DB_TX_ATTENUATION uint16_t       decibels (dB)
	 * IEEE80211_RADIOTAP_DBM_TX_POWER      s8           decibels from
	 * IEEE80211_RADIOTAP_FLAGS             u8           bitmap
	 * IEEE80211_RADIOTAP_ANTENNA           u8           antenna index
	 * IEEE80211_RADIOTAP_RX_FLAGS          uint16_t       bitmap
	 * IEEE80211_RADIOTAP_TX_FLAGS          uint16_t       bitmap
	 * IEEE80211_RADIOTAP_RTS_RETRIES       u8           data
	 * IEEE80211_RADIOTAP_DATA_RETRIES      u8           data
	 * IEEE80211_RADIOTAP_MCS	u8, u8, u8		unitless
	 * IEEE80211_RADIOTAP_AMPDU_STATUS	u32, u16, u8, u8	unitlesss
	 */

void showRadiotapInfo(struct ieee80211_radiotap_header *radiotap_header, u_int16_t size){
	printf("Total Size: %d\n",size);

	int err = 1;

	struct ieee80211_radiotap_iterator iterator;

	err = ieee80211_radiotap_iterator_init(&iterator, radiotap_header, size, &vns);
	if (err) {
		printf("malformed radiotap header (init returns %d)\n", err);
		return;
	}

	while (!(err = ieee80211_radiotap_iterator_next(&iterator))) {
		switch(iterator.this_arg_index){
			case IEEE80211_RADIOTAP_TSFT:
				printf("TSFT: %d\n",*iterator.this_arg);
				break;
			case IEEE80211_RADIOTAP_FLAGS:
				printf("FLAGS: %x\n",*iterator.this_arg);
				break;
			case IEEE80211_RADIOTAP_RATE:
				printf("RATE: %d\n",*iterator.this_arg);
				break;
			case IEEE80211_RADIOTAP_CHANNEL:
				printf("CHANNEL: %d\n",*iterator.this_arg);
				break;
			case IEEE80211_RADIOTAP_FHSS:
				printf("FHSS: %d\n",*iterator.this_arg);
				break;
			case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
				printf("DBM_ANTSIGNAL: %d\n",*iterator.this_arg);
				break;
			case IEEE80211_RADIOTAP_DBM_ANTNOISE:
				printf("DBM_ANTNOISE: %d\n",*iterator.this_arg);
				break;
			case IEEE80211_RADIOTAP_LOCK_QUALITY:
				printf("LOCK_QUALITY: %d\n",*iterator.this_arg);
				break;
			case IEEE80211_RADIOTAP_TX_ATTENUATION:
				printf("TX_ATTENUATION: %d\n",*iterator.this_arg);
				break;
			case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
				printf("DB_TX_ATTENUATION: %d\n",*iterator.this_arg);
				break;
			case IEEE80211_RADIOTAP_DBM_TX_POWER:
				printf("DBM_TX_POWER: %d\n",*iterator.this_arg);
				break;
			case IEEE80211_RADIOTAP_ANTENNA:
				printf("ANTENNA: %x\n",*iterator.this_arg);
				break;
			case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
				printf("DB_ANTSIGNAL: %d\n",*iterator.this_arg);
				break;
			case IEEE80211_RADIOTAP_DB_ANTNOISE:
				printf("DB_ANTNOISE: %d\n",*iterator.this_arg);
				break;
			case IEEE80211_RADIOTAP_RX_FLAGS:
				printf("RX_FLAGS: %x\n",*iterator.this_arg);
				break;
			case IEEE80211_RADIOTAP_TX_FLAGS:
				printf("TX_FLAGS: %x\n",*iterator.this_arg);
				break;
			case IEEE80211_RADIOTAP_RTS_RETRIES:
				printf("RTS_RETRIES: %d\n",*iterator.this_arg);
				break;
			case IEEE80211_RADIOTAP_DATA_RETRIES:
				printf("RETRIEST: %d\n",*iterator.this_arg);
				break;
			case IEEE80211_RADIOTAP_MCS:
				printf("MCS: %d\n",*iterator.this_arg);
				break;
			case IEEE80211_RADIOTAP_AMPDU_STATUS:
				printf("AMPDU_STATUS: %d\n",*iterator.this_arg);
				break;
		}
	}
}

/*
*		Returns the DBM signal that this antenna is receiveng
*/
int getStrength(struct ieee80211_radiotap_header *radiotap_header, u_int16_t size){

	int8_t pwr_dbm = -1;
	int8_t pwr_db = -1;
	
	int err = 1;

	struct ieee80211_radiotap_iterator iterator;

	err = ieee80211_radiotap_iterator_init(&iterator, radiotap_header, size, &vns);
	if (err) {
		printf("malformed radiotap header (init returns %d)\n", err);
		return 3;
	}

	while (!(err = ieee80211_radiotap_iterator_next(&iterator))) {
		switch(iterator.this_arg_index){
			case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
				pwr_dbm = *iterator.this_arg;
				break;
			case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
				pwr_db = *iterator.this_arg;
				break;
		}
	}
	if(pwr_dbm != -1){
		return pwr_dbm;
	}
	else{
		return pwr_db;
	}
}

/*
*		Process the packet received by libpcap
*/
void process_packet (u_char * args, const struct pcap_pkthdr *header,const u_char * packet){

	//struct ether_header *eth_header;  /* in ethernet.h included by if_eth.h */
	//struct snap_header *llc_header;   /* RFC 1042 encapsulation header */
	//struct ether_arp *arp_packet;     /* from if_eth.h */

	struct AVS_header *avs_header;
	struct PRISM_header *prism_header;

	struct ieee80211_radiotap_header *radiotap_header;

	struct ieee80211_beacon_header *beacon_header;

	// These are the parameters that we extract from the headers

	time_t nowtime = time(NULL);
	int8_t strength;
	char *mac_addr;

	char *buf;
	size_t sz;

    switch(type){
			case AVS_TYPE:
				avs_header = (struct AVS_header *) (packet);
				beacon_header = (struct ieee80211_beacon_header *) (packet + AVS_HEADER_SIZE);

				strength = avs_header->ssi_signal;
				mac_addr = (char *) beacon_header->mac_transmitter;

				break;

			case PRISM_TYPE:
				prism_header = (struct PRISM_header *) (packet);
				beacon_header = (struct ieee80211_beacon_header *) (packet + prism_header->msglen);

				strength = prism_header->rssi.data;
				mac_addr = (char *) beacon_header->mac_transmitter;

				break;

			case RADIOTAP_TYPE:
				radiotap_header = (struct ieee80211_radiotap_header *) (packet);
				beacon_header = (struct ieee80211_beacon_header *) (packet + radiotap_header->it_len);

				strength = getStrength(radiotap_header,header->len);
				mac_addr = (char *) beacon_header->mac_transmitter;
				//showRadiotapInfo(radiotap_header,header->len);
				break;
			}

	switch(output_opt){
		case TERMINAL_OUTPUT:
			if(color_opt){
				if(strength<-80){
					printf("%ju " ANSI_COLOR_RED "%d dBm " ANSI_COLOR_RESET "[",(uintmax_t)nowtime,strength);
				}
				else if(strength>-60){
					printf("%ju " ANSI_COLOR_GREEN "%d dBm " ANSI_COLOR_RESET "[",(uintmax_t)nowtime,strength);
				}
				else{
					printf("%ju " ANSI_COLOR_YELLOW "%d dBm " ANSI_COLOR_RESET "[",(uintmax_t)nowtime,strength);
				}
			}
			else{
				printf("%ju %d dBm [",(uintmax_t)nowtime,strength);
			}
			print_mac(mac_addr);
			printf("]\n");

			if(verbose_opt==1){
				showRadiotapInfo(radiotap_header,header->len);
				printf("\n");
			}

			break;

		case NETWORK_OUTPUT:
			// Im against this implementation, I would like to send just the information in bytes:
			// MAC + TIME + RSSI + MAC = 6+4+1+6 = 17 bytes!

			// With the actual implementation we send evens spaces!

			sz = snprintf(NULL,0,"%s %ju %d %02X:%02X:%02X:%02X:%02X:%02X\n",mac,(uintmax_t)nowtime,strength,mac_addr[0] & 0xff,mac_addr[1] & 0xff,mac_addr[2] & 0xff,mac_addr[3] & 0xff,mac_addr[4] & 0xff,mac_addr[5] & 0xff);
			buf = (char *)malloc(sz +1);
			snprintf(buf,sz+1,"%s %ju %d %02X:%02X:%02X:%02X:%02X:%02X\n",mac,(uintmax_t)nowtime,strength,mac_addr[0] & 0xff,mac_addr[1] & 0xff,mac_addr[2] & 0xff,mac_addr[3] & 0xff,mac_addr[4] & 0xff,mac_addr[5] & 0xff);

			if(send(srvr_sock, buf, sz , 0) == -1) {
					printf("Socket Error\n");
					exit(EXIT_FAILURE);
			}

			break;

	}
}
/*
*		Print the help when you ask for it or you screw up
*/
void print_help(){
	printf("\n WIMON: Wi-fi probe for localization services\n");
	printf("\n OPTIONS:\n");
	printf("\t -h \tPrint this help\n");
	printf("\t -i [IF]\tSpecify an interface to listen to\n");
	printf("\t -u [IP]\tSpecify an IP to send the data instead of stdout\n");
	printf("\t -p [PORT]\t specify the port you wnat to send the data\n");
	printf("\t -d \t Use this if you want to run in daemon mode\n");
	printf("\t -m [ID]\t If you want to add an identificator to the packet you are sending over the network\n");
	printf("\t -c \t if you want to add some colour to the console output.\n\n");
	printf("\t -v \t if you want see some more information (buggy).\n\n");
	printf("To send the output to stdout\n");
	printf("	wimon -i [IF] \n");
	printf("\nTo send the output to an ip address\n");
	printf("	wimon -i [IF] -u [IP] -p [PORT]\n");
	exit(1);
}
/*
*		Get a socket to initialize the connection
*/
int get_sock (char * addr, int port) {
	int sock;
	struct sockaddr_in srvr_addr;
	size_t addr_len;

	sock = socket(AF_INET, SOCK_STREAM, 0);

	addr_len = sizeof(srvr_addr);
	bzero(&srvr_addr, addr_len);

	srvr_addr.sin_family 		= AF_INET;
	srvr_addr.sin_addr.s_addr 	= inet_addr(addr);
	srvr_addr.sin_port 			= htons(port);

	if(connect(sock, (struct sockaddr *) &srvr_addr, addr_len)) {
          perror("Error ");
          return -1;
        }

	return sock;
}
/*
*		Make the process run as daemon.
*		This method is inherited from old kismet_Wrapper, I did not try it.
*/
void daemonize (char *prog_name) {
    pid_t pid, sid;

    // Work as a daemon
    pid = fork();

    // Parent process
    if(!pid) exit(EXIT_SUCCESS);

        // Fork failed
    if(pid < 0) {
        printf("Fork failed\n");
        exit(EXIT_FAILURE);
    }
    // Fork ok

    // Safe file permissions
    umask(0);

    // syslog all errors
    openlog(prog_name,LOG_NOWAIT|LOG_PID,LOG_USER);
    syslog(LOG_NOTICE, "Successfully started daemon\n");

    // Try to create our own process group
    sid = setsid();
    if (sid < 0) {
        syslog(LOG_ERR, "Could not create process group\n");
        exit(EXIT_FAILURE);
    }

    // Change the current working directory
    // (TODO: /tmp should be mounted as ramfs?)
    if ((chdir("/tmp/")) < 0) {
        syslog(LOG_ERR, "Could not change working directory to /\n");
        exit(EXIT_FAILURE);
    }

    // Close the standard file descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
}
