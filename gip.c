#include "gip.h"

/*

Copyright 2015 Sergio Maeso Jiménez [sergio.maeso@imdea.org]

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

char errbuf[PCAP_ERRBUF_SIZE];
pcap_t *handle;
char *dev; // Interface to analize
int r;      /* generic return value, we use it in the radiotap iterator*/
mac_addr_t my_mac;
unsigned char infinite_mode = 0;

int main(int argc, char *argv[]){

	// Parsing the terminal arguments

	int opt;
	while ((opt = getopt(argc, argv, "i:hc")) != -1) {
	switch(opt) {
		case 'i':
			dev = optarg;
			break;
		case 'h':
				print_help();
				break;
		case 'c':
			infinite_mode = 1;
			break;
		}
	}

	/* setup signal handler so Control-C will gracefully exit */
	signal (SIGINT, ctrl_c);

	if (dev == NULL){
		printf("Please insert a Interface\n");
		print_help();
	}

	getMyMac(my_mac);
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == NULL) {
		 fprintf(stderr, "Couldn't open device %s: %s\n", dev,errbuf);
		 return -2;
	}


	if (pcap_set_datalink (handle, DLT_EN10MB) == -1)
    	{
      		pcap_perror (handle, "Error on pcap_set_datalink: ");
      		printf("Did you check that the interface %s is in Monitor Mode?\n",dev);
      		exit (1);
    	}


	if ((r = pcap_loop (handle, -1, process_packet, NULL)) < 0){
		if (r == -1){    /* pcap error */
			fprintf (stderr, "%s\n", pcap_geterr (handle));
			return(-1);
		}
	}

	  /* close our devices */
  	pcap_close (handle);
	return 0;
}

void ctrl_c ( ){
  pcap_breakloop (handle);  /* tell pcap_loop or pcap_dispatch to stop capturing */
  pcap_close(handle);
  exit (0);
}

/*
*
*		Process the packet received by libpcap
*/
void process_packet (u_char * args, const struct pcap_pkthdr *header,const u_char * packet){

	//time_t nowtime = time(NULL);

	eth_frame_t *ethernet_frame;
	ethernet_frame = ( eth_frame_t *) (packet);
	mac_str_t mac_string;
	mac_addr_str ( ethernet_frame->src_addr, mac_string );
	if(memcmp(my_mac,ethernet_frame->src_addr,MAC_ADDR_SIZE)!=0){
		if(ntohs(ethernet_frame->type)==IPv4_ETH_TYPE){
			ipv4_pkt_t *ip_packet;
			ip_packet = ( ipv4_pkt_t *) (ethernet_frame->payload);
			ipv4_str_t ip_string;
			ipv4_addr_str ( ip_packet->ip_addr_dst, ip_string );
			if(infinite_mode){
				printf("%s\t\t%s\n",ip_string,mac_string);
			}
			else{
				printf("\tMAC:\t%s\n",mac_string);
				printf("\tIP:\t%s\n",ip_string);
				ctrl_c();
			}

		}
	}

}
/*
*		Print the help when you ask for it or you screw up
*/
void print_help(){
	printf("\n gip - Get IP info: Capture packets to find out the configuration of the remote interface\n");
	printf("\n OPTIONS:\n");
	printf("\t -h \tPrint this help\n");
	printf("\t -i [IF]\tSpecify an interface to listen to\n");
	printf("\t -c\t The program does not stop capturing packets");
	exit(1);
}

/* void mac_addr_str ( mac_addr_t addr, char str[] );
 *
 * DESCRIPCIÓN:
 *   Esta función genera una cadena de texto que representa la dirección MAC
 *   indicada.
 *
 * PARÁMETROS:
 *   'addr': La dirección MAC que se quiere representar textualente.
 *    'str': Memoria donde se desea almacenar la cadena de texto generada.
 *           Deben reservarse al menos 'MAC_STR_LENGTH' bytes.
 */
void mac_addr_str ( mac_addr_t addr, char str[] )
{
  if (str != NULL) {
    sprintf(str, "%02X:%02X:%02X:%02X:%02X:%02X",
            addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
  }
}

/* int mac_str_addr ( char* str, mac_addr_t addr );
 *
 * DESCRIPCIÓN:
 *   Esta función analiza una cadena de texto en busca de una dirección MAC.
 *
 * PARÁMETROS:
 *    'str': La cadena de texto que se desea procesar.
 *   'addr': Memoria donde se almacena la dirección MAC encontrada.
 *
 * VALOR DEVUELTO:
 *   Se devuelve 0 si la cadena de texto representaba una dirección MAC.
 *
 * ERRORES:
 *   La función devuelve -1 si la cadena de texto no representaba una
 *   dirección MAC.
 */
int mac_str_addr ( char* str, mac_addr_t addr )
{
  int err = -1;

  if (str != NULL) {
    unsigned int addr_int[MAC_ADDR_SIZE];
    int len = sscanf(str, "%02X:%02X:%02X:%02X:%02X:%02X",
                     &addr_int[0], &addr_int[1], &addr_int[2],
                     &addr_int[3], &addr_int[4], &addr_int[5]);

    if (len == MAC_ADDR_SIZE) {
      int i;
      for (i=0; i<MAC_ADDR_SIZE; i++) {
        addr[i] = (unsigned char) addr_int[i];
      }
      err = 0;
    }
  }

  return err;
}

void getMyMac(mac_addr_t my_mac){

    struct ifreq buffer;
    int s = socket(PF_INET, SOCK_DGRAM, 0);
    memset(&buffer, 0x00, sizeof(buffer));
    strcpy(buffer.ifr_name, dev);
    ioctl(s, SIOCGIFHWADDR, &buffer);
    close(s);
	memcpy(my_mac,buffer.ifr_hwaddr.sa_data,MAC_ADDR_SIZE);


}


/* void ipv4_addr_str ( ipv4_addr_t addr, char* str );
 *
 * DESCRIPCIÓN:
 *   Esta función genera una cadena de texto que representa la dirección IPv4
 *   indicada.
 *
 * PARÁMETROS:
 *   'addr': La dirección IP que se quiere representar textualente.
 *    'str': Memoria donde se desea almacenar la cadena de texto generada.
 *           Deben reservarse al menos 'IPv4_STR_MAX_LENGTH' bytes.
 */
void ipv4_addr_str ( ipv4_addr_t addr, char* str )
{
  if (str != NULL) {
    sprintf(str, "%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3]);
  }
}


/* int ipv4_str_addr ( char* str, ipv4_addr_t addr );
 *
 * DESCRIPCIÓN:
 *   Esta función analiza una cadena de texto en busca de una dirección IPv4.
 *
 * PARÁMETROS:
 *    'str': La cadena de texto que se desea procesar.
 *   'addr': Memoria donde se almacena la dirección IPv4 encontrada.
 *
 * VALOR DEVUELTO:
 *   Se devuelve 0 si la cadena de texto representaba una dirección IPv4.
 *
 * ERRORES:
 *   La función devuelve -1 si la cadena de texto no representaba una
 *   dirección IPv4.
 */
int ipv4_str_addr ( char* str, ipv4_addr_t addr )
{
  int err = -1;

  if (str != NULL) {
    unsigned int addr_int[IPv4_ADDR_SIZE];
    int len = sscanf(str, "%d.%d.%d.%d",
                     &addr_int[0], &addr_int[1],
                     &addr_int[2], &addr_int[3]);

    if (len == IPv4_ADDR_SIZE) {
      int i;
      for (i=0; i<IPv4_ADDR_SIZE; i++) {
        addr[i] = (unsigned char) addr_int[i];
      }

      err = 0;
    }
  }

  return err;
}
