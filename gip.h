/*
Copyright 2015 Sergio Maeso Jiménez [massesos_at_gmail.com]

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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <pcap.h>
#include <signal.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>

#include <errno.h>
#include <sys/socket.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <syslog.h>
#include <string.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <net/if.h>


// Terminal colors
#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

/* Tamaño en bytes de las direcciones MAC (48 bits == 6 bytes) */
#define MAC_ADDR_SIZE 6
/* Longitud en bytes de una cadena de texto que representa una dirección MAC */
#define MAC_STR_LENGTH 18
/* Maximum Transmission Unit (MTU) de la tramas Ethernet. */
#define ETH_MTU 1500

/*Tamaño MTU en Ipv4== ETH_MTU-IPv4_HDR =1500-20=1480*/
#define IPv4_MTU 1480
/*Para rellenar el tipo de direccion software (proto_type) del paquete ARP*/
# define IPv4_ETH_TYPE 0x0800

/* Tamaño de una IPv4 (32 bits == 4 bytes). */
#define IPv4_ADDR_SIZE 4
/* Longitud en bytes de una cadena de texto que representa una dirección IP */
#define IPv4_STR_MAX_LENGTH 16

/* Definición del tipo para almacenar direcciones MAC */
typedef unsigned char mac_addr_t [MAC_ADDR_SIZE];
typedef char mac_str_t [MAC_STR_LENGTH];


/* Definición del tipo para almacenar direcciones IP */
typedef unsigned char ipv4_addr_t [IPv4_ADDR_SIZE];
typedef char ipv4_str_t [IPv4_STR_MAX_LENGTH];
/*Estructura de un paquete ipv4*/
typedef struct ipv4_packet {
	uint8_t version_ihl; //version+ihl= 8bits
	uint8_t type;
	uint16_t length;
	uint16_t id;
	uint16_t flags_offset; //flags+offset= 16 bits
	uint8_t ttl;
	uint8_t proto;         //protocol
	uint16_t checksum;
	ipv4_addr_t ip_addr_src;
	ipv4_addr_t ip_addr_dst;
	unsigned char ip_payload[IPv4_MTU];
} ipv4_pkt_t;

typedef struct eth_frame {
  mac_addr_t dest_addr; /* Dirección MAC destino*/
  mac_addr_t src_addr;  /* Dirección MAC origen */
  uint16_t type;        /* Campo 'Tipo'.
                           Identificador de la capa de red superior */
  unsigned char payload[ETH_MTU]; /* Campo 'payload'.
                                          Datos de la capa superior */

  /* NOTA: El campo "Frame Checksum" (FCS) no está incluido en la estructura
     porque lo añade automáticamente la tarjeta de red. */
} eth_frame_t;

void process_packet (u_char * args, const struct pcap_pkthdr *header,const u_char * packet);
void print_help();
void mac_addr_str ( mac_addr_t addr, char str[] );
int mac_str_addr ( char* str, mac_addr_t addr );
void ctrl_c ();
void getMyMac(mac_addr_t my_mac);
void ipv4_addr_str ( ipv4_addr_t addr, char* str );
int ipv4_str_addr ( char* str, ipv4_addr_t addr );
