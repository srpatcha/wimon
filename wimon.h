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



#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <pcap.h>
#include <signal.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <stdint.h>
#include <errno.h>
#include <sys/socket.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <syslog.h>
#include <string.h>


// Radiotap parser
#include "platform.h"
#include "radiotap.h"
#include "radiotap_iter.h"

// Terminal colors
#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

/* uDefining our header sizes */
#define ETH_HEADER_SIZE 14
#define AVS_HEADER_SIZE 64                 /* AVS capture header size */
#define RADIOTAP_HEADER_SIZE 8
#define DATA_80211_FRAME_SIZE 24           /* header for 802.11 data packet */
#define LLC_HEADER_SIZE 8                  /* LLC frame for encapsulation */

/* Defining the types of header the program can distinguish */
#define OTHER_TYPE 0
#define AVS_TYPE 1
#define RADIOTAP_TYPE 2
#define PRISM_TYPE 3

#define NETWORK_OUTPUT 1
#define TERMINAL_OUTPUT 0

#define TIMESTAMP_LEN       10

typedef uint64_t uint64;
typedef uint32_t uint32;
typedef uint32_t int32;

struct prism_value
{
 uint32 did; // This has a different ID for each parameter
 u_int16_t status; // 0 = set;  1 = not set (yes - not what you expected)
 u_int16_t len; // length of the data (u32) used 0-4
 uint32 data; // The data value
} __attribute__ ((__packed__));


struct PRISM_header
{
 uint32 msgcode;             // = PRISM_MSGCODE
 uint32 msglen;     // The length of the entire header - usually 144 bytes = 0x90
 char devname[16];       // The name of the device that captured this packet
 struct prism_value hosttime;  // This is measured in jiffies - I think
 struct prism_value mactime;   // This is a truncated microsecond timer,
                                  // we get the lower 32 bits of a 64 bit value
 struct prism_value channel;
 struct prism_value rssi;
 struct prism_value sq;
 struct prism_value signal;
 struct prism_value noise;
 struct prism_value rate;
 struct prism_value istx;
 struct prism_value frmlen;
 char   dot_11_header[];
} __attribute__ ((__packed__));

struct AVS_header
	{
	  uint32 version;
	  uint32 length;
	  uint64 mactime;
	  uint64 hosttime;
	  uint32 phytype;
	  uint32 channel;
	  uint32 datarate;
	  uint32 antenna;
	  uint32 priority;
	  uint32 ssi_type;
	  int32 ssi_signal;
	  int32 ssi_noise;
	  uint32 preamble;
	  uint32 encoding;
	};

	/* SNAP LLC header format */
struct snap_header
{
  u_int8_t dsap;
  u_int8_t ssap;
  u_int8_t ctl;
  u_int16_t org;
  u_int8_t org2;
  u_int16_t ether_type;          /* ethernet type */
} __attribute__ ((__packed__));

struct ieee80211_beacon_header{
	u_int8_t type;
	u_int8_t flags;
	u_int16_t duration;
	u_int8_t mac_receiver[6];
	u_int8_t mac_transmitter[6];
	u_int8_t id_transmitter[6];
	u_int16_t seq_number;

} __attribute__((__packed__));

static const struct radiotap_align_size align_size_000000_00[] = {
		[0] = { .align = 1, .size = 4, },
		[52] = { .align = 1, .size = 4, },
	};

static const struct ieee80211_radiotap_namespace vns_array[] = {
		{
			.oui = 0x000000,
			.subns = 0,
			.n_bits = sizeof(align_size_000000_00),
			.align_size = align_size_000000_00,
		},
	};

static const struct ieee80211_radiotap_vendor_namespaces vns = {
		.ns = vns_array,
		.n_ns = sizeof(vns_array)/sizeof(vns_array[0]),
	};


/* Funciton Definitions */

void print_mem(void const *vp, size_t n);
void print_mac(char *mac_addr);
void ctrl_c ();
void process_packet (u_char * args, const struct pcap_pkthdr *header,const u_char * packet);
void print_help();

int get_sock (char * addr, int port);
void daemonize (char *prog_name);
int getStrength(struct ieee80211_radiotap_header *radiotap_header, u_int16_t size);
void showRadiotapInfo(struct ieee80211_radiotap_header *radiotap_header, u_int16_t size);
