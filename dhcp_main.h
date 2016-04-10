




#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdlib.h>

#if defined(__linux__)
#include <linux/if_ether.h>
#include <linux/ip.h>
#endif 

#include <fcntl.h>



#define STATE_OK          0
#define STATE_WARNING     1
#define STATE_CRITICAL    2
#define STATE_UNKNOWN     -1

#define OK                0
#define ERROR             -1

#define FALSE             0
#define TRUE              1


/**** DHCP definitions ****/

#define MAX_DHCP_CHADDR_LENGTH           16
#define MAX_DHCP_SNAME_LENGTH            64
#define MAX_DHCP_FILE_LENGTH             128
#define MAX_DHCP_OPTIONS_LENGTH          312




#define BOOTREQUEST     1
#define BOOTREPLY       2


#define DHCP_INFINITE_TIME              0xFFFFFFFF

#define DHCP_BROADCAST_FLAG 32768

#define DHCP_SERVER_PORT   67
#define DHCP_CLIENT_PORT   68

#define ETHERNET_HARDWARE_ADDRESS            1     /* used in htype field of dhcp packet */
#define ETHERNET_HARDWARE_ADDRESS_LENGTH     6     /* length of Ethernet hardware addresses */
#define DHCP_MIN_LEN                         (28+16+64+128)  /* Length of packet excluding options */



typedef enum
{
  DHCPUNKNOWN  = 0,
  DHCPDISCOVER = 1,
  DHCPOFFER    = 2,
  DHCPREQUEST  = 3,
  DHCPDECLINE  = 4,
  DHCPACK      = 5,
  DHCPNACK     = 6,
  DHCPRELEASE  = 7

}dhcp_message_type_t;

typedef enum
{
  DHCP_OPTION_PAD_OPTION                 = 0,
  DHCP_OPTION_SUBNET_MASK                = 1,
  DHCP_OPTION_ROUTER_OPTION              = 3,
  DHCP_OPTION_TIME_SERVER_OPTION         = 4,
  DHCP_OPTION_DOMAIN_NAME_SERVER         = 6,
  DHCP_OPTION_HOST_NAME                  = 12,
  DHCP_OPTION_DOMAIN_NAME                = 15,
  
  DHCP_OPTION_INTERFACE_MTU              = 26,
  DHCP_OPTION_BROADCAST_ADDRESS          = 28,
  /* Network Information Server Domain */
  DHCP_OPTION_NIS_DOMAIN                 = 40,
  /* Network Information Server */
  DHCP_OPTION_NIS                         = 41,
  DHCP_OPTION_NTP_SERVER                  = 42,
  DHCP_OPTION_REQUESTED_IP_ADDRESS        = 50,
  DHCP_OPTION_IP_LEASE_TIME               = 51,
  DHCP_OPTION_OPTION_OVERLOAD             = 52,
  DHCP_OPTION_MESSAGE_TYPE                = 53,
  DHCP_OPTION_SERVER_IDENTIFIER           = 54,
  DHCP_OPTION_PARAMETER_REQUEST_LIST      = 55,
  DHCP_OPTION_MESSAGE                     = 56,
  DHCP_OPTION_MAXIMUM_DHCP_MESSAGE_SIZE   = 57,
  DHCP_OPTION_RENEWAL_TIME_T1             = 58,
  DHCP_OPTION_REBINDING_TIME_T2           = 59,
  DHCP_OPTION_CLASS_IDENTIFIER            = 60,
  DHCP_OPTION_CLIENT_IDENTIFIER           = 61,
  DHCP_OPTION_END                         = 255
}dhcp_option_type_t;


/**
 *
 * This unin is to define the client IP Address
 * Client IP address may be stored in octet and can be retrieved 
 * from int named ciaddr
 *
 * @Author: Mohd Naushad Ahmed
 * @E-mail: naushad.dln@gmail.com
 * @Dated:  24-Mar-2016
 */
typedef union
{
  int ciaddr;
  unsigned char octet[4];
}dhcp_client_addr_t;

typedef struct dhcp_client_pool
{
  dhcp_client_addr_t      offered_addr;          /* IP Address that is offered to Client */
  dhcp_client_addr_t      offered_net_mask;
  char                    chaddr[6];             /* Client MAC Address */
  unsigned int            xid;                   /* Client Transaction ID */
  unsigned int            lease_time;            /* lease time in seconds */
  unsigned int            renewal_time;          /* renewal time in seconds */
  unsigned int            rebinding_time;        /* rebinding time in seconds */
  struct dhcp_client_pool *next_client;	
}dhcp_client_pool_t;

typedef struct
{
  unsigned char  tag;
  unsigned char  length;
  unsigned char  value[50];
}dhcp_generic_option_t;

/*
 *  Refer to http://www.networksorcery.com/enp/rfc/rfc1533.txt
 *
 * @Author:
 */
/**
 *
 * DHCP Header Format
 * 
 * */
typedef struct
{
  unsigned char      op;                   /* packet type */
  unsigned char      htype;                /* type of hardware address for this machine (Ethernet, etc) */
  unsigned char      hlen;                 /* length of hardware address (of this machine) */
  unsigned char      hops;                 /* hops */
  unsigned int       xid;                  /* random transaction id number - chosen by this machine */
  unsigned short int secs;                 /* seconds used in timing */
  unsigned short int flags;                /* flags */
  unsigned int       ciaddr;               /* IP address of this machine (if we already have one) */
  unsigned int       yiaddr;               /* IP address of this machine (offered by the DHCP server) */
  unsigned int       siaddr;               /* IP address of DHCP server */
  unsigned int       giaddr;               /* IP address of DHCP relay */
  unsigned char      chaddr[MAX_DHCP_CHADDR_LENGTH];      /* hardware address of this machine */
  char               sname[MAX_DHCP_SNAME_LENGTH];        /* name of DHCP server */
  char               file[MAX_DHCP_FILE_LENGTH];          /* boot file name (used for diskless booting?) */
  char               options[MAX_DHCP_OPTIONS_LENGTH];    /* options */
}__attribute__((packed))dhcp_generic_packet_t;



/**
 *
 * This structure defines to hold the 
 * DHCP Server context data/variable.
 */
typedef struct
{
  int                fd;
  int                dhcp_dst_port;     /* UDP Destination Port for DHCP SERVER is 68 */
  int                dhcp_src_port;     /* UDP Source port for DHCP SERVER is 67 */
  char               interface_name[6]; /* Interface name could eth0, eth1 etc */
  fd_set             read_fd;
  fd_set             write_fd;
  fd_set             exception_fd;
  struct             timeval to;        /* Timeout of select system call */
  char               host_name[128];    /* DHCP Server Host Name (Optional) */
  struct sockaddr_in dhcp_server_addr;
  struct sockaddr_in dhcp_client_addr;
  struct ifreq       intf_name;
  char               *received_pkt;     /* This is used to hold the received Packet */
  size_t             received_pkt_len;  /* This holds the length of received Packet */
  char               *response_pkt;     /* This holds the response to be sent */
  size_t             response_pkt_len;  /* This is the response packet length */
  unsigned char      host_mac[6];       /* MAC Address of DHCP Server */
  dhcp_client_addr_t dns_ip_addr[2];
  dhcp_client_pool_t *ciaddr_free_pool;
  dhcp_client_pool_t *ciaddr_allocated_pool;

}dhcp_ctx_t;



/**
 * This is the data type of callback function which shall be
 * used to define the callback type.
 *
 * @param		Transaction Id which is received from DHCP client in DHCP DISCOVER
 *              Which is optional DHCP CLient may provide it or not. If it is provided
 *              by DHCP client then DHCP server shall use it.
 * @param		This is the DHCP client IP Address which is assigned in DHCP OFFER Message.
 * @param		This is the variable that hodls the context related information of DHCP as well as DHCP
 * 				Client.
 * @return	    The callback Function will return DHCP_SUCCESS or DHCP_FAILURE.
 */
typedef int (*dhcp_function_callback_type_t)( unsigned int txid, int dhcp_client_ip_address, dhcp_ctx_t *ctx );




typedef struct
{
  dhcp_message_type_t             dhcp_msg;
  dhcp_function_callback_type_t   dhcp_cb;
}dhcp_msg_to_callback_t;
/**
 * This is the callback which is invoked when preparing DHCPOFFER Message to DHCP CLIENT
 *
 * @param		Transaction Id which is received from DHCP client in DHCP DISCOVER
 *          Which is optional DHCP CLient may provide it or not. If it is provided
 *          bt DHCP client then DHCP server shall use it.
 * @param		This is the DHCP client IP Address which is assigned in DHCP OFFER Message.
 * @param		This is the variable that hodls the context related information of DHCP as well as DHCP
 * 					Client.
 * @return	The callback Function will return DHCP_SUCCESS or DHCP_FAILURE.
 */
int 
handle_dhcp_offer_callback
(
  unsigned int txid, 
	int dhcp_client_ip_address, 
	dhcp_ctx_t *ctx
);

/**
 * This is the callback which is invoked upon receipt of DHCPDISCOVER Message from DHCP CLIENT
 *
 * @param		Transaction Id which is received from DHCP client in DHCP DISCOVER
 *          Which is optional DHCP CLient may provide it or not. If it is provided
 *          bt DHCP client then DHCP server shall use it.
 * @param		This is the DHCP client IP Address which is assigned in DHCP OFFER Message.
 * @param		This is the variable that hodls the context related information of DHCP as well as DHCP
 * 					Client.
 * @return	The callback Function will return DHCP_SUCCESS or DHCP_FAILURE.
 */
int 
handle_dhcp_discover_callback
(
  unsigned int txid, 
	int dhcp_client_ip_address, 
	dhcp_ctx_t *ctx
);

/**
 * This is the callback/function which is invoked upon receipt of DHCPREQUEST from DHCP CLIENT. 
 *
 * @param		Transaction Id which is received from DHCP client in DHCP DISCOVER
 *          Which is optional DHCP CLient may provide it or not. If it is provided
 *          bt DHCP client then DHCP server shall use it.
 * @param		This is the DHCP client IP Address which is assigned in DHCP OFFER Message.
 * @param		This is the variable that hodls the context related information of DHCP as well as DHCP
 * 					Client.
 * @return	The callback Function will return DHCP_SUCCESS or DHCP_FAILURE.
 */
int 
handle_dhcp_request_callback
(
  unsigned int txid, 
	int dhcp_client_ip_address, 
	dhcp_ctx_t *ctx
);

/**
 * This is the callback which is used to reply DHCPACK to DHCP CLIENT.
 *
 * @param		Transaction Id which is received from DHCP client in DHCP DISCOVER
 *          Which is optional DHCP CLient may provide it or not. If it is provided
 *          bt DHCP client then DHCP server shall use it.
 * @param		This is the DHCP client IP Address which is assigned in DHCP OFFER Message.
 * @param		This is the variable that hodls the context related information of DHCP as well as DHCP
 * 					Client.
 * @return	The callback Function will return DHCP_SUCCESS or DHCP_FAILURE.
 */
int
dhcp_prepare_ack_message
(
 unsigned int txid,
 int dhcp_client_ip_address,
 dhcp_ctx_t *ctx
 );

/**
 * This is the callback which is invoked/called while sending DHCPNACK message to DHCP CLIENT.
 *
 * @param		Transaction Id which is received from DHCP client in DHCP DISCOVER
 *          Which is optional DHCP CLient may provide it or not. If it is provided
 *          bt DHCP client then DHCP server shall use it.
 * @param		This is the DHCP client IP Address which is assigned in DHCP OFFER Message.
 * @param		This is the variable that hodls the context related information of DHCP as well as DHCP
 * 					Client.
 * @return	The callback Function will return DHCP_SUCCESS or DHCP_FAILURE.
 */
int 
handle_dhcp_nack_callback
(
  unsigned int txid, 
	int dhcp_client_ip_address, 
	dhcp_ctx_t *ctx 
);

/**
 * This is the callback which is invoked upon receipt of DHCPDECLINE Message 
 *
 * @param		Transaction Id which is received from DHCP client in DHCP DISCOVER
 *          Which is optional DHCP CLient may provide it or not. If it is provided
 *          bt DHCP client then DHCP server shall use it.
 * @param		This is the DHCP client IP Address which is assigned in DHCP OFFER Message.
 * @param		This is the variable that hodls the context related information of DHCP as well as DHCP
 * 					Client.
 * @return	The callback Function will return DHCP_SUCCESS or DHCP_FAILURE.
 */
int 
handle_dhcp_decline_callback
(
  unsigned int txid, 
	int dhcp_client_ip_address, 
	dhcp_ctx_t *ctx
);

/**
 * This is callback which is called/invoked pon receipt of DHCPRELEASE message.
 *
 * @param		Transaction Id which is received from DHCP client in DHCP DISCOVER
 *          Which is optional DHCP CLient may provide it or not. If it is provided
 *          bt DHCP client then DHCP server shall use it.
 * @param		This is the DHCP client IP Address which is assigned in DHCP OFFER Message.
 * @param		This is the variable that hodls the context related information of DHCP as well as DHCP
 * 					Client.
 * @return	The callback Function will return DHCP_SUCCESS or DHCP_FAILURE.
 */
int 
handle_dhcp_release_callback
(
  unsigned int txid, 
	int dhcp_client_ip_address, 
	dhcp_ctx_t *ctx
);

int
dhcp_prepare_dhcp_options_message
(
 unsigned char *p_dhcp_offer,
 dhcp_ctx_t    *ctx,
 int           dhcp_header_offset,
 int           msg_type
 );

int
dhcp_prepare_dhcp_header
(
 unsigned char   *p_dhcp_offer,
 dhcp_ctx_t      *ctx,
 unsigned char   msg_type
 );

int
prepare_dhcp_offer_message(
  unsigned int txid,
  int dhcp_client_ip_address,
  dhcp_ctx_t *ctx
);

/**
 * This function is used to DHCP SELECT Function Call
 *
 * @param   This is the variable that holds the context related information of DHCP as well as DHCP
 *          Client.
 * @return  The callback Function will return DHCP_SUCCESS or DHCP_FAILURE.
 */

int
dhcp_select
(
  dhcp_ctx_t *ctx 
);

/**
 * This function is used to send the DHCP Response to DHCP CLIENT
 *
 * @param   DHCP Server Context
 * @param   conn_id is on which DHCP request has been received
 * @return  The callback Function will return DHCP_SUCCESS or DHCP_FAILURE.
 */
int
send_dhcp_packet
(
  dhcp_ctx_t *ctx,
  int conn_id
);

/**
 * This function is used to receive the DHCP Client Request over UDP
 *
 * @param   DHCP Server Context
 * @param   connection id on which DHCP Request has been received
 * @return  length of received DHCP Request
 */
int
recv_dhcp_packet
(
  dhcp_ctx_t *ctx,
  int conn_id
);


/**
 * This function is used to print received request in HEX Format.
 *
 * @param   Pointer to Char buffer to received DHCP Request
 * @param   received buffer length
 * @return  void
 */
void
dhcp_print_hex
(
  unsigned char *bytes_buffer,
  unsigned int  buffer_len
);



