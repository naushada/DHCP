#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>
#include <netdb.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <assert.h>


#if defined ( __linux__ )

#include <linux/if_ether.h>
#include <features.h>

#endif
/**
 * local include files defined in inc
 */
#include <dhcp_main.h>



dhcp_msg_to_callback_t dhcp_msg_callback_table[25] =
{

  {DHCPUNKNOWN,     NULL},
  {DHCPDISCOVER,    handle_dhcp_discover_callback},
  {DHCPOFFER,       NULL},
  {DHCPREQUEST,     handle_dhcp_request_callback},
  {DHCPACK,         NULL}
};


/**
 * This function is retrieve the node which contains the network
 * parameters assigned to DHCP Client. Each node is retrieved
 * based on transaction id.
 *
 * @author      Mohd Naushad Ahmed (NAUSHAD.DLN@GMAIL.COM)
 * @version     V.1.0
 * @param       transaction id (xid) received from DHCP Client
 * @param       DHCP Server context parameters
 * @return      DHCP Client node containing network parameters
 */
dhcp_client_pool_t *
dhcp_get_client_node
(
  unsigned int xid,
  dhcp_ctx_t   *ctx
)
{
  dhcp_client_pool_t *tmp_node = ctx->ciaddr_allocated_pool;
  
  while ( NULL != tmp_node )
  {
    if ( xid == tmp_node->xid)
    {
      break;
    }
    tmp_node = tmp_node->next_client;
  }
  return (tmp_node);
} /* dhcp_get_client_node */


/**
 * This function is used to get the free IP address for DHCP Client,
 * Once the DHCP IP address is determine, It updates the other network
 * parameters.
 
 * @author      Mohd Naushad Ahmed (NAUSHAD.DLN@GMAIL.COM)
 * @version     V.1.0
 * @param       DHCP Server Context Parameter
 * @return      Allocated Node containing network parameter.
 */
dhcp_client_pool_t *
dhcp_get_free_dhcp_client_node
(
  dhcp_ctx_t *ctx
)
{
  dhcp_client_pool_t *tmp_node = NULL;
  
  /* First IP Address is going to be allocated */
  if ( NULL == ctx->ciaddr_allocated_pool )
  {
    ctx->ciaddr_allocated_pool = ctx->ciaddr_free_pool;
    ctx->ciaddr_free_pool = ctx->ciaddr_free_pool->next_client;
    ctx->ciaddr_allocated_pool->next_client = NULL;

    return ( ctx->ciaddr_allocated_pool );
  }
  else
  {
    tmp_node = ctx->ciaddr_allocated_pool;
    while ( NULL != tmp_node->next_client )
    {
      tmp_node = tmp_node->next_client;
    }
    tmp_node->next_client = ctx->ciaddr_free_pool;
    ctx->ciaddr_free_pool = ctx->ciaddr_free_pool->next_client;
    tmp_node = tmp_node->next_client;
    tmp_node->next_client = NULL;
    return ( tmp_node );
  }
} /*dhcp_get_free_dcp_client_node */


/**
 * This Function is used to populate network parameters along with IP address
 * and subnet mask and lease time. And node is allocated upon receipt of DHCP DISCOVER
 *
 * @author      Mohd Naushad Ahmed (NAUSHAD.DLN@GMAIL.COM)
 * @version     V.1.0
 * @param       start ip address
 * @param       end ip address
 * @param       net mask
 * @return      this function return the head of the linked list
 */
dhcp_client_pool_t *
dhcp_populate_client_ip_pool
(
  int        start_ip_address,
  int        end_ip_address,
  int        net_mask
)
{
  dhcp_client_pool_t *client_node = NULL, *head_node = NULL;
  dhcp_client_addr_t start_ip     = (dhcp_client_addr_t)start_ip_address;
  dhcp_client_addr_t end_ip       = (dhcp_client_addr_t)end_ip_address;
  dhcp_client_addr_t mask         = (dhcp_client_addr_t)net_mask;

  head_node = (dhcp_client_pool_t *) malloc(sizeof(dhcp_client_pool_t));
	
  if ( NULL != head_node )
  {
    memset( head_node, 0, sizeof(dhcp_client_pool_t));

    head_node->offered_addr.ciaddr       = start_ip.ciaddr; /* yiaddr */
    head_node->offered_net_mask.ciaddr   = mask.ciaddr;    /* subnet mask */
    head_node->lease_time                = DHCP_INFINITE_TIME;
    head_node->renewal_time              = 0x00;
    head_node->rebinding_time            = 0x00;
    head_node->next_client               = NULL;
    client_node                          = head_node;
  }
  
  while ( (start_ip.octet[3] + 1)  <= end_ip.octet[3] )
  {
    client_node->next_client = (dhcp_client_pool_t *) malloc(sizeof(dhcp_client_pool_t));
    
    if ( NULL != client_node->next_client )
    {
      client_node = client_node->next_client;
      memset( client_node, 0, sizeof(dhcp_client_pool_t));
      start_ip.octet[3]                      = start_ip.octet[3] + 1;
      client_node->offered_addr.ciaddr       = start_ip.ciaddr;
      client_node->offered_net_mask.ciaddr   = mask.ciaddr;
      client_node->lease_time                = DHCP_INFINITE_TIME;
      client_node->renewal_time              = 0x00;
      client_node->rebinding_time            = 0x00;
      client_node->next_client               = NULL;
    }
  }
  return ( head_node );
} /* dhcp_populate_client_ip_pool */


/**
 * This function is used to determine whether Request has come from existing
 * DHCP Client or new DHCP client based on Transaction ID.
 *
 * @author      Mohd Naushad Ahmed (NAUSHAD.DLN@GMAIL.COM)
 * @version     V.1.0
 * @param       transaction id received in DHCP REQUEST
 * @param       DHCP Server Context Parameter.
 * @return      TRUE if it is a new DHCP Client or FALSE for existing one.
 */
char
is_txid_of_new_dhcp_client
(
  unsigned int xid,
  dhcp_ctx_t   *ctx
)
{
  dhcp_client_pool_t *tmp_node = ctx->ciaddr_allocated_pool;
  
  while ( tmp_node      != NULL &&
          tmp_node->xid != xid )
  {
    tmp_node = tmp_node->next_client;
  }
  if (!tmp_node ) /* xid - transaction id is not found in the allocated node */
  {
    return(TRUE);
  }
  return(FALSE);
} /* is_txid_of_new_dhcp_client */


/**
 * This function prepares the DHCPACK message and sets the 
 * fd_write fd set so that select system call would gets unblocked and sends the DHCPACK 
 * to DHCP Client.
 
 * @author      Mohd Naushad Ahmed (NAUSHAD.DLN@GMAIL.COM)
 * @version     V.1.0
 * @param       transaction id received in DHCP REQUEST
 * @param       DHCP CLIENT IP ADDRESS
 * @param       DHCP Server context
 * @return      length of DHCPACK message
 */
int
dhcp_prepare_ack
(
  unsigned int txid,
  int dhcp_client_ip_address,
  dhcp_ctx_t *ctx
)
{
  unsigned char   *p_dhcp_ack      = NULL;
  size_t dhcp_ack_pkt_len          = 0;
  
  p_dhcp_ack = (unsigned char *) malloc( sizeof( dhcp_generic_packet_t ) );
  
  if ( NULL != p_dhcp_ack)
  {
    memset( p_dhcp_ack, 0, sizeof(dhcp_generic_packet_t) );
  
    dhcp_ack_pkt_len = dhcp_prepare_dhcp_header(p_dhcp_ack,
                                                ctx,
                                                BOOTREPLY);
  
    dhcp_ack_pkt_len = dhcp_prepare_dhcp_options_message(p_dhcp_ack,
                                               ctx,
                                               dhcp_ack_pkt_len,
                                               DHCPACK);
  
    ctx->response_pkt = (char *)malloc(dhcp_ack_pkt_len);
    assert( NULL != ctx->response_pkt );
    
    memset(ctx->response_pkt, 0, dhcp_ack_pkt_len);
  
    ctx->response_pkt_len = dhcp_ack_pkt_len;
  
    memcpy(ctx->response_pkt, p_dhcp_ack, dhcp_ack_pkt_len);
  
    free(p_dhcp_ack);
    p_dhcp_ack = NULL;
  
    FD_SET(ctx->fd, &ctx->write_fd);
  
    return (dhcp_ack_pkt_len);
  }
  return (0);
} /* dhcp_prepare_ack */


/**
 * This function prepares the DHCP OPTIONS message which is
 * of variable length.
 *
 * @author      Mohd Naushad Ahmed (NAUSHAD.DLN@GMAIL.COM)
 * @version     V.1.0
 * @param       pointer to char buffer for DHCP OPTIONS
 * @param       DHCP Server Context
 * @param       this is the length of DHCP Fixed Header
 * @param       DHCP Message Type
 * @return      DHCP Fixed headre's and DHCP OPTIONS's length
 */
int
dhcp_prepare_dhcp_options_message
(
  unsigned char *p_dhcp_offer,
  dhcp_ctx_t    *ctx,
  int           dhcp_header_offset,
  int           msg_type
)
{
  unsigned int subnet_mask = 0x00000000;
  
  subnet_mask = dhcp_get_client_node(((dhcp_generic_packet_t *)(ctx->received_pkt))->xid,ctx)->offered_net_mask.ciaddr;
  
  p_dhcp_offer[++dhcp_header_offset] = DHCP_OPTION_MESSAGE_TYPE;
  p_dhcp_offer[++dhcp_header_offset] = 1;       /* length */
  p_dhcp_offer[++dhcp_header_offset] = msg_type /* DHCPOFFER/ DHCPACK/ */;
  
  p_dhcp_offer[++dhcp_header_offset] = DHCP_OPTION_SUBNET_MASK;
  p_dhcp_offer[++dhcp_header_offset] = 4;   /* length */
  p_dhcp_offer[++dhcp_header_offset] = ( subnet_mask & 0x000000FF );
  p_dhcp_offer[++dhcp_header_offset] = ( subnet_mask & 0x0000FF00 ) >> 8;
  p_dhcp_offer[++dhcp_header_offset] = ( subnet_mask & 0x00FF0000 ) >> 16;
  p_dhcp_offer[++dhcp_header_offset] = ( subnet_mask & 0xFF000000 ) >> 24;

  p_dhcp_offer[++dhcp_header_offset] = DHCP_OPTION_ROUTER_OPTION;
  p_dhcp_offer[++dhcp_header_offset] = 4;   /* length */
  p_dhcp_offer[++dhcp_header_offset] = ( ctx->dhcp_server_addr.sin_addr.s_addr & 0x000000FF ) ;
  p_dhcp_offer[++dhcp_header_offset] = ( ctx->dhcp_server_addr.sin_addr.s_addr & 0x0000FF00 ) >> 8;
  p_dhcp_offer[++dhcp_header_offset] = ( ctx->dhcp_server_addr.sin_addr.s_addr & 0x00FF0000 ) >> 16;
  p_dhcp_offer[++dhcp_header_offset] = ( ctx->dhcp_server_addr.sin_addr.s_addr & 0xFF000000 ) >> 24;

  p_dhcp_offer[++dhcp_header_offset] = DHCP_OPTION_DOMAIN_NAME_SERVER;
  p_dhcp_offer[++dhcp_header_offset] = 8;   /* length */
  p_dhcp_offer[++dhcp_header_offset] = ( ctx->dns_ip_addr[0].ciaddr & 0x000000FF ) ;
  p_dhcp_offer[++dhcp_header_offset] = ( ctx->dns_ip_addr[0].ciaddr & 0x0000FF00 ) >> 8;
  p_dhcp_offer[++dhcp_header_offset] = ( ctx->dns_ip_addr[0].ciaddr & 0x00FF0000 ) >> 16;
  p_dhcp_offer[++dhcp_header_offset] = ( ctx->dns_ip_addr[0].ciaddr & 0xFF000000 ) >> 24;
  
  p_dhcp_offer[++dhcp_header_offset] = ( ctx->dns_ip_addr[1].ciaddr & 0x000000FF );
  p_dhcp_offer[++dhcp_header_offset] = ( ctx->dns_ip_addr[1].ciaddr & 0x0000FF00 ) >> 8;
  p_dhcp_offer[++dhcp_header_offset] = ( ctx->dns_ip_addr[1].ciaddr & 0x00FF0000 ) >> 16;
  p_dhcp_offer[++dhcp_header_offset] = ( ctx->dns_ip_addr[1].ciaddr & 0xFF000000 ) >> 24;
  
  p_dhcp_offer[++dhcp_header_offset] = DHCP_OPTION_IP_LEASE_TIME;
  p_dhcp_offer[++dhcp_header_offset] = 4;     /* length */
  p_dhcp_offer[++dhcp_header_offset] = 0;   /* vale */
  p_dhcp_offer[++dhcp_header_offset] = 255;   /* value */
  p_dhcp_offer[++dhcp_header_offset] = 255;   /* value */
  p_dhcp_offer[++dhcp_header_offset] = 255;   /* value */
  
  p_dhcp_offer[++dhcp_header_offset] = DHCP_OPTION_INTERFACE_MTU;
  p_dhcp_offer[++dhcp_header_offset] = 2;     /* length */
  p_dhcp_offer[++dhcp_header_offset] = ( 1500 & 0xFF00 ) >> 8;     /* value */
  p_dhcp_offer[++dhcp_header_offset] = ( 1500 & 0x00FF ) ; /* value */
  
  p_dhcp_offer[++dhcp_header_offset] = DHCP_OPTION_SERVER_IDENTIFIER;
  p_dhcp_offer[++dhcp_header_offset] = 4; /* length of dhcp server identifier */
  p_dhcp_offer[++dhcp_header_offset] = ( ctx->dhcp_server_addr.sin_addr.s_addr & 0x000000FF );
  p_dhcp_offer[++dhcp_header_offset] = ( ctx->dhcp_server_addr.sin_addr.s_addr & 0x0000FF00 ) >> 8;
  p_dhcp_offer[++dhcp_header_offset] = ( ctx->dhcp_server_addr.sin_addr.s_addr & 0x00FF0000 ) >> 16;
  p_dhcp_offer[++dhcp_header_offset] = ( ctx->dhcp_server_addr.sin_addr.s_addr & 0xFF000000 ) >> 24;
  
  p_dhcp_offer[++dhcp_header_offset] = DHCP_OPTION_END; /* end of Options */
 
  return(++dhcp_header_offset);
} /* dhcp_prepare_dhcp_options_message */


/**
 * This Function Prepares the DHCP Header which is common for all message
 *
 * @author      Mohd Naushad Ahmed (NAUSHAD.DLN@GMAIL.COM)
 * @version     V.1.0
 * @param       pointer to char buffer for DHCPHEADER
 * @param       DHCP Server Context
 * @param       DHCP Message Type
 * @return      length of DHCPHEADER Buffer
 */
int
dhcp_prepare_dhcp_header
(
  unsigned char   *p_dhcp_offer,
  dhcp_ctx_t      *ctx,
  unsigned char   msg_type
)
{
  int offset = -1;
  unsigned int offered_ip;
  
  if ( NULL != p_dhcp_offer )
  {
    p_dhcp_offer[++offset]  = msg_type; /* message type */
    p_dhcp_offer[++offset]  = 1;  /* htype */
    p_dhcp_offer[++offset]  = 6;  /* hlen */
    p_dhcp_offer[++offset]  = 0;  /* hops */
    p_dhcp_offer[++offset]  = ctx->received_pkt[4]; /* xid */
    p_dhcp_offer[++offset]  = ctx->received_pkt[5]; /* xid */
    p_dhcp_offer[++offset]  = ctx->received_pkt[6]; /* xid */
    p_dhcp_offer[++offset]  = ctx->received_pkt[7]; /* xid */
    p_dhcp_offer[++offset]  = 0x00; /* secs */
    p_dhcp_offer[++offset]  = 0x00; /* secs */
    p_dhcp_offer[++offset]  = 0x00; /* flags */
    p_dhcp_offer[++offset]  = 0x00; /* flags */
    p_dhcp_offer[++offset]  = ctx->received_pkt[12]; /* ciaddr */
    p_dhcp_offer[++offset]  = ctx->received_pkt[13]; /* ciaddr */
    p_dhcp_offer[++offset]  = ctx->received_pkt[14]; /* ciaddr */
    p_dhcp_offer[++offset]  = ctx->received_pkt[15]; /* ciaddr */
    
    offered_ip = dhcp_get_client_node(((dhcp_generic_packet_t *)(ctx->received_pkt))->xid,ctx)->offered_addr.ciaddr;
    
    p_dhcp_offer[++offset]   = (offered_ip & 0x000000FF );      /* Offered ip address */
    p_dhcp_offer[++offset]   = (offered_ip & 0x0000FF00 ) >> 8; /* Offered ip address */
    p_dhcp_offer[++offset]   = (offered_ip & 0x00FF0000 ) >> 16;/* Offered ip address */
    p_dhcp_offer[++offset]   = (offered_ip & 0xFF000000 ) >> 24;/* Offered ip address */
    p_dhcp_offer[++offset]   = 0x00; /* next server ip address */
    p_dhcp_offer[++offset]   = 0x00; /* next server ip address */
    p_dhcp_offer[++offset]   = 0x00; /* next server ip address */
    p_dhcp_offer[++offset]   = 0x00; /* next server ip address */
    
    p_dhcp_offer[++offset]   = 0x00; /* relay agent ip address */
    p_dhcp_offer[++offset]   = 0x00; /* relay agent ip address */
    p_dhcp_offer[++offset]   = 0x00; /* relay agent ip address */
    p_dhcp_offer[++offset]   = 0x00; /* relay agent ip address */
    
    memcpy((void *)&p_dhcp_offer[++offset], (void *)&ctx->received_pkt[28], (size_t)6); /* client mac address */
    offset += 15;
    
    memset((void *)&p_dhcp_offer[++offset], 0, (size_t)64); /* optional server host name */
    offset += 63;
    
    memset((void *)&p_dhcp_offer[++offset], 0, (size_t)128);/* boot file name */
    offset += 127;
    
    
    p_dhcp_offer[++offset]   = 0x63; /* dhcp magic cookie */
    p_dhcp_offer[++offset]   = 0x82; /* dhcp magic cookie */
    p_dhcp_offer[++offset]   = 0x53; /* dhcp magic cookie */
    p_dhcp_offer[++offset]   = 0x63; /* dhcp magic cookie */
    
    return(offset);
  }
  return(0);
  
}/* dhcp_prepare_dhcp_header */


/**
 * This is the callback which is invoked upon receipt of DHCPREQUEST Message from DHCP CLIENT
 *
 * @param   Transaction Id which is received from DHCP client in DHCP DISCOVER
 *          Which is optional DHCP CLient may provide it or not. If it is provided
 *          bt DHCP client then DHCP server shall use it.
 * @param   This is the DHCP client IP Address which is assigned in DHCP OFFER Message.
 * @param   This is the variable that hodls the context related information of DHCP as well as DHCP
 *          Client.
 * @return  The callback Function will return DHCP_SUCCESS or DHCP_FAILURE.
 */
int
handle_dhcp_request_callback
(
  unsigned int txid,
  int dhcp_client_ip_address,
  dhcp_ctx_t *ctx
)
{
  dhcp_client_pool_t    *dhcp_allocated_client = NULL;
  int                   response_pkt_len       = 0;

  if ( FALSE == is_txid_of_new_dhcp_client( txid, ctx ) )
  {
    dhcp_allocated_client = dhcp_get_client_node( txid, ctx );
    
    if ( NULL != dhcp_allocated_client )
    {
      dhcp_client_ip_address = dhcp_allocated_client->offered_addr.ciaddr; 
    }
    response_pkt_len =  dhcp_prepare_ack( txid, dhcp_client_ip_address, ctx );
    return(response_pkt_len);
  }
  fprintf(stderr,"Different DHCP Clients are using same xtid\n");
  return(ERROR);
} /* handle_dhcp_request_callback */


/**
 * This is the callback which is invoked when preparing DHCPOFFER Message to DHCP CLIENT
 *
 * @author Mohammed Naushad Ahmed (NAUSHAD.DLN@GMAIL.COM)
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
prepare_dhcp_offer_message
(
  unsigned int txid,
	int dhcp_client_ip_address,
	dhcp_ctx_t *ctx
)
{
  unsigned char   *p_dhcp_offer      = NULL;
  size_t dhcp_offer_pkt_len          = 0;
  
  p_dhcp_offer = (unsigned char *) malloc( sizeof( dhcp_generic_packet_t ) );
  assert( NULL != p_dhcp_offer );
  
  memset( p_dhcp_offer, 0, sizeof(dhcp_generic_packet_t) );
  
  dhcp_offer_pkt_len = dhcp_prepare_dhcp_header(p_dhcp_offer,
                                                ctx,
                                                BOOTREPLY);
  
  dhcp_offer_pkt_len = dhcp_prepare_dhcp_options_message(p_dhcp_offer,
                                               ctx,
                                               dhcp_offer_pkt_len,
                                               DHCPOFFER);
  
  ctx->response_pkt = (char *)malloc(dhcp_offer_pkt_len);
  assert( NULL != ctx->response_pkt );
  
  memset( ctx->response_pkt, 0, dhcp_offer_pkt_len );
  
  ctx->response_pkt_len = dhcp_offer_pkt_len;
  
  memcpy( ctx->response_pkt, p_dhcp_offer, dhcp_offer_pkt_len );
  
  free(p_dhcp_offer);
  
  p_dhcp_offer = NULL;
  
  FD_SET(ctx->fd, &ctx->write_fd);
  
  return(dhcp_offer_pkt_len);
  
} /* prepare_dhcp_offer_message */


/**
 * This is the callback which is invoked upon receipt of DHCPDISCOVER Message from DHCP CLIENT
 *
 * @param   Transaction Id which is received from DHCP client in DHCP DISCOVER
 *          Which is optional DHCP CLient may provide it or not. If it is provided
 *          bt DHCP client then DHCP server shall use it.
 * @param   This is the DHCP client IP Address which is assigned in DHCP OFFER Message.
 * @param   This is the variable that hodls the context related information of DHCP as well as DHCP
 *          Client.
 * @return  The callback Function will return DHCP_SUCCESS or DHCP_FAILURE.
 */
int
handle_dhcp_discover_callback
(
  unsigned int txid,
  int dhcp_client_ip_address,
  dhcp_ctx_t *ctx
)
{
  dhcp_client_pool_t   *dhcp_free_client = NULL;
  dhcp_generic_packet_t *dhcp_pkt         = NULL;
  int                  response_pkt_len  = 0;

  if ( TRUE == is_txid_of_new_dhcp_client( txid, ctx ) )
  {
    fprintf(stderr,"\ntxid 0x%X\n",txid);
    dhcp_free_client = dhcp_get_free_dhcp_client_node( ctx );
    dhcp_pkt = (dhcp_generic_packet_t *)ctx->received_pkt;
    memcpy( dhcp_free_client->chaddr, dhcp_pkt->chaddr, 6 );
    dhcp_free_client->xid = txid;
    response_pkt_len =  prepare_dhcp_offer_message( txid, dhcp_client_ip_address, ctx );
    return(response_pkt_len);
  }
  else
  {
    fprintf(stderr,"Different DHCP Clients are using same xtid\n");
    return(ERROR);
  }
} /* handle_dhcp_discover_callback */



/**
 * This function is used to create the UDP BROADCAST socket and binds it to 
 * given IP Address.
 *
 * @param   DHCP Server Context
 * @return  Returns OK upon SUCESS and ERROR upon Failure
 */
int
dhcp_create_socket
(
  dhcp_ctx_t *dhcp_ctx
)
{
  int flag = 1;

  /* Set up the address we're going to bind to. */
	bzero( &dhcp_ctx->dhcp_server_addr, sizeof( dhcp_ctx->dhcp_server_addr ) );
  dhcp_ctx->dhcp_server_addr.sin_family      = AF_INET;
  dhcp_ctx->dhcp_server_addr.sin_port        = htons( dhcp_ctx->dhcp_src_port );
  dhcp_ctx->dhcp_server_addr.sin_addr.s_addr = INADDR_ANY;                 /* listen on any address */

  bzero( &dhcp_ctx->dhcp_server_addr.sin_zero, sizeof( dhcp_ctx->dhcp_server_addr.sin_zero ) );

  /* create a socket for DHCP communications */
	dhcp_ctx->fd  = socket( AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  if ( dhcp_ctx->fd < 0 )
	{
		printf("Error: Could not create socket!\n");
	  exit(STATE_UNKNOWN);
	}

  /* set the reuse address flag so we don't get errors when restarting */
  flag = 1;

  if ( setsockopt( dhcp_ctx->fd, SOL_SOCKET, SO_REUSEADDR, (char *)&flag, sizeof(flag)) < 0 )
	{
	  printf("Error: Could not set reuse address option on DHCP socket!\n");
		exit(STATE_UNKNOWN);
	}

  /* set the broadcast option - we need this to listen to DHCP broadcast messages */
  if ( setsockopt( dhcp_ctx->fd, SOL_SOCKET, SO_BROADCAST, (char *)&flag, sizeof( flag) ) < 0 )
	{
	  printf("Error: Could not set broadcast option on DHCP socket!\n");
		exit(STATE_UNKNOWN);
	}

	/* bind socket to interface */
#if defined(__linux__)
	strncpy( dhcp_ctx->intf_name.ifr_ifrn.ifrn_name, dhcp_ctx->interface_name, IFNAMSIZ);
#else
	strncpy( dhcp_ctx->intf_name.ifr_name, dhcp_ctx->interface_name, IFNAMSIZ);
#endif

#if defined(__linux__)
	if ( setsockopt( dhcp_ctx->fd, SOL_SOCKET, SO_BINDTODEVICE, (char *)&dhcp_ctx->intf_name, sizeof( dhcp_ctx->intf_name ) ) < 0) 
	{
		exit(STATE_UNKNOWN);
	}
#endif 
  
  /* bind the socket */
  if ( bind( dhcp_ctx->fd, (struct sockaddr *)&dhcp_ctx->dhcp_server_addr, sizeof(dhcp_ctx->dhcp_server_addr) ) < 0) 
	{
	  printf("Error: Could not bind to DHCP socket (port %d)!  Check your privileges...\n",DHCP_CLIENT_PORT);
		exit(STATE_UNKNOWN);
	}
  dhcp_ctx->dhcp_server_addr.sin_addr.s_addr = inet_addr("192.168.3.1");                 /* listen on any address */
  return (OK);
} /* dhcp_create_socket */


/**
 * This Function is used to get the DHCP Message Type
 * @see     For details refer to https://tools.ietf.org/html/rfc1533#page-2
 * @param   pointer to char buffer to received dhcp request.
 * @param   length of dhcp request.
 * @return  returns the message type from received dhcp request.
 */
unsigned char 
get_dhcp_message_type
(
	 char       *dhcp_pkt,
	 size_t     dhcp_pkt_len 
)
{
  dhcp_message_type_t msg_type = DHCPUNKNOWN;
  /* 4 is for DHCP MAGIC COOKIE which is part of Options */
  /* 2 is to get to the offset of message type in BOOTP REQUEST */
	if ( (DHCP_MIN_LEN + 2 + 4) < dhcp_pkt_len )
	{
	  /* DHCP Packet is having at least one optional Filed present */
		/*  Code   Len  Type
		 *  +-----+-----+-----+
		 *  |  53 |  1  | 1-7 |
		 *  +-----+-----+-----+
		 * */			
    msg_type = (dhcp_message_type_t)((dhcp_generic_packet_t *)dhcp_pkt)->options[ 4 + 2 ];
	}
  return ( (unsigned char)msg_type );
} /* get_dhcp_message_type */


/**
 * This function is used to determine whether received message is valid or not.
 *
 * @param   dhcp message type
 *
 * @return  Returns TRUE if it is valid Message or FALSE for invalid message
 */
unsigned char
is_dhcp_message_valid
(
  unsigned char dhcp_msg_type
)
{
	unsigned char dhcp_ret_status = (unsigned char)FALSE;

  switch (dhcp_msg_type)
	{
	  case DHCPDISCOVER:
		case DHCPOFFER:
		case DHCPREQUEST:
		case DHCPDECLINE:
		case DHCPACK:
		case DHCPNACK:
		case DHCPRELEASE:
		  dhcp_ret_status = (unsigned char)TRUE; 
      break;
		default:
		  dhcp_ret_status = (unsigned char)FALSE;	
	}
	return (dhcp_ret_status);
} /* is_dhcp_message_valid */


/**
 * This Function is used to parse the received DHCP Request from DHCP CLIENT
 *
 * @param   DHCP Server Context
 * @return  OK upon success and ERROR upon Failure
 */
int
dhcp_parse_dhcp_req
(
  dhcp_ctx_t *dhcp_ctx
)
{
  dhcp_generic_packet_t *dhcp_pkt = (dhcp_generic_packet_t *)( dhcp_ctx->received_pkt );
  size_t dhcp_pkt_len             = dhcp_ctx->received_pkt_len;
  unsigned char dhcp_msg_type     = 0;

  dhcp_msg_type = get_dhcp_message_type( (char *)dhcp_pkt, dhcp_pkt_len );
  
  if ( TRUE == is_dhcp_message_valid( dhcp_msg_type ))
	{
    dhcp_msg_callback_table[dhcp_msg_type].dhcp_cb(dhcp_pkt->xid,
                                                   0x000000,
                                                   dhcp_ctx);
    return((int)OK);
	}
  fprintf(stderr, "Invalid Message Type [0x%X]\n",dhcp_msg_type);
  return ((int)ERROR);
} /* dhcp_parse_dhcp_req */


/**
 * This function is used to initialize the DHCP Server Context
 *
 * @param   pointer to DHCP Server Context
 * @return  OK upon success and ERROR upon FAILURE
 */
int
dhcp_init_dhcp_ctx
(
  dhcp_ctx_t *ctx
)
{
  struct sockaddr_in self_addr;
  char intf_name[] = "eth2";
  dhcp_client_addr_t start_ip;
  dhcp_client_addr_t end_ip;
  dhcp_client_addr_t mask;
  dhcp_client_addr_t dns1;
  dhcp_client_addr_t dns2;
  
  self_addr.sin_addr.s_addr = inet_addr("192.168.3.1");
  self_addr.sin_family      = AF_INET;
  self_addr.sin_port        = htons(DHCP_SERVER_PORT);
  
  memset( self_addr.sin_zero, 0, sizeof(self_addr.sin_zero) );
  
  start_ip.ciaddr = inet_addr("192.168.3.2");
  end_ip.ciaddr   = inet_addr("192.168.3.200");
  mask.ciaddr     = inet_addr("255.255.255.0");
  dns1.ciaddr     = inet_addr("208.67.222.222");
  dns2.ciaddr     = inet_addr("208.67.220.220");

  memcpy( (void *)&ctx->dhcp_server_addr, (void *)&self_addr, sizeof(struct sockaddr_in) );
  
  ctx->dhcp_src_port = DHCP_SERVER_PORT;
  ctx->dhcp_dst_port = DHCP_CLIENT_PORT;

  ctx->ciaddr_free_pool = dhcp_populate_client_ip_pool( start_ip.ciaddr, /* Start IP Address */
                                                        end_ip.ciaddr,   /* End IP Address */
                                                        mask.ciaddr );   /* Subnet MASK */
  
  strcpy( (char *)ctx->interface_name, (char *)intf_name); /* Ethernet Interface Name viz. eth1 or eth2 */
  
  FD_ZERO(&ctx->read_fd);      /* Zeroing read fd set */
  FD_ZERO(&ctx->write_fd);     /* Zeroing write fd set */
  FD_ZERO(&ctx->exception_fd); /* Zeroing exception fd set */
  
  ctx->to.tv_sec  = 5;  /* Wait for 5 seconds for response */
  ctx->to.tv_usec = 0;
  
  ctx->dns_ip_addr[0].ciaddr = dns1.ciaddr;  /* Open DNS Server IP Address */
  ctx->dns_ip_addr[1].ciaddr = dns2.ciaddr;  /* Auxilary Open Server IP Address */
  
  return(OK);
} /* dhcp_init_dhcp_ctx */


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
)
{
  int conn_id   = -1;
  int num_bytes = -1;
    
  FD_SET( ctx->fd, &ctx->read_fd);
  
  ctx->to.tv_sec=5;
  ctx->to.tv_usec=0;

  while (1)
  {
    conn_id = select( (ctx->fd + 1),
                      (fd_set *)&ctx->read_fd,
                      (fd_set *)&ctx->write_fd,
                      (fd_set *)&ctx->exception_fd,
                      (struct timeval *)&ctx->to );
  

    if (0 == conn_id)
    {

      /* Upon time out select system call rest all fd set to zero */
      FD_SET( ctx->fd, &ctx->read_fd);
    
      /* timeout of 2 second has happened */
      ctx->to.tv_sec  = 2;
      ctx->to.tv_usec = 0;
    }
    else if ( conn_id > 0)
    {
      if ( FD_ISSET( ctx->fd, &ctx->read_fd ) )
      {
        FD_CLR(ctx->fd, &ctx->read_fd);
        num_bytes = recv_dhcp_packet(ctx, ctx->fd);
        assert( num_bytes >=0 );
      }
      else if (FD_ISSET(ctx->fd, &ctx->write_fd))
      {
        FD_CLR(ctx->fd, &ctx->write_fd);
        num_bytes = send_dhcp_packet(ctx, ctx->fd);
        FD_SET( ctx->fd, &ctx->read_fd);

        ctx->to.tv_sec  = 2;
        ctx->to.tv_usec = 0;
      }
      else if (FD_ISSET(ctx->fd, &ctx->exception_fd))
      {
        fprintf(stderr,"Exception fd is set\n");
        
      }
    }/* end of ( conn_id > 0 )*/
  } /* End of while loop */
}/* dhcp_select */


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
)
{
  struct sockaddr_in client_addr;
  int ret_status = -1;

  socklen_t client_addr_len = sizeof(struct sockaddr_in);
  
  client_addr.sin_port = htons(ctx->dhcp_dst_port);
  client_addr.sin_family = AF_INET;
  client_addr.sin_addr.s_addr = inet_addr("255.255.255.255");
  
  memset(client_addr.sin_zero, 0, sizeof(client_addr.sin_zero));
  dhcp_print_hex ( (unsigned char*)ctx->response_pkt, ctx->response_pkt_len );
  
  if ( ( ret_status = sendto( conn_id,
                            (const void *)ctx->response_pkt,
                            (size_t)ctx->response_pkt_len,
                            (int)0,
                            (struct sockaddr *)&client_addr,
                            client_addr_len ) )  > 0 )
  {
    /* Freeing both memory pertaining to dhcp request & response */
    free(ctx->received_pkt);
    free(ctx->response_pkt);
    /* Initializing both of them NULL */
    ctx->received_pkt = NULL;
    ctx->response_pkt = NULL;
    fprintf(stderr,"\nResponse sent successfully\n");
  }
  return (ret_status); 
}/* sned_dhcp_packet */


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
)
{
  unsigned int idx = 0x00000000;
  for ( idx = 0; idx < buffer_len; idx++ )
  {
    if ( 0 == idx%16 )
    {
      fprintf( stderr, "\n" );
    }
    fprintf( stderr,"%.2X ", bytes_buffer[idx] );
  }
  fprintf( stderr, "\n" );
  
}/* dhcp_print_hex */


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
)
{
  unsigned char   tmp_buffer[1500];
  int    recv_buffer_len = 0;
  struct sockaddr_in dhcp_client_addr;
    
  socklen_t client_addr_len = sizeof(struct sockaddr_in);
  
  recv_buffer_len = recvfrom( (int)conn_id,
                              (void *)tmp_buffer,
                              sizeof(tmp_buffer),
                              (int)0,
                              (struct sockaddr *)&dhcp_client_addr,
                              (socklen_t *)&client_addr_len );
  
  if ( recv_buffer_len > 0)
  {
    dhcp_print_hex( tmp_buffer, recv_buffer_len );
    ctx->received_pkt = (char *) malloc( (size_t)recv_buffer_len );
    assert ( NULL != ctx->received_pkt );
    
    memset( (void *)ctx->received_pkt, (int)0, (size_t)recv_buffer_len );
    memcpy( (void *)ctx->received_pkt, (const void *)tmp_buffer, (size_t)recv_buffer_len );
    ctx->received_pkt_len = recv_buffer_len;
    /* Starts processing of received request now */
    dhcp_parse_dhcp_req(ctx);
    
  }
  return(recv_buffer_len);
} /* recv_dhcp_packet */


/**
 * This function is used to initialize the DHCP SERVER Context and Create Broad cast 
 * DHCP Socket for client.
 *
 * @param   DHCP Server Context
 * @return  OK Upon success and ERROR upon failure
 */
int
dhcp_server_main
(
  dhcp_ctx_t *ctx
)
{
  int ret_status = OK;
  
  ret_status = dhcp_init_dhcp_ctx( ctx );
  fprintf(stderr,"dhcp_init_dhcp_ctx ret status %d\n" ,ret_status);
  ret_status = dhcp_create_socket(ctx);
  fprintf(stderr,"dhcp_create_socket ret status %d\n" ,ret_status);
  ret_status = dhcp_select( ctx );
  return( (int)OK ); 
} /* dhcp_server_main */


/**
 * This function is the main function for DHCP Server
 *
 * @param   number of Arguments (Argument Count)
 * @param   List of arguments
 * @return  OK upon success or ERROR upon Failure
 */
int main (int argc, char *argv[])
{
  dhcp_ctx_t *ctx = (dhcp_ctx_t *)malloc(sizeof(dhcp_ctx_t));
  
  dhcp_server_main(ctx);
  return( (int)OK ); 
}
