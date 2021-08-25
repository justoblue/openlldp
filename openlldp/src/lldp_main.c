/** @file lldp_main.c
 *
 * OpenLLDP Main
 *
 * See LICENSE file for more info.
 * 
 * 
 * Authors: Terry Simons (terry.simons@gmail.com)
 *          Jason Peterson (condurre@users.sourceforge.net)
 *
 *******************************************************************/

#include <unistd.h>
#include <strings.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <getopt.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>


#include "framehandlers/linux/lldp_linux_framer.h"


#ifdef __FREEBSD__
#include <netinet/in.h>
#include <net/if_dl.h>
#include <net/if_arp.h>
#include <net/if_media.h>
#include <net/ethernet.h>
#include <net/bpf.h>
#endif /* __FREEBSD __ */



#ifdef USE_CONFUSE
#include <confuse.h>
#endif // USE_CONFUSE

#include "lldp_port.h"
#include "lldp_debug.h"
#include "tlv.h"
#include "lldp_neighbor.h"
#include "rx_sm.h"
#include "tx_sm.h"
#include "tlv_common.h"
#include "lldp_api.h"
#include "OrQueue.h"

#include "crypt/md5.h"

#include "platform/framehandler.h"
#ifndef __LEAK_DETECTOR__
#include <malloc.h>
#else
#include "leak_detector_c.h"
#endif
// This is set to argv[0] on startup.
char *program = "OPENLLDP";
const char * OPENLLDP_CONFIG_FILE = "/usr/local/bin/openlldpconfig";
const char* LOCAL_SUN_PATH = "/var/run/";
const char* LOCAL_SUN_FILE = "openlldpd.sock";

const char* IFNAME_1 = "eth0.80";
const char* IFNAME_2 = "eth0.81";

#ifdef __TARGET__
const char* OSC_MGR = "eth0.19";
#else
const char* OSC_MGR = "eth0.17";
#endif


void* g_OrInstance = NULL;
queue_t* g_DbMsgQueue = NULL;

struct lci_s lci;
#ifdef USE_CONFUSE
static cfg_t *cfg = NULL;
#endif

const uint8_t LLDP_TYPE_SHELFID = 1;
const uint8_t LLDP_TYPE_MCN = 2;
uint8_t g_LLDP_TYPE = 0;

void usage();

int initializeLLDP();
void cleanupLLDP();
void handle_segfault();

uint8_t glldpIpType = 0;
uint32_t gMgtAddressIpv4 = 0;
uint8_t gMgtAddressIpv6[LLDP_IPV6_SIZE] = {0};

char iface_list[IF_SIZE][LLDP_IF_NAMESIZE];
int  iface_filter = 0;
int process_loopback = 0;

struct lldp_port *lldp_ports = NULL;
struct lldp_port *lldp_osc_ports = NULL;
uint8_t g_dstMac[6];
uint8_t g_use_dstMac = 0;
uint8_t g_McnEnabled = 0;
LLDP_NEIGHBOR_SHELFID lldp_neignbor_shelfid_ifname1;
LLDP_NEIGHBOR_SHELFID lldp_neignbor_shelfid_ifname2;
LLDP_NEIGHBOR_SHELFID* g_lldp_neighbor_shelfid = NULL;

uint16_t g_MsgTxHold = 4;
uint16_t g_MsgTxInterval = 30;

#ifdef BUILD_SERVICE
SERVICE_STATUS          ServiceStatus; 
SERVICE_STATUS_HANDLE   hStatus; 

void ControlHandler(DWORD request);
#endif

int CreateOSCLLDP(lldp_osc_port_info_t* lldp_osc_port_info);


int LLDP_CalculatePduMsgDigest(uint8_t *pu1Lldpdu, uint16_t u2MsgLen,
                              uint8_t *pu1RetValMsgDigest)
{
    md5_get_key_digest(pu1Lldpdu, u2MsgLen, pu1RetValMsgDigest);

    return 0;
}

int LLDP_RxComparePduMsgDigest(uint8_t *pu1RecvDigest, uint8_t *pu1ExDigest)
{
    int i4RetVal = 1;

    if (pu1ExDigest != NULL)
    {
        i4RetVal = memcmp(pu1RecvDigest, pu1ExDigest, MD5_MAX_KEY_LENGTH);
        if (i4RetVal == 0)
        {
            /* Received digest matches the calculated digest */
            return 1;
        }
    }
    return 0;
}

void walk_port_list() {
    struct lldp_port *lldp_port = lldp_ports;

    while(lldp_port != NULL) {
        debug_printf(DEBUG_INT, "Interface structure @ %X\n", lldp_port);
        debug_printf(DEBUG_INT, "\tName: %s\n", lldp_port->if_name);
        debug_printf(DEBUG_INT, "\tIndex: %d\n", lldp_port->if_index);
        debug_printf(DEBUG_INT, "\tMTU: %d\n", lldp_port->mtu);
        debug_printf(DEBUG_INT, "\tMAC: %X:%X:%X:%X:%X:%X\n", lldp_port->source_mac[0]
                                                            , lldp_port->source_mac[1]
                                                            , lldp_port->source_mac[2]
                                                            , lldp_port->source_mac[3]
                                                            , lldp_port->source_mac[4]
                                                            , lldp_port->source_mac[5]); 
        debug_printf(DEBUG_INT, "\tIP: %d.%d.%d.%d\n", lldp_port->source_ipaddr[0]
                                                     , lldp_port->source_ipaddr[1]
                                                     , lldp_port->source_ipaddr[2]
                                                     , lldp_port->source_ipaddr[3]);
        lldp_port = lldp_port->next;
    }
}

uint8_t net_detect(const char* net_name)
{
    int skfd = 0;
    struct ifreq ifr;
    uint8_t result = 0;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(skfd < 0)
    {
        debug_printf(DEBUG_INT,"net_detect Open socket error!\n");
        return 0;
    }

    strcpy(ifr.ifr_name, net_name);

    if(ioctl(skfd, SIOCGIFFLAGS, &ifr) <0 )
    {
        debug_printf(DEBUG_INT,"net_detect %s: IOCTL error!\n", ifr.ifr_name);
        close(skfd);
        return 0;
    }

    if(ifr.ifr_flags & IFF_RUNNING)
    {
        result = 1;
    }
    else
    {
        result = 0;
    }
    close(skfd);
    return result;

}

void LLDP_Report()
{
    uint8_t IFNAME_1_ENABLED = 0;
    uint8_t IFNAME_2_ENABLED = 0;

    struct lldp_port *lldp_port = lldp_ports;
    while(lldp_port != NULL) 
    {
        if(lldp_port->if_name != NULL)
        {
            if (0 == strncmp(IFNAME_1, lldp_port->if_name, LLDP_IF_NAMESIZE))
            {
                g_lldp_neighbor_shelfid = &lldp_neignbor_shelfid_ifname1;
                IFNAME_1_ENABLED = 1;
            }
            else if (0 == strncmp(IFNAME_2, lldp_port->if_name, LLDP_IF_NAMESIZE))
            {
                g_lldp_neighbor_shelfid = &lldp_neignbor_shelfid_ifname2;
                IFNAME_2_ENABLED = 1;
            }
            else
            {
                lldp_port = lldp_port->next;
                continue;
            }
            if (!net_detect(lldp_port->if_name))
            {
                if(1 == g_lldp_neighbor_shelfid->isUp)
                {
                    debug_printf(DEBUG_INT, "(F)LLDP_Report: %s lldp_neighbor is down\n", lldp_port->if_name);
                    memset(g_lldp_neighbor_shelfid, 0, sizeof(LLDP_NEIGHBOR_SHELFID));
                    strncpy(g_lldp_neighbor_shelfid->localIfName, lldp_port->if_name, LLDP_IF_NAMESIZE-1);
                    g_lldp_neighbor_shelfid->isChanged = 1;
                }
            }
            else
            {
                if (0 == g_lldp_neighbor_shelfid->isUp)
                {
                    debug_printf(DEBUG_INT, "(G)LLDP_Report: %s lldp_neighbor is retain\n", lldp_port->if_name);
                    char aIfName[LLDP_IF_NAMESIZE] = {0};
                    strncpy(aIfName, lldp_port->if_name, LLDP_IF_NAMESIZE-1);
                    lldp_port = lldp_port->next;
                    LLDP_DeletePort(aIfName);
                    LLDP_AddPort(aIfName);
                    continue;
                }

                if (lldp_port->rx.somethingChangedRemote)
                {
                    debug_printf(DEBUG_INT, "(C true)LLDP_Report: somethingChangedRemote = %d,lldp_port->rx.state=%d on %s \n", lldp_port->rx.somethingChangedRemote, lldp_port->rx.state,lldp_port->if_name);
                    char *client_msg = lldp_neighbor_information(lldp_port, lldp_port->if_name, 0);
                    debug_printf(DEBUG_INT, "(D)LLDP_Report: neighbor information =  %s\n", client_msg);
                    free(client_msg);
                    if (g_lldp_neighbor_shelfid->isChanged)
                    {
                        debug_printf(DEBUG_INT, "(E)LLDP_Report: %s lldp_neighbor is Changed\n", lldp_port->if_name);
                    }
                }
            }
        }
        lldp_port = lldp_port->next;
    }

    if (IFNAME_1_ENABLED != 1)
    {
        debug_printf(DEBUG_INT, "LLDP_Report: IFNAME_1_ENABLED != 1\n");
        if (net_detect(IFNAME_1))
        {
            LLDP_AddPort(IFNAME_1);
            debug_printf(DEBUG_INT, "LLDP_Report: LLDP_AddPort(IFNAME_1)\n");
        }
    }

    if (IFNAME_2_ENABLED != 1)
    {
        debug_printf(DEBUG_INT, "LLDP_Report: IFNAME_2_ENABLED != 1\n");
        if (net_detect(IFNAME_2))
        {
            LLDP_AddPort(IFNAME_2);
            debug_printf(DEBUG_INT, "LLDP_Report: LLDP_AddPort(IFNAME_2)\n");
        }
    }
}

void LLDP_OSC_Report()
{
    struct lldp_port *lldp_port = lldp_osc_ports;
    while(lldp_port != NULL) 
    {
        if(lldp_port->if_name != NULL)
        {
            if (lldp_port->rx.somethingChangedRemote)
            {
                debug_printf(DEBUG_INT, "LLDP_OSC_Report: somethingChangedRemote = %d,lldp_port->rx.state=%d on %s \n", lldp_port->rx.somethingChangedRemote, lldp_port->rx.state,lldp_port->if_name);
                char *client_msg = lldp_neighbor_information(lldp_port, NULL, 0);
                debug_printf(DEBUG_INT, "LLDP_OSC_Report: neighbor information =  %s\n", client_msg);
                free(client_msg);
            }
        }
        lldp_port = lldp_port->next;
    }
}

void LLDP_OSC_Report_Neignbor()
{
    char *client_msg = lldp_neighbor_information(lldp_osc_ports, NULL, 1);
    printf("LLDP_OSC_Report_Neignbor:\n%s\n", client_msg);//cli debug menu
    free(client_msg);
}


void LLDP_OSC_RunSM()
{
    struct lldp_port *lldp_port = lldp_osc_ports;
    while(lldp_port != NULL) 
    {
        if(lldp_port->if_name != NULL)
        {
            txStatemachineRun(lldp_port);
            rxStatemachineRun(lldp_port);
        }
        lldp_port = lldp_port->next;
    }
}

void LLDP_OSC_RunRxSM()
{
    struct lldp_port *lldp_port = lldp_osc_ports;
    while(lldp_port != NULL) 
    {
        if(lldp_port->if_name != NULL)
        {
            rxStatemachineRun(lldp_port);
        }
        lldp_port = lldp_port->next;
    }
}

int LLDP_PortIsExist(char * theIfName)
{
    struct lldp_port *lldp_port = lldp_ports;
    while(lldp_port != NULL) 
    {
        if(strncmp(theIfName, (const char*)lldp_port->if_name, IF_NAMESIZE) == 0)
        {
            return 1;
        }
        lldp_port = lldp_port->next;
    }
    return 0;
}
void initializeLldpNeighborShelfId()
{
    memset(&lldp_neignbor_shelfid_ifname1, 0, sizeof(LLDP_NEIGHBOR_SHELFID));
    memset(&lldp_neignbor_shelfid_ifname2, 0, sizeof(LLDP_NEIGHBOR_SHELFID));
    strncpy(lldp_neignbor_shelfid_ifname1.localIfName, IFNAME_1, LLDP_IF_NAMESIZE-1);
    strncpy(lldp_neignbor_shelfid_ifname2.localIfName, IFNAME_2, LLDP_IF_NAMESIZE-1);
    lldp_neignbor_shelfid_ifname1.isUp = 0;
    lldp_neignbor_shelfid_ifname2.isUp = 0;
    strncpy(iface_list[0], IFNAME_1, LLDP_IF_NAMESIZE-1);
    strncpy(iface_list[1], IFNAME_2, LLDP_IF_NAMESIZE-1);
    iface_filter = 2;

}
void initializeLldpNeighborOSC()
{
    strncpy(iface_list[0], OSC_MGR, LLDP_IF_NAMESIZE-1);
    iface_filter = 1;

}

void initializeInterface()
{
    int ifIndex;
    for (ifIndex = 0; ifIndex < IF_SIZE; ifIndex++)
    {
        memset(iface_list[ifIndex], 0, LLDP_IF_NAMESIZE);
    }
}

time_t g_last_check = 0;

void LLDP_daemon()
{
    int socket_width = 0;
    /* Needed for select() */
    fd_set readfds;
    struct timeval timeout;
    struct timeval un_timeout;
    time_t current_time = 0;

    int result = 0;
    struct lldp_port *lldp_port = NULL;

    /* Set up select() */
    FD_ZERO(&readfds);

    lldp_port = lldp_ports;

    while(lldp_port != NULL) {
      // This is not the interface you are looking for...
      if(lldp_port->if_name == NULL)
      {
          debug_printf(DEBUG_NORMAL, "LLDP_daemon [ERROR] Interface index %d with name is NULL at: %s():%d\n", lldp_port->if_index, __FUNCTION__, __LINE__);
          lldp_port = lldp_port->next;
          continue;
      }

      FD_SET(lldp_port->socket, &readfds);

      if(lldp_port->socket > socket_width)
      {
          socket_width = lldp_port->socket;
      }

      lldp_port = lldp_port->next;

    }

    time(&current_time);

    // Will be used to tell select how long to wait for...
    //timeout.tv_sec = 1;
    timeout.tv_sec = 0;
    timeout.tv_usec = 1;

    // Timeout after 1 second if nothing is ready
    result = select(socket_width+1, &readfds, NULL, NULL, &timeout);

    // Everything is cool... process the sockets
    lldp_port = lldp_ports;

    while(lldp_port != NULL) {
      // This is not the interface you are looking for...
      if(lldp_port->if_name == NULL ||
         lldp_port->rx.frame == NULL ||
         lldp_port->tx.frame == NULL) {
          debug_printf(DEBUG_NORMAL, "LLDP_daemon [ERROR] Interface index %d with name is NULL at: %s():%d\n", lldp_port->if_index, __FUNCTION__, __LINE__);
          lldp_port = lldp_port->next;
          continue;
      }

      if(result > 0) {
          if(FD_ISSET(lldp_port->socket, &readfds)) {
              debug_printf(DEBUG_INT, "%s is readable!\n", lldp_port->if_name);
              FD_CLR(lldp_port->socket, &readfds);

              // Get the frame back from the OS-specific frame handler.
              lldp_read(lldp_port);

              if(lldp_port->rx.recvsize <= 0) {
                  if(errno != EAGAIN && errno != ENETDOWN) {
                      debug_printf(DEBUG_INT, "Error: (%d) : %s (%s:%d)\n", errno, strerror(errno), __FUNCTION__, __LINE__);
                  }
              }
              else if((int)lldp_port->rx.recvsize >(int)(lldp_port->mtu-4)){
                  memset(&lldp_port->rx.frame[0], 0x0, lldp_port->mtu);
                  debug_printf(DEBUG_INT, "Error: receive wrong packets (%s:%d)\n", __FUNCTION__, __LINE__);
              }
              else {
                  debug_printf(DEBUG_INT, "Got an LLDP frame %d bytes long on %s!\n", lldp_port->rx.recvsize, lldp_port->if_name);
                  //      debug_hex_dump(DEBUG_INT, lldp_port->rx.frame, lldp_port->rx.recvsize);
                  // Mark that we received a frame so the state machine can process it.
                  lldp_port->rx.rcvFrame = 1;
                  rxStatemachineRun(lldp_port);
              }
          }

      }
      if((result == 0) || (current_time > g_last_check)) {
          lldp_port->tick = 1;

          txStatemachineRun(lldp_port);
          rxStatemachineRun(lldp_port);

          lldp_port->tick = 0;
      }

      if(result < 0) {
          if(errno != EINTR) {
              debug_printf(DEBUG_NORMAL, "[ERROR] %s\n", strerror(errno));
          }
      }

      lldp_port = lldp_port->next;

    }

    time(&g_last_check);


}

void LLDP_OSC_Recv()
{
    if (lldp_ports == NULL)
    {
        return;
    }
    if(lldp_ports->rx.frame == NULL)
    {
        return;
    }

    int socket_width = 0;
    /* Needed for select() */
    fd_set readfds;
    struct timeval timeout;
    struct timeval un_timeout;
    struct lldp_port *lldp_port = lldp_ports;
    struct lldp_port *lldp_osc_port = NULL;
    uint8_t aPduMsgDigest[MD5_MAX_KEY_LENGTH] = {0};

    int result = 0;

    /* Set up select() */
    FD_ZERO(&readfds);
    FD_SET(lldp_port->socket, &readfds);
    if(lldp_port->socket > socket_width)
    {
      socket_width = lldp_port->socket;
    }
    // Will be used to tell select how long to wait for...
    //timeout.tv_sec = 1;
    timeout.tv_sec = 0;
    timeout.tv_usec = 1;

    // Timeout after 1 second if nothing is ready
    result = select(socket_width+1, &readfds, NULL, NULL, &timeout);
    if(result > 0)
    {
        if(FD_ISSET(lldp_port->socket, &readfds))
        {
            FD_CLR(lldp_port->socket, &readfds);

            debug_printf(DEBUG_INT, "%s is readable!\n", lldp_port->if_name);
            // Get the frame back from the OS-specific frame handler.
            while(lldp_osc_read(lldp_port) > 0)
            {
                if( (g_McnEnabled == 0) || (int)lldp_port->rx.recvsize > (int)(lldp_port->mtu-4))
                {
                    memset(&lldp_port->rx.frame[0], 0x0, lldp_port->mtu);
                    debug_printf(DEBUG_INT, "MCN disabled or Error: receive wrong packets (%s:%d)\n", __FUNCTION__, __LINE__);
                    continue;
                }

                debug_printf(DEBUG_INT,"%s is readable! lldp_port->rx.recvsize =%d \n", lldp_port->if_name, (int)lldp_port->rx.recvsize);
                lldp_osc_port = rxHandleFrame(&lldp_port->rx.frame[0], lldp_osc_ports);
                if (lldp_osc_port != NULL)
                {
                    lldp_osc_port->rx.recvsize = lldp_port->rx.recvsize;
                    lldp_osc_port->rx.rcvFrame = 1;

                    LLDP_CalculatePduMsgDigest(lldp_osc_port->rx.frame, lldp_osc_port->rx.recvsize, aPduMsgDigest);
                    if (LLDP_RxComparePduMsgDigest(aPduMsgDigest, lldp_osc_port->rx.pduMsgDigest) == 0)
                    {
                        debug_printf(DEBUG_INT, "Got an LLDP frame %d bytes long on %s!\n", lldp_osc_port->rx.recvsize, lldp_osc_port->if_name);
                        rxStatemachineRun(lldp_osc_port);

                        if (lldp_osc_port->rx.badFrame == 0)
                        {
                            debug_printf(DEBUG_INT, "Got an different PduMsgDigest LLDP frame  on %s!\n", lldp_osc_port->if_name);
                            memcpy(&lldp_osc_port->rx.pduMsgDigest[0], &aPduMsgDigest[0],
                                   MD5_MAX_KEY_LENGTH);
                        }
                        else
                        {
                            debug_printf(DEBUG_INT, "Got an badFrame on %s!\n", lldp_osc_port->if_name);
                            lldp_osc_port->rx.rxFrameType = ORLLDP_RX_FRAME_INVALID;
                        }
                    }
                    else
                    {
                        if(lldp_osc_port->msap_cache != NULL)
                        {
                            lldp_osc_port->msap_cache->rxInfoTTL = lldp_osc_port->msap_cache->rxOrignalTTL;
                        }
                        else
                        {
                            debug_printf(DEBUG_INT, "Got an refresh LLDP frame, but msap_cache is null on %s!\n", lldp_osc_port->if_name);
                            memset(lldp_port->rx.pduMsgDigest, 0, MD5_MAX_KEY_LENGTH);
                        }
                        lldp_osc_port->rx.recvsize = 0;
                        lldp_osc_port->rx.rcvFrame = 0;
                        lldp_osc_port->rx.rxFrameType = ORLLDP_RX_FRAME_REFRESH;
                    }
                    debug_printf(DEBUG_INT, "Got an LLDP frame Type is (%d)\n", (int)lldp_osc_port->rx.rxFrameType);
                    lldp_osc_port->rx.frame = NULL;
                }
                memset(&lldp_port->rx.frame[0], 0x0, lldp_port->rx.recvsize);
            }
        }
    }
    if (g_McnEnabled == 1)
    {
        LLDP_OSC_RunSM();
        LLDP_OSC_Report();
    }
    else
    {
        LLDP_OSC_RunRxSM();
    }
}

void LLDP_AddPort(const char * theIfName)
{
    if (theIfName)
    {
        initializeInterface();
        memcpy(iface_list[0], theIfName, strlen(theIfName)+1);
        iface_filter = 1;
        initializeLLDP();
    }

}
void LLDP_ShowPort()
{
    struct lldp_port *lldp_port = lldp_ports;
    printf("lldp_port: port information:\n");//cli debug menu

    while (lldp_port != NULL)
    {
        if(lldp_port->if_name == NULL)
        {
            lldp_port = lldp_port->next;
            continue;
        }
        printf("ifname:%s ",lldp_port->if_name);//cli debug menu
        lldp_port = lldp_port->next;
    }
}

void LLDP_ShowOscPort()
{
    struct lldp_port *lldp_osc_port = lldp_osc_ports;
    printf("LLDP_ShowOscPort: OSC port information:\n");//cli debug menu

    while (lldp_osc_port != NULL)
    {
        if(lldp_osc_port->if_name == NULL)
        {
            lldp_osc_port = lldp_osc_port->next;
            continue;
        }
        printf("shelf_id:%d ",lldp_osc_port->shelf_id);//cli debug menu
        printf("slot_id:%d ",lldp_osc_port->slot_id);//cli debug menu
        printf("port_id:%d\n",lldp_osc_port->port_id);//cli debug menu
        lldp_osc_port = lldp_osc_port->next;
    }
}


void LLDP_AddOscPort(lldp_osc_port_info_t* lldp_osc_port_info)
{
    if (lldp_osc_port_info == NULL)
    {
        return;
    }
    if (lldp_osc_port_info->shelf_id > 0 && lldp_osc_port_info->shelf_id < 64 &&
        lldp_osc_port_info->slot_id > 0 && lldp_osc_port_info->slot_id < 100 &&
        lldp_osc_port_info->port_id > 0 && lldp_osc_port_info->port_id < 128)
    {
        CreateOSCLLDP(lldp_osc_port_info);
    }

}

void LLDP_SetMcnEnabled(uint8_t theMcnEnabled)
{
    g_McnEnabled = theMcnEnabled;
}

void LLDP_SetMsgTxHold(uint16_t theMsgTxHold)
{
    struct lldp_port *lldp_osc_port = lldp_osc_ports;
    g_MsgTxHold = theMsgTxHold;
    debug_printf(DEBUG_INT,"g_MsgTxHold:%d\n",g_MsgTxHold);
    while (lldp_osc_port != NULL)
    {
        lldp_osc_port->tx.timers.msgTxHold = g_MsgTxHold;
        lldp_osc_port = lldp_osc_port->next;
    }
}
void LLDP_SetMsgTxInterval(uint16_t theMsgTxInterval)
{
    struct lldp_port *lldp_osc_port = lldp_osc_ports;
    g_MsgTxInterval = theMsgTxInterval;
    debug_printf(DEBUG_INT,"g_MsgTxInterval:%d\n",g_MsgTxInterval);
    while (lldp_osc_port != NULL)
    {
        lldp_osc_port->tx.timers.msgTxInterval = g_MsgTxInterval;
        lldp_osc_port = lldp_osc_port->next;
    }
}

struct lldp_port *LLDP_GetPortFromIfName(struct lldp_port * lldp_port, const char* theIfName)
{
    if (theIfName == NULL)
    {
        return NULL;
    }

    while(lldp_port != NULL)
    {
        if(strncmp(theIfName, (const char*)lldp_port->if_name, LLDP_IF_NAMESIZE) == 0)
        {
            break;
        }
        lldp_port = lldp_port->next;
    }
    return lldp_port;
}

void LLDP_UpdateOscPortSrcMac(uint8_t shelf_id,uint8_t slot_id,uint8_t port_id, uint8_t* src_mac)
{
    if (shelf_id > 0 && shelf_id < 128 &&
        slot_id > 0 && slot_id < 16 &&
        port_id > 0 && port_id<64 &&
        src_mac != NULL)
    {
        struct lldp_port *lldp_port = lldp_osc_ports;
        while(lldp_port != NULL)
        {
            if(lldp_port->tx.frame != NULL &&
                shelf_id == lldp_port->shelf_id &&
                slot_id == lldp_port->slot_id &&
                port_id == lldp_port->port_id)
            {
                lldp_port->source_mac[0] = src_mac[0];
                lldp_port->source_mac[1] = src_mac[1];
                lldp_port->source_mac[2] = src_mac[2];
                lldp_port->source_mac[3] = src_mac[3];
                lldp_port->source_mac[4] = src_mac[4];
                lldp_port->source_mac[5] = src_mac[5];                
                debug_printf(DEBUG_INT,"LLDP_UpdateOscPortSrcMac:%x:%x:%x:%x:%x:%x\n",
                    lldp_port->source_mac[0],lldp_port->source_mac[1],lldp_port->source_mac[2],
                    lldp_port->source_mac[3],lldp_port->source_mac[4],lldp_port->source_mac[5]);
                break;
            }
            lldp_port = lldp_port->next;
        }


    }
}

void LLDP_UpdateOscPortChassisID(uint8_t shelf_id, uint8_t* chassis_id)
{
    if (shelf_id > 0 && shelf_id < 128 &&
        chassis_id != NULL)
    {
        struct lldp_port *lldp_port = lldp_osc_ports;
        while(lldp_port != NULL)
        {
            if(lldp_port->tx.frame != NULL &&
                shelf_id == lldp_port->shelf_id)
            {
                lldp_port->chassis_id[0] = chassis_id[0];
                lldp_port->chassis_id[1] = chassis_id[1];
                lldp_port->chassis_id[2] = chassis_id[2];
                lldp_port->chassis_id[3] = chassis_id[3];
                lldp_port->chassis_id[4] = chassis_id[4];
                lldp_port->chassis_id[5] = chassis_id[5];
                debug_printf(DEBUG_INT,"LLDP_UpdateOscPort:%x:%x:%x:%x:%x:%x\n",
                    lldp_port->chassis_id[0],lldp_port->chassis_id[1],lldp_port->chassis_id[2],
                    lldp_port->chassis_id[3],lldp_port->chassis_id[4],lldp_port->chassis_id[5]);
            }
            lldp_port = lldp_port->next;
        }
    }
}

void LLDP_UpdateOscPortStatus(uint8_t shelf_id, uint8_t admin_status)
{
    if (shelf_id > 0 && shelf_id < 128)
    {
        struct lldp_port *lldp_port = lldp_osc_ports;
        while(lldp_port != NULL)
        {
            if(lldp_port->tx.frame != NULL &&
                shelf_id == lldp_port->shelf_id)
            {
                if (admin_status == 1)
                {
                    lldp_port->adminStatus  = enabledRxTx;
                    // Send out the first LLDP frame
                    // This allows other devices to see us right when we come up, rather than 
                    // having to wait for a full timer cycle
                    txChangeToState(lldp_port, TX_IDLE);
                    mibConstrInfoOSCLLDPDU(lldp_port);
                    if (lldp_ports != NULL)
                    {
                        txOscFrame(lldp_port, lldp_ports);
                    }
                }
                else
                {
                    lldp_port->adminStatus  = enabledRxOnly;
                }
                debug_printf(DEBUG_INT,"LLDP_UpdateOscPortStatus:shelf_ready:%d\n",admin_status);
            }
            lldp_port = lldp_port->next;
        }
    }

}
void LLDP_DeleteOscPort(lldp_osc_port_info_t* lldp_osc_port_info, uint8_t* need_delete)
{
    if (lldp_osc_port_info->shelf_id > 0 && lldp_osc_port_info->shelf_id < 128 &&
        lldp_osc_port_info->slot_id > 0 && lldp_osc_port_info->slot_id < 16 &&
        lldp_osc_port_info->port_id > 0 && lldp_osc_port_info->port_id<64)
    {
        char aIfName[LLDP_IF_NAMESIZE];
        memset(aIfName, 0, LLDP_IF_NAMESIZE);
        strncpy((char *)aIfName, (char *)lldp_osc_port_info->if_name, LLDP_IF_NAMESIZE);

        struct lldp_port *lldp_osc_port = LLDP_GetPortFromIfName(lldp_osc_ports, aIfName);
        if (lldp_osc_port != NULL)
        {
            debug_printf(DEBUG_INT, "LLDP_DeleteOscPort tx shutdown OscFrame\n");
            mibForceDeleteObjects(lldp_osc_port, need_delete);

            txChangeToState(lldp_osc_port, TX_SHUTDOWN_FRAME);
            mibConstrShutdownOSCLLDPDU(lldp_osc_port);
            txOscFrame(lldp_osc_port, lldp_ports);
            cleanupOscLLDPPort(aIfName, 0);
        }
    }

}


void LLDP_DeletePort(char * theIfName)
{
    if (theIfName)
    {
        struct lldp_port *lldp_port = LLDP_GetPortFromIfName(lldp_ports, theIfName);
        if (lldp_port != NULL)
        {
            debug_printf(DEBUG_INT, "LLDP_DeletePort tx shutdown Frame\n");
            txChangeToState(lldp_port, TX_SHUTDOWN_FRAME);
            mibConstrShutdownLLDPDU(lldp_port);
            txFrame(lldp_port);
        }

        cleanupLLDPPort(theIfName, 0);
    }
}

LLDP_NEIGHBOR_SHELFID* LLDP_GetPortNeighbor(const char * theIfName)
{
    if (theIfName)
    {
        if (0 == strncmp(IFNAME_1, theIfName, LLDP_IF_NAMESIZE))
        {
            return &lldp_neignbor_shelfid_ifname1;
        }
        else if (0 == strncmp(IFNAME_2, theIfName, LLDP_IF_NAMESIZE))
        {
            return &lldp_neignbor_shelfid_ifname2;
        }
        else
        {
            return NULL;
        }
    }
    return NULL;

}

void LLDP_SetPortValid(const char * theIfName , uint8_t theUp)
{
    if (theIfName)
    {
        if (0 == strncmp(IFNAME_1, theIfName, LLDP_IF_NAMESIZE))
        {
            lldp_neignbor_shelfid_ifname1.isUp = theUp;
        }
        else if (0 == strncmp(IFNAME_2, theIfName, LLDP_IF_NAMESIZE))
        {
            lldp_neignbor_shelfid_ifname2.isUp = theUp;
        }
    }
    return;
}

void  LLDP_SetSysName(char* aSysName)
{
    get_sys_fqdn(aSysName);
}
void  LLDP_SetOrInstance(void* aOrInstance)
{
    g_OrInstance = aOrInstance;
}

void  LLDP_SetIpv4MgtAddress(uint32_t theAddress)
{
    glldpIpType = IANA_IP;
    gMgtAddressIpv4 = theAddress;
}

void  LLDP_SetIpv6MgtAddress(uint8_t theMgtAddress[])
{
    glldpIpType = IANA_IP6;
    memset((void *)gMgtAddressIpv6, 0 , sizeof(uint8_t) * LLDP_IPV6_SIZE);
    memcpy((void *)gMgtAddressIpv6, (void *)theMgtAddress, LLDP_IPV6_SIZE);
}
void LLDP_DeleteMgtAddress()
{
    glldpIpType = 0;
    gMgtAddressIpv4 = 0;
    memset((void *)gMgtAddressIpv6, 0 , sizeof(uint8_t) * LLDP_IPV6_SIZE);
}
int hex2num(char c)
{
    if (c>='0' && c<='9') return c - '0';
    if (c>='a' && c<='z') return c - 'a' + 10;
    if (c>='A' && c<='Z') return c - 'A' + 10;

    debug_printf(DEBUG_INT, "unexpected char: %c", c);
    return 0;
}
 
int str2mac(const char * szMac, uint8_t * pMac)  
{  
    const char * pTemp = szMac;  
    int i;
    
    for (i = 0;i < 6;++i)  
    {  
        pMac[i] = hex2num(*pTemp++) * 16;  
        pMac[i] += hex2num(*pTemp++);  
    }     
    return 0;
}

void  LLDP_SetDstMac(const char* theDstMac)
{
    if (strlen(theDstMac) < 6)
    {
        g_use_dstMac = 0;
    }
    else
    {
        g_use_dstMac = 1;
        str2mac(theDstMac, g_dstMac);
        printf("set dst MAC to: \n");//cli debug menu
        debug_hex_printf(DEBUG_NORMAL, (uint8_t *)g_dstMac, 6);

    }
}

char* LLDP_GetSysName()
{
    return &lldp_systemname[0];
}


int LLDP_init(const char * debug_flags,uint8 threadFlag)
{
    uid_t uid;
    int op = 0;
    int result = 0;

    if (debug_flags)
    {
        debug_alpha_set_flags(debug_flags);
    }
    g_DbMsgQueue = (queue_t*)malloc(sizeof(queue_t));
    queue_init(g_DbMsgQueue, MCN_LLDP_MAX_MSG_NUM);

    initializeInterface();
    g_LLDP_TYPE = threadFlag;
    if(threadFlag == LLDP_TYPE_SHELFID)
    {
        initializeLldpNeighborShelfId();
    }
    else if (threadFlag == LLDP_TYPE_MCN)
    {
        initializeLldpNeighborOSC();
        get_sys_fqdn((char*)NULL);
    }
    /* Initialize2 the LLDP subsystem */
    /* This should happen on a per-interface basis */
    if(initializeLLDP() == 0)
    {
        debug_printf(DEBUG_NORMAL, "No interface found to listen on\n");
    }


#ifdef USE_CONFUSE
    //lci.config_file = OPENLLDP_CONFIG_FILE;
#endif // USE_CONFUSE

    lci.config_file = NULL;


    /* Don't forget to initialize the TLV validators... */
    initializeTLVFunctionValidators();

    get_sys_desc();

    #ifdef USE_CONFUSE
    //read the location config file for the first time!
    lci_config ();
    #endif // USE_CONFUSE


    return 0;
}


/***************************************
 *
 * Trap a segfault, and exit cleanly.
 *
 ***************************************/
void handle_segfault()
{
    debug_printf(DEBUG_NORMAL, "[FATAL] SIGSEGV  (Segmentation Fault)!\n");

    exit(-1);
}

/***************************************
 *
 * Trap a HUP, and read location config file new.
 *
 ***************************************/
void
handle_hup()
{
#ifdef USE_CONFUSE
  debug_printf(DEBUG_NORMAL, "[INFO] SIGHUP-> read config file again!\n");
  lci_config();
#endif // USE_CONFUSE
}

int initializeLLDP()
{
    int if_index = 0;
    char if_name[LLDP_IF_NAMESIZE];
    struct lldp_port *lldp_port = NULL;
    int nb_ifaces = 0;

    /* We need to initialize an LLDP port-per interface */
    /* "lldp_port" will be changed to point at the interface currently being serviced */
    //for (if_index = MIN_INTERFACES; if_index < MAX_INTERFACES; if_index++)
    //{
    //    if(if_indextoname(if_index, if_name) == NULL)
    //        continue;

    if (iface_filter > 0) 
    {
        if (iface_filter > IF_SIZE)
        {
            debug_printf(DEBUG_NORMAL, " Error : iface_list overflow\n");
            return 0;
        }
        int ifIndex;
        for (ifIndex = 0; ifIndex < iface_filter; ifIndex++)
        {

            if_index = if_nametoindex((const char*)iface_list[ifIndex]);
            if (if_index == 0)
            {
                debug_printf(DEBUG_NORMAL, " Error : iface_list %s does not existed in kernel\n", iface_list[ifIndex]);
                continue;
            }
            memset(if_name, 0, LLDP_IF_NAMESIZE);
            memcpy(if_name, (const char*)iface_list[ifIndex], strlen(iface_list[ifIndex])+1);
            //if(strncmp(if_name, (const char*)iface_list[ifIndex], IF_NAMESIZE) == 0) {
            //    break;
            //}
            
            //if (iface_filter == ifIndex)
            //{
            //    debug_printf(DEBUG_NORMAL, "Skipping interface %s (not in iface_list)\n", if_name);
            //    continue;
            //}
        

            /* Create our new interface struct */
            lldp_port = malloc(sizeof(struct lldp_port));
            memset(lldp_port, 0x0, sizeof(struct lldp_port));

            /* Add it to the global list */
            lldp_port->next = lldp_ports;

            lldp_port->if_index = if_index;
            lldp_port->if_name = malloc(LLDP_IF_NAMESIZE);
            if(lldp_port->if_name == NULL) {
                free(lldp_port);
                lldp_port = NULL;
                continue;
            }
            
            nb_ifaces++;
            memcpy(lldp_port->if_name, if_name, LLDP_IF_NAMESIZE);

            debug_printf(DEBUG_INT, "%s (index %d) found. Initializing...\n", lldp_port->if_name, lldp_port->if_index);

            // We want the first state to be LLDP_WAIT_PORT_OPERATIONAL, so we'll blank out everything here.
            lldp_port->portEnabled = 1;

            /* Initialize the socket for this interface */
            int ret;
            if (g_LLDP_TYPE == LLDP_TYPE_SHELFID)
            {
                ret = socketInitializeLLDP(lldp_port, 0x88CC);
            }
            else
            {
                ret = socketInitializeLLDP(lldp_port, 0x99a1);
            }
            if(ret != 0) {
                debug_printf(DEBUG_NORMAL, "[ERROR] Problem initializing socket for %s\n", lldp_port->if_name);
                free(lldp_port->if_name);
                lldp_port->if_name = NULL;
                free(lldp_port);
                lldp_port = NULL;
                continue;
            } else {
                debug_printf(DEBUG_EXCESSIVE, "Finished initializing socket for index %d with name %s\n", lldp_port->if_index, lldp_port->if_name);
            }
            if(g_LLDP_TYPE == LLDP_TYPE_SHELFID)
            {
                debug_printf(DEBUG_EXCESSIVE, "Initializing TX SM for index %d with name %s\n", lldp_port->if_index, lldp_port->if_name);
                lldp_port->tx.state = TX_LLDP_INITIALIZE;
                txInitializeLLDP(lldp_port);
                debug_printf(DEBUG_EXCESSIVE, "Initializing RX SM for index %d with name %s\n", lldp_port->if_index, lldp_port->if_name);
                lldp_port->rx.state = LLDP_WAIT_PORT_OPERATIONAL;
                rxInitializeLLDP(lldp_port);
                lldp_port->portEnabled  = 0;
                lldp_port->adminStatus  = enabledRxTx;

                debug_printf(DEBUG_EXCESSIVE, "Initializing TLV subsystem for index %d with name %s\n", lldp_port->if_index, lldp_port->if_name);
                /* Initialize the TLV subsystem for this interface */
                tlvInitializeLLDP(lldp_port);

                // Send out the first LLDP frame
                // This allows other devices to see us right when we come up, rather than 
                // having to wait for a full timer cycle
                txChangeToState(lldp_port, TX_IDLE);
                mibConstrInfoLLDPDU(lldp_port);
                txFrame(lldp_port);

                debug_printf(DEBUG_EXCESSIVE, "Adding index %d with name %s to global port list\n", lldp_port->if_index, lldp_port->if_name);
                /* Reset the global list to point at the top of the list */
                /* We only want to get here if initialization succeeded  */
               LLDP_SetPortValid((const char *)lldp_port->if_name , 1);
            }
            lldp_ports = lldp_port;

        }
    }

/*
    // When we quit, cleanup.
    signal(SIGTERM, cleanupLLDP);
    signal(SIGINT, cleanupLLDP);
    signal(SIGQUIT, cleanupLLDP);
    signal(SIGSEGV, handle_segfault);
    signal(SIGHUP, handle_hup);
*/
    return nb_ifaces;
}


int CreateOSCLLDP(lldp_osc_port_info_t* lldp_osc_port_info)
{
    char if_name[LLDP_IF_NAMESIZE];
    struct lldp_port *lldp_osc_port = NULL;

    /* Create our new interface struct */
    lldp_osc_port = malloc(sizeof(struct lldp_port));
    if(lldp_osc_port == NULL)
    {
        return 0;
    }

    memset(lldp_osc_port, 0x0, sizeof(struct lldp_port));

    /* Add it to the global list */
    lldp_osc_port->next = lldp_osc_ports;

    lldp_osc_port->if_name = malloc(LLDP_IF_NAMESIZE);
    if(lldp_osc_port->if_name == NULL)
    {
        free(lldp_osc_port);
        lldp_osc_port = NULL;
        return 0;
    }
    memset(lldp_osc_port->if_name, 0, LLDP_IF_NAMESIZE);
    strncpy(lldp_osc_port->if_name, (char *)lldp_osc_port_info->if_name, LLDP_IF_NAMESIZE);

    lldp_osc_port->shelf_id = lldp_osc_port_info->shelf_id;
    lldp_osc_port->slot_id = lldp_osc_port_info->slot_id;
    lldp_osc_port->port_id = lldp_osc_port_info->port_id;
    lldp_osc_port->if_index = lldp_osc_port_info->if_index;
    lldp_osc_port->source_mac[0] = lldp_osc_port_info->shelf_mac[0];
    lldp_osc_port->source_mac[1] = lldp_osc_port_info->shelf_mac[1];
    lldp_osc_port->source_mac[2] = lldp_osc_port_info->shelf_mac[2];
    lldp_osc_port->source_mac[3] = lldp_osc_port_info->shelf_mac[3];
    lldp_osc_port->source_mac[4] = lldp_osc_port_info->shelf_mac[4];
    lldp_osc_port->source_mac[5] = lldp_osc_port_info->shelf_mac[5];

    lldp_osc_port->chassis_id[0] = lldp_osc_port_info->chassis_id[0];
    lldp_osc_port->chassis_id[1] = lldp_osc_port_info->chassis_id[1];
    lldp_osc_port->chassis_id[2] = lldp_osc_port_info->chassis_id[2];
    lldp_osc_port->chassis_id[3] = lldp_osc_port_info->chassis_id[3];
    lldp_osc_port->chassis_id[4] = lldp_osc_port_info->chassis_id[4];
    lldp_osc_port->chassis_id[5] = lldp_osc_port_info->chassis_id[5];

    // We want the first state to be LLDP_WAIT_PORT_OPERATIONAL, so we'll blank out everything here.
    lldp_osc_port->portEnabled = 1;
    lldp_osc_port->socket = 0;
    if (lldp_ports != NULL)
    {
        lldp_osc_port->mtu = lldp_ports->mtu;
    }
    else
    {
        lldp_osc_port->mtu = 1500;
    }
    debug_printf(DEBUG_INT, "[%s] MTU is %d\n", lldp_osc_port->if_name, lldp_osc_port->mtu);
    lldp_osc_port->tx.frame = calloc(1, (lldp_osc_port->mtu - 2));
    if(!lldp_osc_port->tx.frame) {
        debug_printf(DEBUG_NORMAL, "[ERROR] Unable to malloc buffer in %s() at line: %d!\n", __FUNCTION__, __LINE__);
    } else {
        debug_printf(DEBUG_INT, "Created framebuffer for %s at %x\n", lldp_osc_port->if_name, &lldp_osc_port->tx.frame);
    }

    debug_printf(DEBUG_EXCESSIVE, "Initializing TX SM for index %d with name %s\n", lldp_osc_port->if_index, lldp_osc_port->if_name);
    lldp_osc_port->tx.state = TX_LLDP_INITIALIZE;
    txInitializeLLDP(lldp_osc_port);
    debug_printf(DEBUG_EXCESSIVE, "Initializing RX SM for index %d with name %s\n", lldp_osc_port->if_index, lldp_osc_port->if_name);
    lldp_osc_port->rx.state = LLDP_WAIT_PORT_OPERATIONAL;
    rxInitializeLLDP(lldp_osc_port);
    lldp_osc_port->portEnabled  = 0;
    debug_printf(DEBUG_EXCESSIVE, "Initializing TLV subsystem for index %d with name %s\n", lldp_osc_port->if_index, lldp_osc_port->if_name);
    /* Initialize the TLV subsystem for this interface */
    tlvInitializeLLDP(lldp_osc_port);

    if (lldp_osc_port_info->admin_status == 1)
    {
        lldp_osc_port->adminStatus  = enabledRxTx;
        // Send out the first LLDP frame
        // This allows other devices to see us right when we come up, rather than 
        // having to wait for a full timer cycle
        txChangeToState(lldp_osc_port, TX_IDLE);
        mibConstrInfoOSCLLDPDU(lldp_osc_port);
        if (lldp_ports != NULL)
        {
            txOscFrame(lldp_osc_port, lldp_ports);
        }
    }
    else
    {
        lldp_osc_port->adminStatus  = enabledRxOnly;
    }
    debug_printf(DEBUG_EXCESSIVE, "Adding index %d with name %s to global port list\n", lldp_osc_port->if_index, lldp_osc_port->if_name);
    /* Reset the global list to point at the top of the list */
    /* We only want to get here if initialization succeeded  */
    lldp_osc_ports = lldp_osc_port;

    return 1;
}



void deleteLLDP()
{
    cleanupLLDP();
}

void cleanupOscLLDPPort(const char * theIfName, char theRegular)
{
    struct lldp_port *lldp_port= NULL;

    if (g_LLDP_TYPE == LLDP_TYPE_SHELFID)
    {
        lldp_port= lldp_ports;
    }
    else if (g_LLDP_TYPE == LLDP_TYPE_MCN)
    {
        lldp_port = lldp_osc_ports;
        if(theIfName != NULL)
        {
            if (strncmp(theIfName, OSC_MGR, LLDP_IF_NAMESIZE) == 0)
            {
                lldp_port= lldp_ports;
            }
        }

    }

    struct lldp_port *prevPort = lldp_port;

    while(lldp_port != NULL)
    {
        if (0 == theRegular && NULL != theIfName)
        {
            if(strncmp(theIfName, (const char*)lldp_port->if_name, LLDP_IF_NAMESIZE) != 0)
            {
                prevPort = lldp_port;
                lldp_port = lldp_port->next;
                continue;
            }
        }
        
        
        lldp_port->msap_cache = NULL;

        if(lldp_port->if_name != NULL)
        {
            debug_printf(DEBUG_NORMAL, "[CLEAN] %s (%d)\n", lldp_port->if_name, lldp_port->if_index);
            tlvCleanupLLDP(lldp_port);
            socketCleanupLLDP(lldp_port);
        }
        else
        {
            debug_printf(DEBUG_NORMAL, "[ERROR] Interface index %d with name is NULL at: %s():%d\n", lldp_port->if_index, __FUNCTION__, __LINE__);
        }


        // Clean the previous node and move up.
        if (0 == theRegular)
        {
            prevPort->next = lldp_port->next;
            if(lldp_port == lldp_ports)
            {
                lldp_ports = lldp_port->next;
            }
            else if(lldp_port == lldp_osc_ports)
            {
                lldp_osc_ports = lldp_port->next;
            }
            free(lldp_port);
            break;
        }
        else
        {
            lldp_port = lldp_port->next;
            if (g_LLDP_TYPE == LLDP_TYPE_SHELFID)
            {
                free(lldp_ports);
                lldp_ports = lldp_port;
            }
            else if (g_LLDP_TYPE == LLDP_TYPE_MCN)
            {
                if(theIfName != NULL && (strncmp(theIfName, OSC_MGR, LLDP_IF_NAMESIZE) == 0))
                {
                    free(lldp_ports);
                    lldp_ports = lldp_port;
                }
                else
                {
                    free(lldp_osc_ports);
                    lldp_osc_ports = lldp_port;
                }
            }
        }
    }
}





void cleanupLLDPPort(const char * theIfName, char theRegular)
{
    struct lldp_port *lldp_port= NULL;
    struct lldp_msap *msap_cache = NULL;

    if (g_LLDP_TYPE == LLDP_TYPE_SHELFID)
    {
        lldp_port= lldp_ports;
    }
    else if (g_LLDP_TYPE == LLDP_TYPE_MCN)
    {
        lldp_port = lldp_osc_ports;
        if(theIfName != NULL)
        {
            if (strncmp(theIfName, OSC_MGR, LLDP_IF_NAMESIZE) == 0)
            {
                lldp_port= lldp_ports;
            }
        }

    }

    struct lldp_port *prevPort = lldp_port;

    while(lldp_port != NULL)
    {
        if (0 == theRegular && NULL != theIfName)
        {
            if(strncmp(theIfName, (const char*)lldp_port->if_name, LLDP_IF_NAMESIZE) != 0)
            {
                prevPort = lldp_port;
                lldp_port = lldp_port->next;
                continue;
            }
        }
        
        {
            msap_cache = lldp_port->msap_cache;

            while(msap_cache != NULL)
            {
                if(msap_cache->tlv_list != NULL) 
                {
                    destroy_tlv_list(&msap_cache->tlv_list);
                }

                if(msap_cache->id != NULL) 
                    free(msap_cache->id);
                msap_cache = msap_cache->next;
            }
            if(lldp_port->msap_cache != NULL)
                free(lldp_port->msap_cache);
        }
        lldp_port->msap_cache = NULL;

        if(lldp_port->if_name != NULL)
        {
            debug_printf(DEBUG_NORMAL, "[CLEAN] %s (%d)\n", lldp_port->if_name, lldp_port->if_index);
            tlvCleanupLLDP(lldp_port);
            socketCleanupLLDP(lldp_port);
        }
        else
        {
            debug_printf(DEBUG_NORMAL, "[ERROR] Interface index %d with name is NULL at: %s():%d\n", lldp_port->if_index, __FUNCTION__, __LINE__);
        }


        // Clean the previous node and move up.
        if (0 == theRegular)
        {
            prevPort->next = lldp_port->next;
            if(lldp_port == lldp_ports)
            {
                lldp_ports = lldp_port->next;
            }
            else if(lldp_port == lldp_osc_ports)
            {
                lldp_osc_ports = lldp_port->next;
            }
            free(lldp_port);
            break;
        }
        else
        {
            lldp_port = lldp_port->next;
            if (g_LLDP_TYPE == LLDP_TYPE_SHELFID)
            {
                free(lldp_ports);
                lldp_ports = lldp_port;
            }
            else if (g_LLDP_TYPE == LLDP_TYPE_MCN)
            {
                if(theIfName != NULL && (strncmp(theIfName, OSC_MGR, LLDP_IF_NAMESIZE) == 0))
                {
                    free(lldp_ports);
                    lldp_ports = lldp_port;
                }
                else
                {
                    free(lldp_osc_ports);
                    lldp_osc_ports = lldp_port;
                }
            }
        }
    }
}
void cleanupLLDP() {
    while(!queue_empty(g_DbMsgQueue))
    {
        item_t* aItem;
        queue_dequeue(g_DbMsgQueue, &aItem);
        lldp_port_db_msg_t* lldp_db_msg = (lldp_port_db_msg_t*)aItem->statellite;
        /*
        if (lldp_db_msg->mgt_addr_tlv != NULL)
        {
            free(lldp_db_msg->mgt_addr_tlv->info_string);
            free(lldp_db_msg->mgt_addr_tlv);
        }
        */
        free(aItem->statellite);
        free(aItem);
    }
    queue_free(g_DbMsgQueue);

    debug_printf(DEBUG_NORMAL, "cleanupLLDP!\n");
    cleanupLLDPPort(NULL, 1);
    if(g_LLDP_TYPE == LLDP_TYPE_MCN)
    {
        cleanupLLDPPort(OSC_MGR, 1);
    }
    //if(neighbor_local_sd > 0)
      //close(neighbor_local_sd);
    //unlink(local.sun_path);

    #ifdef USE_CONFUSE
    if(cfg != NULL)
      cfg_free(cfg);
    #endif

    //exit(0);
}

/****************************************
 *
 * Display our usage information.
 *
 ****************************************/
void usage()
{
    debug_printf(DEBUG_EXCESSIVE, "Entering %s():%d\n", __FUNCTION__, __LINE__);

    debug_printf(DEBUG_NORMAL, "\nlldpd 0.4\n");
    debug_printf(DEBUG_NORMAL, "(c) Copyright 2002 - 2007 The OpenLLDP Group\n");
    debug_printf(DEBUG_NORMAL, "Licensed under the BSD license."
            "\n\n");
    debug_printf(DEBUG_NORMAL, "This product borrows some code from the Open1X project"
            ". (http://www.open1x.org)\n\n");
    debug_printf(DEBUG_NORMAL, "Usage: %s "
            "[-i <device>] "
            "[-d <debug_level>] "
	    "[-l <med location file>]"
            "[-f] "
            "[-s] "
	    "[-o] "
            "\n", program);

    debug_printf(DEBUG_NORMAL, "\n\n");
    debug_printf(DEBUG_NORMAL, "-i <interface> : Use <interface> for LLDP transactions"
            "\n");
    debug_printf(DEBUG_NORMAL, "-d <debug_level/flags> : Set debug verbosity."
            "\n");
    debug_printf(DEBUG_NORMAL, "-l <file> : LLDP-MED Location Identification Configuration File.\n");
    debug_printf(DEBUG_NORMAL, "-f : Run in forground mode.\n");
    debug_printf(DEBUG_NORMAL, "-s : Remove the existing control socket if found.  (Should only be used in system init scripts!)\n");
    debug_printf(DEBUG_NORMAL, "-o : Process LLDP frames on the loopback interface (mainly for testing)\n");
    debug_printf(DEBUG_NORMAL, "\n\n");

    debug_printf(DEBUG_NORMAL, " <debug_level> can be any of : \n");
    debug_printf(DEBUG_NORMAL, "\tA : Enable ALL debug flags.\n");
    debug_printf(DEBUG_NORMAL, "\tc : Enable CONFIG debug flag.\n");
    debug_printf(DEBUG_NORMAL, "\ts : Enable STATE debug flag.\n");
    debug_printf(DEBUG_NORMAL, "\tt : Enable TLV debug flag.\n");
    debug_printf(DEBUG_NORMAL, "\tm : Enable MSAP debug flag.\n");
    debug_printf(DEBUG_NORMAL, "\ti : Enable INT debug flag.\n");
    debug_printf(DEBUG_NORMAL, "\tn : Enable SNMP debug flag.\n");
    debug_printf(DEBUG_NORMAL, "\tx : Enable EXCESSIVE debug flag.\n");
}


#ifdef USE_CONFUSE
/****************************************
 *
 * LCI Location Configuration Information - read from config file
 *
 ****************************************/
void
lci_config()
{
  static int first = 1;
  int j;

  if (first)
    {
      first = 0;
      if (lci.config_file == NULL)
	lci.config_file = "lldp.conf";
    }
  else
    cfg_free(cfg);//free cfg before reading new configuration!
  
  debug_printf (DEBUG_NORMAL, "Using config file %s\n", lci.config_file);
  
  lci.coordinate_based_lci = NULL;
  lci.location_data_format = -1;  //location identification TLV is not created when location_data_format is set to -1. If location_data_format is not found in the location config or no location config file exists, no location identification TLV will be created!
  lci.civic_what = 1;
  lci.civic_countrycode = NULL;
  lci.elin = NULL;

  cfg_opt_t opts[] = {
    CFG_SIMPLE_INT ("location_data_format", &lci.location_data_format),
    CFG_SIMPLE_STR ("coordinate_based_lci", &lci.coordinate_based_lci),
    CFG_SIMPLE_INT ("civic_what", &lci.civic_what),
    CFG_SIMPLE_STR ("civic_countrycode", &lci.civic_countrycode),
    CFG_SIMPLE_STR ("elin", &lci.elin),
    CFG_SIMPLE_STR ("civic_ca0", &lci.civic_ca[0]),//CA Type 0 is language
    CFG_SIMPLE_STR ("civic_ca1", &lci.civic_ca[1]),
    CFG_SIMPLE_STR ("civic_ca2", &lci.civic_ca[2]),
    CFG_SIMPLE_STR ("civic_ca3", &lci.civic_ca[3]),
    CFG_SIMPLE_STR ("civic_ca4", &lci.civic_ca[4]),
    CFG_SIMPLE_STR ("civic_ca5", &lci.civic_ca[5]),
    CFG_SIMPLE_STR ("civic_ca6", &lci.civic_ca[6]),
    CFG_SIMPLE_STR ("civic_ca7", &lci.civic_ca[7]),
    CFG_SIMPLE_STR ("civic_ca8", &lci.civic_ca[8]),
    CFG_SIMPLE_STR ("civic_ca9", &lci.civic_ca[9]),
    CFG_SIMPLE_STR ("civic_ca10", &lci.civic_ca[10]),
    CFG_SIMPLE_STR ("civic_ca11", &lci.civic_ca[11]),
    CFG_SIMPLE_STR ("civic_ca12", &lci.civic_ca[12]),
    CFG_SIMPLE_STR ("civic_ca13", &lci.civic_ca[13]),
    CFG_SIMPLE_STR ("civic_ca14", &lci.civic_ca[14]),
    CFG_SIMPLE_STR ("civic_ca15", &lci.civic_ca[15]),
    CFG_SIMPLE_STR ("civic_ca16", &lci.civic_ca[16]),
    CFG_SIMPLE_STR ("civic_ca17", &lci.civic_ca[17]),
    CFG_SIMPLE_STR ("civic_ca18", &lci.civic_ca[18]),
    CFG_SIMPLE_STR ("civic_ca19", &lci.civic_ca[19]),
    CFG_SIMPLE_STR ("civic_ca20", &lci.civic_ca[20]),
    CFG_SIMPLE_STR ("civic_ca21", &lci.civic_ca[21]),
    CFG_SIMPLE_STR ("civic_ca22", &lci.civic_ca[22]),
    CFG_SIMPLE_STR ("civic_ca23", &lci.civic_ca[23]),
    CFG_SIMPLE_STR ("civic_ca24", &lci.civic_ca[24]),
    CFG_SIMPLE_STR ("civic_ca25", &lci.civic_ca[25]),
    CFG_SIMPLE_STR ("civic_ca26", &lci.civic_ca[26]),
    CFG_SIMPLE_STR ("civic_ca27", &lci.civic_ca[27]),
    CFG_SIMPLE_STR ("civic_ca28", &lci.civic_ca[28]),
    CFG_SIMPLE_STR ("civic_ca29", &lci.civic_ca[29]),
    CFG_SIMPLE_STR ("civic_ca30", &lci.civic_ca[30]),
    CFG_SIMPLE_STR ("civic_ca31", &lci.civic_ca[31]),
    CFG_SIMPLE_STR ("civic_ca32", &lci.civic_ca[32]),
    
    CFG_END ()
  };
  
  //set all civic location elements to NULL in case not defined in config
  for (j = 0; j < 33; j++)
    {
      lci.civic_ca[j] = NULL;
    }
  
  //read config file for location information configuration
  cfg = cfg_init(opts, 0);
  cfg_parse(cfg, lci.config_file);
  
  /*
    if (lci.location_data_format = 2)
    for (j = 0; j < 33; j++)
    {
    if(strlen (lci.civic_ca[j]) > 255 )
    {
    debug_printf(DEBUG_NORMAL, "[ERROR] invalid civic location: CAType %i is too long!\n", j);
    lci.location_data_format = -1;
    }
    }
*/
}
#endif // USE_CONFUSE

