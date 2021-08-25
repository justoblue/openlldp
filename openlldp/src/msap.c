/** @file msap.c
  OpenLLDP MSAP Cache

  See LICENSE file for more info.

Authors: Terry Simons (terry.simons@gmail.com)
*/

#ifndef WIN32
#include <stdint.h>
#else
#include "stdintwin.h"
#endif // WIN32

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "msap.h"
#include "tlv_common.h"
#include "lldp_debug.h"

#ifdef __LEAK_DETECTOR__
#include "leak_detector_c.h"
#endif
struct lldp_msap *create_msap(struct lldp_tlv *tlv1, struct lldp_tlv *tlv2) {
	return NULL;
}

void iterate_msap_cache(struct lldp_msap *msap_cache){
  while(msap_cache != NULL) {
    debug_printf(DEBUG_MSAP, "MSAP cache: %X\n", msap_cache);

    debug_printf(DEBUG_MSAP, "MSAP ID: ");
    debug_hex_printf(DEBUG_MSAP, msap_cache->id, msap_cache->length);
    
    debug_printf(DEBUG_MSAP, "MSAP Length: %X\n", msap_cache->length);

    debug_printf(DEBUG_MSAP, "MSAP Next: %X\n", msap_cache->next);

    msap_cache = msap_cache->next;
  }
}

uint8_t rx_get_remote_index(struct lldp_port *lldp_port) {
    uint8_t index = 0;
    for (index = 0; index < ORLLDP_MAX_NEIGHBORS_PERPORT; index++)
    {
        if (lldp_port->rx.remoteIndexArray[index] == 0)
        {
            lldp_port->rx.remoteIndexArray[index] = 1;
            break;
        }
    }
    return index;
}

uint8_t update_msap_cache(struct lldp_port *lldp_port, struct lldp_msap* msap_cache) {
    struct lldp_msap *old_cache = lldp_port->msap_cache;
    struct lldp_msap *new_cache = msap_cache;
    uint8_t badFrame = 0;

    while(old_cache != NULL)
    {

        if(old_cache->length == new_cache->length) 
        {
            debug_printf(DEBUG_MSAP, "MSAP Length: %X\n", old_cache->length);

            if(memcmp(old_cache->id, new_cache->id, new_cache->length) == 0) 
            {
                debug_printf(DEBUG_MSAP, "MSAP Cache Hit on %s\n", lldp_port->if_name);
                iterate_msap_cache(msap_cache);
#ifndef WIN32
        //#warning This is leaking, but I can't figure out why it's crashing when uncommented.
#endif
                if (new_cache->rxInfoTTL != 0)
                {
                    destroy_tlv_list(&old_cache->tlv_list);
                    
                    old_cache->tlv_list = new_cache->tlv_list;
                    old_cache->rxInfoTTL = new_cache->rxInfoTTL;
                    old_cache->isChanged = 1;
                    // Now free the rest of the MSAP cache
                    free(new_cache->id);
                    free(new_cache);
                    lldp_port->rx.rxFrameType = ORLLDP_RX_FRAME_UPDATE;

                }
                else
                {
                    old_cache->rxInfoTTL = new_cache->rxInfoTTL;
                    lldp_port->rx.rxFrameType = ORLLDP_RX_FRAME_SHUTDOWN;
                }
                return 0;
            }
        }
        debug_printf(DEBUG_MSAP, "Checking next MSAP entry...\n");

        old_cache = old_cache->next;
    }
    if (lldp_port->rx.tooManyNeighbors < ORLLDP_MAX_NEIGHBORS_PERPORT)
    {
        debug_printf(DEBUG_MSAP, "MSAP Cache Miss on %s\n", lldp_port->if_name);

        new_cache->next = lldp_port->msap_cache;
        lldp_port->msap_cache = new_cache;
        lldp_port->msap_cache->isChanged = 1;
        lldp_port->msap_cache->remoteIndexMsap = rx_get_remote_index(lldp_port);
        lldp_port->rx.tooManyNeighbors++;
        lldp_port->rx.rxFrameType = ORLLDP_RX_FRAME_NEW;
    }
    else
    {
        debug_printf(DEBUG_MSAP, "%s has too many Neighbors\n", lldp_port->if_name);
        destroy_tlv_list(&new_cache->tlv_list);
        free(new_cache->id);
        free(new_cache);
        badFrame = 1;
    }
    return badFrame;
#ifndef WIN32
//#warning We are leaking memory... need to dispose of the msap_cache under certain circumstances :/
#endif // WIN32
}
