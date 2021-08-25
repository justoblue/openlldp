/** @file rx_sm.c
  OpenLLDP RX Statemachine

  See LICENSE file for more info.

Authors: Terry Simons (terry.simons@gmail.com)
*/

#ifndef WIN32
#include <arpa/inet.h>
#include <strings.h>
#else // WIN32
#include <Winsock2.h>
//#define strncpy _strncpy
#endif // WIN32

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "rx_sm.h"
#include "lldp_port.h"
#include "tlv.h"
#include "tlv_common.h"
#include "msap.h"
#include "lldp_debug.h"
#include "lldp_api.h"
#include "OrQueue.h"

extern queue_t* g_DbMsgQueue;



#ifdef __LEAK_DETECTOR__
#include "leak_detector_c.h"
#endif

#define FALSE 0
#define TRUE 1

extern const uint8_t LLDP_TYPE_MCN;
extern uint8_t g_LLDP_TYPE;

extern uint8_t g_use_dstMac;

/* This is an 802.1AB per-port variable, 
   so it should go in the port structure */
uint8_t badFrame;

/* Defined by the IEEE 802.1AB standard */
uint8_t rxInitializeLLDP(struct lldp_port *lldp_port) {
    /* As per IEEE 802.1AB section 10.5.5.3 */
    lldp_port->rx.rcvFrame        = 0;
    memset(lldp_port->rx.pduMsgDigest, 0 , MD5_MAX_KEY_LENGTH);
    /* As per IEEE 802.1AB section 10.1.2 */
    lldp_port->rx.tooManyNeighbors = 0;

    lldp_port->rx.rxInfoAge = 0;

    memset(lldp_port->rx.remoteIndexArray, 0, ORLLDP_MAX_NEIGHBORS_PERPORT);

    mibCLeanupObjects(lldp_port);

    lldp_port->rx.rxFrameType = ORLLDP_RX_FRAME_INVALID;


    return 0;
}

struct lldp_port * rxHandleFrame(uint8_t *rxFrame, struct lldp_port *lldp_port)
{
    if (rxFrame == NULL || lldp_port == NULL)
    {
        return NULL;
    }
    uint8_t badFrame = 0;
    struct eth_infn_hdr expect_hdr;
    struct eth_infn_hdr *ether_hdr;
    //ether_hdr = (struct eth_infn_hdr *)&lldp_port->rx.frame[0];
    ether_hdr = (struct eth_infn_hdr *)rxFrame;

    expect_hdr.infntag[0] = 0x0e;

    //debug_hex_printf(DEBUG_NORMAL, (uint8_t *)ether_hdr->dst, sizeof(struct eth_infn_hdr));

    if(ether_hdr->infntag[0] != expect_hdr.infntag[0]) {
        
        debug_printf(DEBUG_NORMAL, "[ERROR] This frame has an incorrect infinera tag: '%x'.\n", ether_hdr->infntag[0]);
        return NULL;
    }

    expect_hdr.dst[0] = 0xef;
    expect_hdr.dst[1] = 0xef;
    expect_hdr.dst[2] = 0x01;
    expect_hdr.dst[3] = 0x00;
    expect_hdr.dst[4] = 0x00;
    expect_hdr.dst[5] = 0x00;

    expect_hdr.infntype = htons(0x99a1);
    expect_hdr.ethertype = htons(0x88cc);

    if (g_use_dstMac == 0)
    {
        /* Validate the frame's destination */
        if(
                ether_hdr->dst[0] != expect_hdr.dst[0] ||
                ether_hdr->dst[1] != expect_hdr.dst[1] ||
                ether_hdr->dst[2] != expect_hdr.dst[2] ||
                ether_hdr->dst[3] != expect_hdr.dst[3] ||
                ether_hdr->dst[4] != expect_hdr.dst[4] ||
                ether_hdr->dst[5] != expect_hdr.dst[5] ) {

            debug_printf(DEBUG_NORMAL, "[ERROR] This frame is incorrectly addressed to: ");
            debug_hex_printf(DEBUG_NORMAL, (uint8_t *)ether_hdr->dst, sizeof(struct eth_infn_hdr));
            debug_printf(DEBUG_NORMAL, "[ERROR] This frame should be addressed to: ");
            debug_hex_printf(DEBUG_NORMAL, (uint8_t *)expect_hdr.dst, sizeof(struct eth_infn_hdr));
            debug_printf(DEBUG_NORMAL, "[ERROR] statsFramesInTotal will *NOT* be incremented\n");

            badFrame++;
        }
    }
    if(ether_hdr->infntype != expect_hdr.infntype) {
        debug_printf(DEBUG_NORMAL, "[ERROR] This frame has an incorrect infntype of: '%x'.\n", htons(ether_hdr->infntype));

        badFrame++;
    }

    if(ether_hdr->ethertype != expect_hdr.ethertype) {
        debug_printf(DEBUG_NORMAL, "[ERROR] This frame has an incorrect ethertype of: '%x'.\n", htons(ether_hdr->ethertype));

        badFrame++;
    }


    if (0 == badFrame)
    {
        while(lldp_port != NULL)
        {
            if (lldp_port->tx.frame != NULL &&
                ether_hdr->infntag[1] == lldp_port->shelf_id &&
                ether_hdr->infntag[2] == lldp_port->slot_id &&
                ether_hdr->infntag[3] == lldp_port->port_id)
            {
                debug_printf(DEBUG_NORMAL,"rxHandleFrame find port:%s\n", lldp_port->if_name);
                lldp_port->rx.frame = rxFrame;
                break;
            }
            lldp_port = lldp_port->next;
        }
    }
    else
    {
        return NULL;

    }
    return lldp_port;
}



/* Defined by the IEEE 802.1AB standard */
int rxProcessFrame(struct lldp_port *lldp_port) {
    /* 802.1AB Variables */
    uint8_t badFrame = 0;
    /* End 802.1AB Variables */

    /* Keep track of the last TLV so we can adhere to the specification */
    /* Which requires the first 3 TLVs to be in the correct order       */
    uint16_t last_tlv_type = 0;
    uint16_t num_tlvs      = 0;
    uint8_t tlv_type       = 0;
    uint16_t tlv_length    = 0;
    uint16_t tlv_offset    = 0;
    uint16_t tlv_infn_offset    = 0;

    struct eth_hdr *ether_hdr;
    struct eth_hdr expect_hdr;

	// The current TLV and respective helper variables
	struct lldp_tlv *tlv     = NULL;
	uint16_t *tlv_hdr        = NULL;
	uint16_t debug_offset    = 0;
	uint8_t *tlv_info_string = NULL;

	// The TLV to be cached for this frame's MSAP
	struct lldp_tlv *cached_tlv = NULL;

    /* The IEEE 802.1AB MSAP is made up of the TLV information string from */
    /* TLV 1 and TLV 2. */
    uint8_t *msap_id           = NULL;
    uint32_t msap_length       = 0;
    uint8_t have_msap          = 0;
    struct lldp_tlv *msap_tlv1 = NULL;
    struct lldp_tlv *msap_tlv2 = NULL;
    //struct lldp_tlv *msap_ttl_tlv = NULL;

    /* The TLV list for this frame */
    /* This list will be added to the MSAP cache */
    struct lldp_tlv_list *tlv_list = NULL;

    /* The MSAP cache for this frame */
    struct lldp_msap *msap_cache = NULL;

	// Variables for location based LLDP-MED TLV
	char *elin   = NULL;
	int calength = 0;
	int catype   = 0;

    debug_printf(DEBUG_INT, "(%s) Processing Frame: \n", lldp_port->if_name);
    if (NULL == lldp_port->rx.frame)
    {
            debug_printf(DEBUG_NORMAL, "[ERROR] lldp_port->rx.frame is NULL!");
            badFrame++;
            return badFrame;
    }
    debug_hex_dump(DEBUG_INT, lldp_port->rx.frame, lldp_port->rx.recvsize);

    if (g_LLDP_TYPE != LLDP_TYPE_MCN)
    {
        ether_hdr = (struct eth_hdr *)&lldp_port->rx.frame[0];
        /* As per section 10.3.1, verify the destination and ethertype */

        expect_hdr.dst[0] = 0x01;
        expect_hdr.dst[1] = 0x80;
        expect_hdr.dst[2] = 0xc2;
        expect_hdr.dst[3] = 0x00;
        expect_hdr.dst[4] = 0x00;
        expect_hdr.dst[5] = 0x0e;

        expect_hdr.ethertype = htons(0x88cc);

        debug_printf(DEBUG_INT, "LLPDU Dst: ");
        debug_hex_printf(DEBUG_INT, (uint8_t *)ether_hdr->dst, 6);

        debug_printf(DEBUG_EXCESSIVE, "Expect Dst: ");
        debug_hex_printf(DEBUG_EXCESSIVE, (uint8_t *)expect_hdr.dst, 6);
        if (g_use_dstMac == 0)
        {
            /* Validate the frame's destination */
            if(
                    ether_hdr->dst[0] != expect_hdr.dst[0] ||
                    ether_hdr->dst[1] != expect_hdr.dst[1] ||
                    ether_hdr->dst[2] != expect_hdr.dst[2] ||
                    ether_hdr->dst[3] != expect_hdr.dst[3] ||
                    ether_hdr->dst[4] != expect_hdr.dst[4] ||
                    ether_hdr->dst[5] != expect_hdr.dst[5] ) {

                debug_printf(DEBUG_NORMAL, "[ERROR] This frame is incorrectly addressed to: ");
                debug_hex_printf(DEBUG_NORMAL, (uint8_t *)ether_hdr->dst, 6);
                debug_printf(DEBUG_NORMAL, "[ERROR] This frame should be addressed to: ");
                debug_hex_printf(DEBUG_NORMAL, (uint8_t *)expect_hdr.dst, 6);
                debug_printf(DEBUG_NORMAL, "[ERROR] statsFramesInTotal will *NOT* be incremented\n");

                badFrame++;
            }
        }
        debug_printf(DEBUG_INT, "LLPDU Src: ");
        debug_hex_printf(DEBUG_INT, (uint8_t *)ether_hdr->src, 6);

        debug_printf(DEBUG_INT, "LLPDU Ethertype: %x\n", htons(ether_hdr->ethertype));

        debug_printf(DEBUG_EXCESSIVE, "Expect Ethertype: %x\n", htons(expect_hdr.ethertype));

        /* Validate the frame's ethertype */
        if(ether_hdr->ethertype != expect_hdr.ethertype) {
            debug_printf(DEBUG_NORMAL, "[ERROR] This frame has an incorrect ethertype of: '%x'.\n", htons(ether_hdr->ethertype));

            badFrame++;
        }

        if(badFrame > 0)
        {
            return badFrame;
        }
    }
    else
    {
        tlv_infn_offset = sizeof(struct eth_infn_hdr) - sizeof(struct eth_hdr);
    }
    lldp_port->rx.statistics.statsFramesInTotal++;

    do 
    {
        num_tlvs++;
        debug_printf(DEBUG_TLV, "Processing TLV #: %d\n", num_tlvs);
        if(tlv_offset > (lldp_port->rx.recvsize - sizeof(struct eth_hdr) - tlv_infn_offset - sizeof(uint16_t)) ||
            tlv_offset > (lldp_port->mtu - sizeof(struct eth_hdr) - tlv_infn_offset - sizeof(uint16_t)) )
        {
            debug_printf(DEBUG_NORMAL, "[ERROR] Offset is larger than received frame!");
            badFrame++;
            break;
        }
        tlv_hdr = (uint16_t *)&lldp_port->rx.frame[sizeof(struct eth_hdr) + tlv_infn_offset + tlv_offset];
        if (NULL == tlv_hdr)
        {
            debug_printf(DEBUG_NORMAL, "[ERROR] tlv_hdr is NULL!");
            badFrame++;
            break;
        }
        /* Grab the first 9 bits */
        tlv_length = htons(*tlv_hdr) & 0x01FF;

        /* Then shift to get the last 7 bits */
        tlv_type = htons(*tlv_hdr) >> 9;

        /* Validate as per 802.1AB section 10.3.2*/
        if(num_tlvs <= 3) {
            if(num_tlvs != tlv_type) {
                debug_printf(DEBUG_NORMAL, "[ERROR] TLV number %d should have tlv_type %d, but is actually %d\n", num_tlvs, num_tlvs, tlv_type);
                debug_printf(DEBUG_NORMAL, "[ERROR] statsFramesDiscardedTotal and statsFramesInErrorsTotal will be incremented as per 802.1AB 10.3.2\n");
                lldp_port->rx.statistics.statsFramesDiscardedTotal++;
                lldp_port->rx.statistics.statsFramesInErrorsTotal++;
                badFrame++;        
                break;
            }
        }

        debug_printf(DEBUG_EXCESSIVE, "TLV type: %d (%s)  Length: %d\n", tlv_type, tlv_typetoname(tlv_type), tlv_length);

        /* Create a compound offset */
        debug_offset = tlv_length + sizeof(struct eth_hdr) + tlv_infn_offset + tlv_offset + sizeof(*tlv_hdr);

        /* The TLV is telling us to index off the end of the frame... tisk tisk */
        if(debug_offset > lldp_port->rx.recvsize) {
            debug_printf(DEBUG_NORMAL, "[ERROR] Received a bad TLV:  %d bytes too long!  Frame will be skipped.\n", debug_offset - lldp_port->rx.recvsize);
            badFrame++;
            break;
        } 
        else 
        {
            /* Temporary Debug to validate above... */
            debug_printf(DEBUG_EXCESSIVE, "TLV would read to: %d, Frame ends at: %d\n", debug_offset, lldp_port->rx.recvsize);
        }

        tlv_info_string = (uint8_t *)&lldp_port->rx.frame[sizeof(struct eth_hdr) + tlv_infn_offset + sizeof(*tlv_hdr) + tlv_offset];

        tlv = initialize_tlv();

        if(!tlv) {
            debug_printf(DEBUG_NORMAL, "[ERROR] Unable to malloc buffer in %s() at line: %d!\n", __FUNCTION__, __LINE__);
            badFrame++;
            break;
        }

        tlv->type        = tlv_type;
        tlv->length      = tlv_length;
        if(tlv->length > 0)
            tlv->info_string = calloc(1, tlv_length);

    // XXX Hmmm is this right?
        if(tlv_type == TIME_TO_LIVE_TLV) 
        {
            if(tlv_length != 2) 
            {
                debug_printf(DEBUG_NORMAL, "[ERROR] TTL TLV has an invalid length!  Should be '2', but is '%d'\n", tlv_length);             
                badFrame++;
                break;
            } 
            else 
            {
                lldp_port->rx.timers.rxTTL = htons(*(uint16_t *)&tlv_info_string[0]);
                //msap_ttl_tlv = tlv;
                debug_printf(DEBUG_EXCESSIVE, "rxTTL is: %d\n", lldp_port->rx.timers.rxTTL);
            }
        }

        if(tlv->info_string) 
        {
            memset(tlv->info_string, 0x0, tlv_length);
            memcpy(tlv->info_string, tlv_info_string, tlv_length);
        } 

        /* Validate the TLV */
        if(validate_tlv[tlv_type] != NULL) 
        {
            debug_printf(DEBUG_EXCESSIVE, "Found a validator for TLV type %d.\n", tlv_type);

            debug_hex_dump(DEBUG_EXCESSIVE, tlv->info_string, tlv->length);

            if(validate_tlv[tlv_type](tlv) != XVALIDTLV) 
            {
                badFrame++;
                break;
            }
        } 
        else 
        {
            // NOTE: Any organizationally specific TLVs should get processed through validate_generic_tlv
            debug_printf(DEBUG_EXCESSIVE, "Didn't find specific validator for TLV type %d.  Using validate_generic_tlv.\n", tlv_type);
            if(validate_generic_tlv(tlv) != XVALIDTLV) 
            {
                badFrame++;
                break;
            }
        }

        cached_tlv = initialize_tlv();

        if(tlvcpy(cached_tlv, tlv) != 0)
        {
            if(tlv->length > 0)
            {
                debug_printf(DEBUG_TLV, "Error copying TLV for MSAP cache!\n");
                badFrame++;
                break;
            }
            else
            {
                debug_printf(DEBUG_TLV, "the failing of tlvcpy is not an issue since it's an end tlv !\n");
            }
        } 

        debug_printf(DEBUG_EXCESSIVE, "Adding exploded TLV to MSAP TLV list.\n");
        // Now we can start stuffing the msap data... ;)
        add_tlv(cached_tlv, &tlv_list);

        debug_printf(DEBUG_EXCESSIVE, "Done\n");

        /* Store the MSAP elements */
        if(tlv_type == CHASSIS_ID_TLV) 
        {
            debug_printf(DEBUG_NORMAL, "Copying TLV1 for MSAP Processing...\n");
            msap_tlv1 = initialize_tlv();
            tlvcpy(msap_tlv1, tlv);
        } 
        else if(tlv_type == PORT_ID_TLV) 
        {
          debug_printf(DEBUG_NORMAL, "Copying TLV2 for MSAP Processing...\n");
          msap_tlv2 = initialize_tlv();
          tlvcpy(msap_tlv2, tlv);     
          //Minus 2, for the chassis id subtype and port id subtype... 
          // IEEE 802.1AB specifies that the MSAP shall be composed of 
          // The value of the subtypes. 
          msap_id = calloc(1, msap_tlv1->length - 1  + msap_tlv2->length - 1);

          if(msap_id == NULL)
          {
              debug_printf(DEBUG_NORMAL, "[ERROR] Unable to malloc buffer in %s() at line: %d!\n", __FUNCTION__, __LINE__);
              badFrame++;
              break;
          }
          
          // Copy the first part of the MSAP 
          memcpy(msap_id, &msap_tlv1->info_string[1], msap_tlv1->length - 1);
          
          // Copy the second part of the MSAP 
          memcpy(&msap_id[msap_tlv1->length - 1], &msap_tlv2->info_string[1], msap_tlv2->length - 1);
          
          msap_length = (msap_tlv1->length - 1) + (msap_tlv2->length - 1);
          
          debug_printf(DEBUG_MSAP, "MSAP TLV1 Length: %d\n", msap_tlv1->length);
          debug_printf(DEBUG_MSAP, "MSAP TLV2 Length: %d\n", msap_tlv2->length);
          
          debug_printf(DEBUG_MSAP, "MSAP is %d bytes: ", msap_length);
          debug_hex_printf(DEBUG_MSAP, msap_id, msap_length);
          debug_hex_dump(DEBUG_MSAP, msap_id, msap_length);

          // Free the MSAP pieces
          destroy_tlv(&msap_tlv1);
          destroy_tlv(&msap_tlv2);
          
          msap_tlv1 = NULL;
          msap_tlv2 = NULL;
          have_msap = 1;
      }

        //************************************
        //LLDP-MED location identification TLV
        //************************************
        if (tlv_type == ORG_SPECIFIC_TLV)
        {
            int i, j, lcilength;
            //check TIA OUI
            if ((tlv->info_string[0] == 0x00) && (tlv->info_string[1] == 0x12)
                && (tlv->info_string[2] == 0xBB))
            {
                //debug_printf (DEBUG_NORMAL, "TIA found\n");
                if (tlv->info_string[3] == 3)
                {

                    debug_printf (DEBUG_NORMAL,
                    "TIA Location Identification found\n");

                    switch (tlv->info_string[4])
                    {

                        case 0:
                            debug_printf (DEBUG_NORMAL,
                            "Invalid Location data format type! \n");
                            break;
                        case 1:
                            debug_printf (DEBUG_NORMAL, "Coordinate-based LCI\n",
                            tlv->length);
                            //encoded location starts at 5
                            for (i = 5; i < 16 + 5; i++)
                            {
                            debug_printf (DEBUG_NORMAL, "%02x",
                            tlv->info_string[i]);
                            }
                            debug_printf (DEBUG_NORMAL, "\n");
                            break;
                        case 2:
                            i = 9;//start of first CA
                            j = 0;
                            lcilength = tlv->info_string[5];
                            debug_printf (DEBUG_NORMAL, "Civic Address LCI\n");
                            debug_printf (DEBUG_NORMAL, "LCI Length = %i  \n",
                            lcilength);
                            debug_printf (DEBUG_NORMAL, "What = %i  \n",
                            tlv->info_string[6]);
                            debug_printf (DEBUG_NORMAL, "Countrycode %c%c \n",
                            tlv->info_string[7], tlv->info_string[8]);

                            //lcilength counts from 'what' element, which is on position 6
                            while (i < 6 + lcilength)
                            {
                                catype = tlv->info_string[i];
                                i++;
                                calength = tlv->info_string[i];
                                i++;
                                debug_printf (DEBUG_NORMAL,
                                "CA-Type %i, CALength %i = ", catype,
                                calength);
                                for (j = i; j < i + calength; j++)
                                debug_printf (DEBUG_NORMAL, "%c",
                                tlv->info_string[j]);
                                //i++;
                                debug_printf (DEBUG_NORMAL, "\n");
                                i += calength;
                            }
                            break;
                        case 3:
                            debug_printf (DEBUG_NORMAL, "ECS ELIN\n");

                            //check if ELIN length is ok
                            if ((tlv->length < 15) || (tlv->length > 30))
                            {
                            debug_printf (DEBUG_NORMAL,
                            "[ERROR] ELIN length is wrong!\n");
                            }

                            elin = calloc (1, sizeof (char) * (tlv->length - 5 + 1));
                            strncpy(elin, (char *)&tlv->info_string[5], tlv->length - 5);
                            elin[tlv->length - 5] = '\0';
                            debug_printf (DEBUG_NORMAL, "%s \n", elin);
                            free (elin);

                            break;

                        default:
                            debug_printf (DEBUG_NORMAL,
                            "Reserved location data format for future use detected!\n");
                            break;

                    }
                }
            }  
        }

        tlv_offset += sizeof(*tlv_hdr) + tlv_length;

        last_tlv_type = tlv_type;

        //decode_tlv_subtype(tlv);

        destroy_tlv(&tlv);
        tlv = NULL;

    }while(tlv_type != 0);

    if (badFrame > 0)
    {
        if (tlv != NULL)
        {
            destroy_tlv(&tlv);
        }

        if(msap_tlv1 != NULL) {
          debug_printf(DEBUG_NORMAL, "Error: msap_tlv1 is still allocated!\n");
          free(msap_tlv1);
          msap_tlv1 = NULL;
        }
        
        if(msap_tlv2 != NULL) {
          debug_printf(DEBUG_NORMAL, "Error: msap_tlv2 is still allocated!\n");
          free(msap_tlv2);
          msap_tlv2 = NULL;
        }

        if (tlv_list != NULL)
        {
            destroy_tlv_list(&tlv_list);
            tlv_list = NULL;
        }
        if (msap_id != NULL)
        {
            free(msap_id);
            msap_id = NULL;
        }

        rxBadFrameInfo(badFrame);

        return badFrame;
    }

    //lldp_port->rxChanges = TRUE;

    /* We're done processing the frame and all TLVs... now we can cache it */
    /* Only cache this TLV list if we have an MSAP for it */
    if(have_msap)
      {
#ifndef WIN32
//        #warning We need to verify whether this is actually the case.
#endif // WIN32
    lldp_port->rxChanges = TRUE;

    debug_printf(DEBUG_TLV, "We have a(n) %d byte MSAP!\n", msap_length);

    msap_cache = calloc(1, sizeof(struct lldp_msap));
    if(msap_cache == NULL)
    {
        debug_printf(DEBUG_NORMAL, "[ERROR] Unable to malloc buffer in %s() at line: %d!\n", __FUNCTION__, __LINE__);
        if (msap_id != NULL)
        {
            free(msap_id);
            msap_id = NULL;
        }
        if (tlv_list != NULL)
        {
            destroy_tlv_list(&tlv_list);
            tlv_list = NULL;
        }

        badFrame++;
    }
    else
    {
        msap_cache->id = msap_id;
        msap_cache->length = msap_length;
        msap_cache->tlv_list = tlv_list;
        msap_cache->next = NULL;

        //msap_ttl_tlv = NULL;
        msap_cache->ttl_tlv = NULL;


        //debug_printf(DEBUG_MSAP, "Iterating MSAP Cache...\n");

        //iterate_msap_cache(msap_cache);

        //debug_printf(DEBUG_MSAP, "Updating MSAP Cache...\n");

        debug_printf(DEBUG_MSAP, "Setting rxInfoTTL to: %d\n", lldp_port->rx.timers.rxTTL);

        msap_cache->rxInfoTTL = lldp_port->rx.timers.rxTTL;
        msap_cache->rxOrignalTTL = lldp_port->rx.timers.rxTTL;

        badFrame = update_msap_cache(lldp_port, msap_cache);
    }

    if(msap_tlv1 != NULL) {
      debug_printf(DEBUG_NORMAL, "Error: msap_tlv1 is still allocated!\n");
      free(msap_tlv1);
      msap_tlv1 = NULL;
    }

    if(msap_tlv2 != NULL) {
      debug_printf(DEBUG_NORMAL, "Error: msap_tlv2 is still allocated!\n");
      free(msap_tlv2);
      msap_tlv2 = NULL;
    }
      }
    else
      {
        debug_printf(DEBUG_NORMAL, "[ERROR] No MSAP for TLVs in Frame!\n");
      }

    return badFrame;
}
  
void rxBadFrameInfo(uint8_t frameErrors) {
    debug_printf(DEBUG_NORMAL, "[WARNING] This frame had %d errors!\n", frameErrors);
}
void rx_free_remote_index(struct lldp_port *lldp_port, uint8_t index) {
    lldp_port->rx.remoteIndexArray[index] = 0;
}

struct lldp_tlv * decode_tlv_subtype_for_MGT(struct lldp_msap *msap_cache)
{
    struct lldp_tlv * tlv = NULL;

    struct lldp_tlv_list *tlv_list   = NULL;
    if(msap_cache != NULL) 
    {
        tlv_list = msap_cache->tlv_list;

        while(tlv_list != NULL) 
        {
            if(tlv_list->tlv != NULL) 
            {
                if (tlv_list->tlv->type == MANAGEMENT_ADDRESS_TLV)
                {
                    tlv = (struct lldp_tlv *)calloc(1, sizeof(struct lldp_tlv));
                    tlv->type = tlv_list->tlv->type;
                    tlv->length = tlv_list->tlv->length;
                    tlv->info_string = (uint8_t *)calloc(1, tlv_list->tlv->length);
                    memcpy(tlv->info_string, (uint8_t*)&tlv_list->tlv->info_string[0], tlv_list->tlv->length);
                    return tlv;
                }
            }
            tlv_list = tlv_list->next;
        }
    }
    return tlv;
}

void _pushDbMsg(struct lldp_port *lldp_port, uint8_t theMsapId, struct lldp_msap *theMsap, struct lldp_tlv * theTlv)
{
    lldp_port_db_msg_t* lldp_db_msg = (lldp_port_db_msg_t*)malloc(sizeof(lldp_port_db_msg_t));
    memset(lldp_db_msg, 0, sizeof(lldp_port_db_msg_t));
    lldp_db_msg->lldp_port = lldp_port;
    lldp_db_msg->remoteIndexMsap = theMsapId;
    //lldp_db_msg->mgt_addr_tlv = theTlv;
    lldp_db_msg->lldp_msap = theMsap;
    item_t* aItem = (item_t*)malloc(sizeof(item_t));
    aItem->key = lldp_port->if_index;
    aItem->statellite = (void *)lldp_db_msg;
    queue_enqueue(g_DbMsgQueue, aItem);
    //queue_info(g_DbMsgQueue);

    debug_printf(DEBUG_NORMAL, "\n _pushDbMsg enqueue %s: msap remote index = %d\n", lldp_port->if_name, (int)theMsapId);


}
void pushDbMsg(struct lldp_port *lldp_port, struct lldp_msap * theMsap)
{
    if (g_LLDP_TYPE == LLDP_TYPE_MCN &&
        lldp_port->rx.rxFrameType != ORLLDP_RX_FRAME_INVALID &&
        lldp_port->rx.rxFrameType != ORLLDP_RX_FRAME_REFRESH)
    {
        if (theMsap != NULL)
        {
            //_pushDbMsg(lldp_port, theMsap->remoteIndexMsap, NULL, decode_tlv_subtype_for_MGT(theMsap));
            _pushDbMsg(lldp_port, theMsap->remoteIndexMsap, theMsap, NULL);
        }
        else
        {
            struct lldp_msap * aMsap = lldp_port->msap_cache;
            while (aMsap != NULL)
            {
                if (aMsap->isChanged == 1)
                {
                    _pushDbMsg(lldp_port, aMsap->remoteIndexMsap, aMsap, NULL);
                    aMsap->isChanged = 0;
                }
                aMsap = aMsap->next;
            }
        }
    }
}
/* Just a stub */
uint8_t mibUpdateObjects(struct lldp_port *lldp_port) {
    pushDbMsg(lldp_port, NULL);
    return 0;
}

uint8_t mibCLeanupObjects(struct lldp_port *lldp_port) {
  struct lldp_msap *current = lldp_port->msap_cache;
  struct lldp_msap *tail    = NULL;
  struct lldp_msap *tmp     = NULL;

  while(current != NULL) {
      // If the top list is expired, then adjust the list
      // before we delete the node.
      if(current == lldp_port->msap_cache) {
	lldp_port->msap_cache = current->next;
      } else {
	tail->next = current->next;
      }

      tmp = current;
      current = current->next;

      if(tmp->id != NULL) {
	free(tmp->id);
      }
	
      destroy_tlv_list(&tmp->tlv_list);
      free(tmp);
  }

  return 0;
}

uint8_t mibForceDeleteObjects(struct lldp_port *lldp_port, uint8_t* need_delete) {
  struct lldp_msap *current = lldp_port->msap_cache;
  *need_delete = 1;

  if(current != NULL) {
    *need_delete = 0;

    lldp_port->rx.rxFrameType = ORLLDP_RX_FRAME_SHUTDOWN;
    pushDbMsg(lldp_port, current);
    memset(lldp_port->rx.pduMsgDigest, 0, MD5_MAX_KEY_LENGTH);
    rx_free_remote_index(lldp_port, lldp_port->msap_cache->remoteIndexMsap);
    lldp_port->rx.tooManyNeighbors--;

  }

  return 0;
}


uint8_t mibDeleteObjects(struct lldp_port *lldp_port) {
  struct lldp_msap *current = lldp_port->msap_cache;
  struct lldp_msap *tail    = NULL;
  struct lldp_msap *tmp     = NULL;

  while(current != NULL) {
    if(current->rxInfoTTL <= 0) {
        if (g_LLDP_TYPE != LLDP_TYPE_MCN)
        {
            LLDP_NEIGHBOR_SHELFID* alldp_neighbor_shelfid = LLDP_GetPortNeighbor(lldp_port->if_name);
            if (alldp_neighbor_shelfid != NULL)
            {
                alldp_neighbor_shelfid->isChanged = 1;
                memset(alldp_neighbor_shelfid->chassis_id, 0x0, CHASSISID_SIZE);
                memset(alldp_neighbor_shelfid->port_id, 0x0, PORTID_SIZE);
                memset(alldp_neighbor_shelfid->system_name, 0x0, SYSNAME_SIZE);
            }
        }
        else
        {
            lldp_port->rx.rxFrameType = ORLLDP_RX_FRAME_SHUTDOWN;
            pushDbMsg(lldp_port, current);
            memset(lldp_port->rx.pduMsgDigest, 0, MD5_MAX_KEY_LENGTH);
        }
        rx_free_remote_index(lldp_port, lldp_port->msap_cache->remoteIndexMsap);
        lldp_port->rx.tooManyNeighbors--;

      // If the top list is expired, then adjust the list
      // before we delete the node.
      if(current == lldp_port->msap_cache) {
	lldp_port->msap_cache = current->next;
      } else {
	tail->next = current->next;
      }

      tmp = current;
      current = current->next;
      if (g_LLDP_TYPE != LLDP_TYPE_MCN)
      {
           if(tmp->id != NULL)
           {
               free(tmp->id);
           }

           destroy_tlv_list(&tmp->tlv_list);
           free(tmp);
       }
    } 
    else 
    {
      tail = current;
      current = current->next;
    } 
  }

  return 0;
}

void rxChangeToState(struct lldp_port *lldp_port, uint8_t state) {
    debug_printf(DEBUG_STATE, "[%s] %s -> %s\n", lldp_port->if_name, rxStateFromID(lldp_port->rx.state), rxStateFromID(state));

    switch(state) {
        case LLDP_WAIT_PORT_OPERATIONAL: {
                                             // Do nothing
                                         }break;    
        case RX_LLDP_INITIALIZE: {
                                     if(lldp_port->rx.state != LLDP_WAIT_PORT_OPERATIONAL) {
                                         debug_printf(DEBUG_STATE, "[ERROR] Illegal Transition: [%s] %s -> %s\n", lldp_port->if_name, rxStateFromID(lldp_port->rx.state), rxStateFromID(state));      
                                     }

                                     /*
                                     // From the 10.5.5.3 rx state machine diagram
                                     rxInitializeLLDP(lldp_port);
                                     lldp_port->rx.rcvFrame = 0;
                                     */
                                 }break;
        case DELETE_AGED_INFO: {
                                   if(lldp_port->rx.state != LLDP_WAIT_PORT_OPERATIONAL) {
                                       debug_printf(DEBUG_STATE, "[ERROR] Illegal Transition: [%s] %s -> %s\n", lldp_port->if_name, rxStateFromID(lldp_port->rx.state), rxStateFromID(state));      
                                   }

                                   /*
                                   // From the 10.5.5.3 rx state machine diagram
                                   lldp_port->rx.somethingChangedRemote = 0;
                                   mibDeleteObjects(lldp_port);
                                   lldp_port->rx.rxInfoAge = 0;
                                   lldp_port->rx.somethingChangedRemote = 1;
                                   */
                               }break;
        case RX_WAIT_FOR_FRAME: {    
                                    if(!(lldp_port->rx.state == RX_LLDP_INITIALIZE ||
                                                lldp_port->rx.state == DELETE_INFO ||
                                                lldp_port->rx.state == UPDATE_INFO ||
                                                lldp_port->rx.state == RX_FRAME)) {
                                        debug_printf(DEBUG_STATE, "[ERROR] Illegal Transition: [%s] %s -> %s\n", lldp_port->if_name, rxStateFromID(lldp_port->rx.state), rxStateFromID(state));      
                                    }

                                    /*
                                    // From the 10.5.5.3 rx state machine diagram
                                    lldp_port->rx.badFrame               = 0;
                                    lldp_port->rx.rxInfoAge              = 0;
                                    lldp_port->rx.somethingChangedRemote = 0;
                                    */
                                }break;
        case RX_FRAME: {
                           if(lldp_port->rx.state != RX_WAIT_FOR_FRAME) {
                               debug_printf(DEBUG_STATE, "[ERROR] Illegal Transition: [%s] %s -> %s\n", lldp_port->if_name, rxStateFromID(lldp_port->rx.state), rxStateFromID(state));      
                           }

                           /*
                           // From the 10.5.5.3 rx state machine diagram
                           lldp_port->rx.rxChanges = 0;
                           lldp_port->rcvFrame     = 0;
                           rxProcessFrame(lldp_port);    
                           */
                       }break;
        case DELETE_INFO: {
                              if(!(lldp_port->rx.state == RX_WAIT_FOR_FRAME ||
                                          lldp_port->rx.state == RX_FRAME)) {
                                  debug_printf(DEBUG_STATE, "[ERROR] Illegal Transition: [%s] %s -> %s\n", lldp_port->if_name, rxStateFromID(lldp_port->rx.state), rxStateFromID(state));      
                              }
                          }break;
        case UPDATE_INFO: {
                              if(lldp_port->rx.state != RX_FRAME) {
                                  debug_printf(DEBUG_STATE, "[ERROR] Illegal Transition: [%s] %s -> %s\n", lldp_port->if_name, rxStateFromID(lldp_port->rx.state), rxStateFromID(state));      
                              }
                          }break;
        default: {
                     debug_printf(DEBUG_STATE, "[ERROR] Illegal Transition: [%s] %s -> %s\n", lldp_port->if_name, rxStateFromID(lldp_port->rx.state), rxStateFromID(state));      
                     // Do nothing
                 };
    };

    // Now update the interface state
    lldp_port->rx.state = state;
}

char *rxStateFromID(uint8_t state)
{
    switch(state)
    {
        case LLDP_WAIT_PORT_OPERATIONAL:
            return "LLDP_WAIT_PORT_OPERATIONAL";
        case DELETE_AGED_INFO:
            return "DELETE_AGED_INFO";
        case RX_LLDP_INITIALIZE:
            return "RX_LLDP_INITIALIZE";
        case RX_WAIT_FOR_FRAME:
            return "RX_WAIT_FOR_FRAME";
        case RX_FRAME:
            return "RX_FRAME";
        case DELETE_INFO:
            return "DELETE_INFO";
        case UPDATE_INFO:
            return "UPDATE_INFO";
    };

    debug_printf(DEBUG_NORMAL, "[ERROR] Unknown RX State: '%d'\n", state);
    return "Unknown";
}

uint8_t rxGlobalStatemachineRun(struct lldp_port *lldp_port)
{
  /* NB: IEEE 802.1AB Section 10.5.5.3 claims that */
  /* An unconditional transfer should occur when */
  /* "(rxInfoAge = FALSE) && (portEnabled == FALSE)" */
  /* I believe that "(rxInfoAge = FALSE)" is a typo and should be: */
  /* "(rxInfoAge == FALSE)" */
  if((lldp_port->rx.rxInfoAge == FALSE) && (lldp_port->portEnabled == FALSE))
    {
      rxChangeToState(lldp_port, LLDP_WAIT_PORT_OPERATIONAL);
    }
  
  switch(lldp_port->rx.state)
    {
    case LLDP_WAIT_PORT_OPERATIONAL:
      {
	if(lldp_port->rx.rxInfoAge == TRUE)
	  rxChangeToState(lldp_port, DELETE_AGED_INFO);
	if(lldp_port->portEnabled == TRUE) 
	  rxChangeToState(lldp_port, RX_LLDP_INITIALIZE);
      }break;
    case DELETE_AGED_INFO:
      {
	rxChangeToState(lldp_port, LLDP_WAIT_PORT_OPERATIONAL);
      }break;
    case RX_LLDP_INITIALIZE:
      {
	if((lldp_port->adminStatus == enabledRxTx) || (lldp_port->adminStatus == enabledRxOnly))
	  rxChangeToState(lldp_port, RX_WAIT_FOR_FRAME);
      }break;
    case RX_WAIT_FOR_FRAME:
      {
	if(lldp_port->rx.rxInfoAge == TRUE)
	  rxChangeToState(lldp_port, DELETE_INFO);
	if(lldp_port->rx.rcvFrame == TRUE)
	  rxChangeToState(lldp_port, RX_FRAME);
      }break;
    case DELETE_INFO:
      {
	rxChangeToState(lldp_port, RX_WAIT_FOR_FRAME);
      }break;
    case RX_FRAME:
      {
	if(lldp_port->rx.timers.rxTTL == 0)
	  rxChangeToState(lldp_port, DELETE_INFO);
	if((lldp_port->rx.timers.rxTTL != 0) && (lldp_port->rxChanges == TRUE))
	  {
	    rxChangeToState(lldp_port, UPDATE_INFO);
	  }
      }break;
    case UPDATE_INFO:
      {
	rxChangeToState(lldp_port, RX_WAIT_FOR_FRAME);
      }break;
    default:
            debug_printf(DEBUG_NORMAL, "[ERROR] The RX Global State Machine is broken!\n");
    };
  
  return 0;
}

void rxStatemachineRun(struct lldp_port *lldp_port)
{
  debug_printf(DEBUG_NORMAL, "Running RX state machine for %s\n", lldp_port->if_name);

    rxGlobalStatemachineRun(lldp_port);

    switch(lldp_port->rx.state)
      {
      case LLDP_WAIT_PORT_OPERATIONAL:
	{
	  // Do nothing here... we'll transition in the global state machine check
	  rx_do_lldp_wait_port_operational(lldp_port);
	}break;
      case DELETE_AGED_INFO:
	{
	  rx_do_delete_aged_info(lldp_port);
	}break;
      case RX_LLDP_INITIALIZE:
	{
	  rx_do_rx_lldp_initialize(lldp_port);
	}break;
      case RX_WAIT_FOR_FRAME:
	{
	  rx_do_rx_wait_for_frame(lldp_port);
	}break;
      case RX_FRAME:
	{
	  rx_do_rx_frame(lldp_port);
	}break;
      case DELETE_INFO: {
	rx_do_rx_delete_info(lldp_port);
      }break;
      case UPDATE_INFO: {
	rx_do_rx_update_info(lldp_port);
      }break;
      default:
	debug_printf(DEBUG_NORMAL, "[ERROR] The RX State Machine is broken!\n");      
    };

    rx_do_update_timers(lldp_port);
}

void rx_decrement_timer(int32_t *timer) {
    if((*timer) > 0) {
        (*timer)--;
    }
}

void rx_do_update_timers(struct lldp_port *lldp_port) {
  struct lldp_msap *msap_cache = lldp_port->msap_cache;

  debug_printf(DEBUG_NORMAL, "Decrementing RX Timers\n");
  lldp_port->rx.timers.tooManyNeighborsTimer = 0;

  // Here's where we update the IEEE 802.1AB RX timers:
  while(msap_cache != NULL) {

    rx_decrement_timer(&msap_cache->rxInfoTTL);

    /*if(msap_cache->ttl_tlv != NULL) {
      rx_decrement_timer((uint16_t *)&msap_cache->ttl_tlv->info_string);
      }*/

    // We're going to potenetially break the state machine here for a performance bump.
    // The state machine isn't clear (to me) how rxInfoAge is supposed to be set (per MSAP or per port)
    // and it seems to me that having a single tag that gets set if at least 1 MSAP is out of date 
    // is much more efficient than traversing the entire cache every state machine loop looking for an 
    // expired MSAP... 
    if(msap_cache->rxInfoTTL <= 0)
      lldp_port->rx.rxInfoAge = TRUE;

    msap_cache = msap_cache->next;
    lldp_port->rx.timers.tooManyNeighborsTimer++;
  }
    if (lldp_port->rx.timers.rxTTL == 0)
    {
        if (lldp_port->rx.pduMsgDigest[0] != 0)
        {
            debug_printf(DEBUG_STATE, "[TIMER] (%s) rxTTL: %d,but pduMsgDigest is not null\n", lldp_port->if_name, lldp_port->rx.timers.rxTTL);
            memset(lldp_port->rx.pduMsgDigest, 0, MD5_MAX_KEY_LENGTH);
        }
    }
  rx_display_timers(lldp_port);
}

void rx_display_timers(struct lldp_port *lldp_port) {
  struct lldp_msap *msap_cache = lldp_port->msap_cache;

  debug_printf(DEBUG_NORMAL, "Displaying RX Timers\n");

  while(msap_cache != NULL) {
        debug_printf(DEBUG_STATE, "[TIMER] (%s with MSAP: ", lldp_port->if_name);
	debug_hex_printf(DEBUG_STATE, msap_cache->id, msap_cache->length);
	debug_printf(DEBUG_NORMAL, ") rxInfoTTL: %d\n", msap_cache->rxInfoTTL);
	
	msap_cache = msap_cache->next;
  }

  debug_printf(DEBUG_STATE, "[TIMER] (%s) tooManyNeighborsTimer: %d\n", lldp_port->if_name, lldp_port->rx.timers.tooManyNeighborsTimer);
  debug_printf(DEBUG_STATE, "[TIMER] (%s) rxTTL: %d\n", lldp_port->if_name, lldp_port->rx.timers.rxTTL);

}

void rx_do_lldp_wait_port_operational(struct lldp_port *lldp_port) {
    /* As per IEEE 802.1AB 10.5.5.3 state diagram */
}


void rx_do_delete_aged_info(struct lldp_port *lldp_port) {
    /* As per IEEE 802.1AB 10.5.5.3 state diagram */
    lldp_port->rx.somethingChangedRemote = FALSE;
    mibDeleteObjects(lldp_port);
    lldp_port->rx.rxInfoAge = FALSE;
    lldp_port->rx.somethingChangedRemote = TRUE;
}

void rx_do_rx_lldp_initialize(struct lldp_port *lldp_port) {
    /* As per IEEE 802.1AB 10.5.5.3 state diagram */
    rxInitializeLLDP(lldp_port);
    lldp_port->rx.rcvFrame = FALSE;
}

void rx_do_rx_wait_for_frame(struct lldp_port *lldp_port) {
    /* As per IEEE 802.1AB 10.5.5.3 state diagram */
    lldp_port->rx.badFrame = FALSE;
    lldp_port->rx.rxInfoAge = FALSE;
    lldp_port->rx.somethingChangedRemote = FALSE;
}

void rx_do_rx_frame(struct lldp_port *lldp_port) {
    /* As per IEEE 802.1AB 10.5.5.3 state diagram */
    lldp_port->rxChanges = FALSE;
    lldp_port->rx.rcvFrame = FALSE;
    lldp_port->rx.badFrame = rxProcessFrame(lldp_port);

    // Clear the frame buffer out to avoid weird problems. ;)
    if (g_LLDP_TYPE != LLDP_TYPE_MCN && (NULL != lldp_port->rx.frame))
    {
        if (lldp_port->rx.recvsize > 0 && lldp_port->rx.recvsize < lldp_port->mtu)
        {
            memset(&lldp_port->rx.frame[0], 0x0, lldp_port->rx.recvsize);
        }
        else
        {
            memset(&lldp_port->rx.frame[0], 0x0, lldp_port->mtu);
        }
    }
}

void rx_do_rx_delete_info(struct lldp_port *lldp_port) {
    /* As per IEEE 802.1AB 10.5.5.3 state diagram */
    mibDeleteObjects(lldp_port);
    lldp_port->rx.somethingChangedRemote = TRUE;
}

void rx_do_rx_update_info(struct lldp_port *lldp_port) {
    /* As per IEEE 802.1AB 10.5.5.3 state diagram */
    mibUpdateObjects(lldp_port);
    lldp_port->rx.somethingChangedRemote = TRUE;
}
