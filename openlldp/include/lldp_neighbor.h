/*******************************************************************
 *
 * OpenLLDP Neighbor Header
 *
 * See LICENSE file for more info.
 * 
 * File: lldp_neighbor.h
 * 
 * Authors: Jason Peterson (condurre@users.sourceforge.net)
 *
 *******************************************************************/

#ifndef LLDP_NEIGHBOR_H
#define LLDP_NEIGHBOR_H

#ifndef WIN32
#include <sys/un.h>
#endif

#include "lldp_port.h"

char lldp_systemname[512];
char lldp_systemdesc[512];

int neighbor_local_sd;
int neighbor_remote_sd;

#ifdef WIN32
// Need to define this
#else
struct sockaddr_un local;
struct sockaddr_un remote;
#endif

typedef unsigned char       uint8;

int get_sys_desc(void);
int get_sys_fqdn(char* aSysName);

char *lldp_neighbor_information(struct lldp_port *lldp_ports,const char* theIfName, uint8_t theIsRegular);


#endif /* LLDP_NEIGHBOR_H */
