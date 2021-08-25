#ifndef LLDP_API_H
#define LLDP_API_H


#define LLDP_IF_NAMESIZE    64
#define IF_SIZE    16
#define LLDP_IPV6_SIZE    16

#define CHASSISID_SIZE 255
#define PORTID_SIZE  255
#define SYSNAME_SIZE 255
#define MCN_LLDP_MAX_MSG_NUM 1000

typedef struct LLDP_PORT_DB_MSG {
    uint8_t msg_type;
    struct lldp_port *lldp_port;
    uint8_t remoteIndexMsap;
    //struct lldp_tlv * mgt_addr_tlv;
    struct lldp_msap *lldp_msap;
}lldp_port_db_msg_t;

typedef struct lldp_neighbor_shelfid {
    uint8_t isChanged;
    uint8_t isUp;
    char localIfName[LLDP_IF_NAMESIZE];
    uint8_t chassis_id[CHASSISID_SIZE];
    uint8_t port_id[PORTID_SIZE];
    uint8_t system_name[SYSNAME_SIZE];
}LLDP_NEIGHBOR_SHELFID;

typedef struct LLDP_OSC_PORT_INFO {
    uint8_t shelf_id;
    uint8_t slot_id;
    uint8_t port_id;
    uint8_t admin_status;
    uint32_t if_index;
    uint8_t* shelf_mac;
    uint8_t* chassis_id;
    uint8_t* if_name;
}lldp_osc_port_info_t;

void LLDP_daemon();
void LLDP_OSC_Recv();
void LLDP_OSC_RunRxSM();
void LLDP_OSC_Report();
int LLDP_init(const char * debug_flags,uint8_t threadFlag);
void deleteLLDP();
void LLDP_Report();
void LLDP_AddPort(const char * theIfName);
void LLDP_ShowPort();
void LLDP_ShowOscPort();
void LLDP_OSC_Report_Neignbor();
void LLDP_UpdateOscPortSrcMac(uint8_t shelf_id,uint8_t slot_id,uint8_t port_id, uint8_t* src_mac);
void LLDP_UpdateOscPortChassisID(uint8_t shelf_id, uint8_t* chassis_id);
void LLDP_UpdateOscPortStatus(uint8_t shelf_id, uint8_t admin_status);
void LLDP_DeleteOscPort(lldp_osc_port_info_t* lldp_osc_port_info, uint8_t* need_delete);
void LLDP_AddOscPort(lldp_osc_port_info_t* lldp_osc_port_info);
int LLDP_PortIsExist(char * theIfName);
void cleanupLLDPPort(const char * theIfName, char theRegular);
void cleanupOscLLDPPort(const char * theIfName, char theRegular);

void cleanupLLDP();
void LLDP_DeletePort(char * theIfName);
LLDP_NEIGHBOR_SHELFID * LLDP_GetPortNeighbor(const char * theIfName);
void  LLDP_SetSysName(char* aSysName);
void  LLDP_SetOrInstance(void* aOrInstance);
void  LLDP_SetIpv4MgtAddress(uint32_t theAddress);
void  LLDP_SetIpv6MgtAddress(uint8_t theMgtAddress[]);
void LLDP_DeleteMgtAddress();
char* LLDP_GetSysName();
void LLDP_SetDstMac(const char * theDstMac);
void LLDP_SetMsgTxHold(uint16_t theMsgTxHold);
void LLDP_SetMsgTxInterval(uint16_t theMsgTxInterval);
void LLDP_SetMcnEnabled(uint8_t theMcnEnabled);

#endif
