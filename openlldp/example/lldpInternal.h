#ifndef _LLDP_INTERNAL_H_
#define _LLDP_INTERNAL_H_

#include <mutex>
#include <boost/thread.hpp>
#include "openlldp/include/openlldp.h"

class LldpNeighberShelfid
{
public:
    const uint8_t* getChassisId(){return m_chassis_id;}
    const uint8_t* getPortId(){return m_port_id;}
    const uint8_t* getSysName(){return m_system_name;}
    const char* getLocalIfName(){return m_local_ifname;}
    uint8_t isValid()  {return m_is_valid;}

    LldpNeighberShelfid(const LLDP_NEIGHBOR_SHELFID& lldpNeignbor)
    {
        memcpy(m_chassis_id, lldpNeignbor.chassis_id, CHASSISID_SIZE);
        memcpy(m_port_id, lldpNeignbor.port_id, PORTID_SIZE);
        memcpy(m_system_name, lldpNeignbor.system_name, SYSNAME_SIZE);
        memcpy(m_local_ifname, lldpNeignbor.localIfName, LLDP_IF_NAMESIZE);
        m_is_valid = lldpNeignbor.isUp;
    }
    LldpNeighberShelfid(char* theLocalIfname)
    {
        memset(m_chassis_id, 0, CHASSISID_SIZE);
        memset(m_port_id, 0, PORTID_SIZE);
        memset(m_system_name, 0, SYSNAME_SIZE);
        strncpy(m_local_ifname, theLocalIfname, LLDP_IF_NAMESIZE);
        m_local_ifname[LLDP_IF_NAMESIZE-1] = '\0';
        m_is_valid = 0;
    }

private:
    uint8_t m_is_valid;
    uint8_t m_chassis_id[CHASSISID_SIZE];
    uint8_t m_port_id[PORTID_SIZE];
    uint8_t m_system_name[SYSNAME_SIZE];
    char m_local_ifname[LLDP_IF_NAMESIZE];

};

class LLDPInternal: public OpenLLDP
{
public:
    static LLDPInternal* GetInstance(void);
    static void DeleteInstance(void);
    boost::shared_ptr<LldpNeighberShelfid> GetPortNeighbor(const char* theIfName, bool updateFlag);

    void StopLLdp();
    void ApplyLLdp();
    void SetSysName();
    void DeletePort(char* theIfName);
    void AddPort(char* theIfName);
    void ShowPort();
    void DeleteAllPorts();


protected:
    LLDPInternal()
    {
    }

    ~LLDPInternal();
    static void LLdpDaemon();
    static void UpdatePortNeighbor(const char* theIfName);

private:
    static LLDPInternal* m_Instance;
    static boost::thread* m_openlldpDaemon;
    static std::mutex m_mutex;

};




#endif

