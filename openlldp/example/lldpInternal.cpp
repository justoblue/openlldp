#include <boost/foreach.hpp>
#include <boost/thread.hpp>
#include <boost/shared_ptr.hpp>


#include <stdio.h>
#include <sys/prctl.h>

#include "include/lldpInternal.h"


#include "LOG/Logger.h"

extern "C"
{
//#include "include/lldp_port.h"
}

boost::thread* LLDPInternal::m_openlldpDaemon = NULL;

LLDPInternal* LLDPInternal::m_Instance = NULL;

std::mutex LLDPInternal::m_mutex;

LLDPInternal* LLDPInternal::GetInstance(void)
{
    if (NULL == m_Instance)
    {
        m_Instance = new LLDPInternal();
    }

    return m_Instance;
}
void LLDPInternal::DeleteInstance(void)
{
    if (NULL != m_Instance)
    {
        delete m_Instance;
    }
}
LLDPInternal::~LLDPInternal()
{
    StopLLdp();
}

void LLDPInternal::LLdpDaemon()
{

    ::prctl(PR_SET_NAME, "LLdpDaemon");

    LOG_INFO2("LLDPInternal: start lldp thread");

    try {
        while (!boost::this_thread::interruption_requested())
        {
            boost::this_thread::sleep_for(boost::chrono::seconds(1));
            std::lock_guard<std::mutex> lock(m_mutex);
            LLDP_daemon();
            LLDP_Report();
            //UpdatePortNeighbor(LinkMonitor::ETH2_ON_OS.c_str());
            //UpdatePortNeighbor(LinkMonitor::ETH3_ON_OS.c_str());

        }
    } catch (boost::thread_interrupted&) {
        LOG_INFO2("LLDPInternal: interrupt lldp thread");
    }
    catch (...)
    {
        LOG_INFO2("LLDPInternal: interrupt lldp thread...");
    }
    LOG_INFO2("LLDPInternal: stop lldp thread");
    deleteLLDP();

}

void LLDPInternal::SetSysName()
{
    char aSysName[100] = {0};
    strncpy(aSysName, "system_name",99);
    LLDP_SetSysName(aSysName);
}

void LLDPInternal::ApplyLLdp()
{
    LLDP_init("d", LLDP_TYPE_SHELFID);
    SetSysName();

    m_openlldpDaemon = new boost::thread(&LLdpDaemon);
}
void LLDPInternal::ShowPort()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    LLDP_ShowPort();
}

void LLDPInternal::StopLLdp()
{
    if (m_openlldpDaemon != NULL) 
    {
        m_openlldpDaemon->interrupt();
        m_openlldpDaemon->join();
        delete m_openlldpDaemon;
        m_openlldpDaemon = NULL;
    }
}

boost::shared_ptr<LldpNeighberShelfid> LLDPInternal::GetPortNeighbor(const char* theIfName, bool updateFlag)
{

    LLDP_NEIGHBOR_SHELFID* tempNeighbor = LLDP_GetPortNeighbor((const char *)theIfName);
    if (tempNeighbor && tempNeighbor->isUp)
    {
        boost::shared_ptr<LldpNeighberShelfid> aNeighborInfo(new LldpNeighberShelfid(*tempNeighbor));
        if (updateFlag)
        {
            LinkMonitor::LinkMonitor::GetInstance()->ExternalUpdateLldpInfo(aNeighborInfo);
        }
        return aNeighborInfo;
    }
    return NULL;
}

void LLDPInternal::UpdatePortNeighbor(const char* theIfName)
{
    LLDP_NEIGHBOR_SHELFID* tempNeighbor = LLDP_GetPortNeighbor(theIfName);
    if (tempNeighbor && tempNeighbor->isChanged)
    {
        boost::shared_ptr<LldpNeighberShelfid> aNeighborInfo(new LldpNeighberShelfid(*tempNeighbor));
        //Update neighbor :LinkMonitor::LinkMonitor::GetInstance()->ExternalUpdateLldpInfo(aNeighborInfo);
        tempNeighbor->isChanged = 0;
    }
    return;
}
void LLDPInternal::DeleteAllPorts()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    cleanupLLDP();
    LLDP_ShowPort();
}

void LLDPInternal::AddPort(char* theIfName)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    LLDP_AddPort(theIfName);
    LLDP_ShowPort();
}


void LLDPInternal::DeletePort(char* theIfName)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    LLDP_DeletePort(theIfName);
    LLDP_ShowPort();
}


