#ifndef _OPEN_LLDP_H_
#define _OPEN_LLDP_H_

#include <stdint.h>

extern "C"
{
#include "lldp_api.h"

extern const uint8_t LLDP_TYPE_SHELFID;
extern const uint8_t LLDP_TYPE_MCN;

}


class OpenLLDP
{
public:
    virtual void StopLLdp() = 0;
    virtual void ApplyLLdp() = 0;

    void ReportMemLeak();
    void SetDstMac(char* theDstMac);

    void SetDebugLevel(char* theDebugLevel);

    const char* GetSysName();

protected:
    OpenLLDP()
    {
    }

    virtual ~OpenLLDP();

private:
};




#endif

