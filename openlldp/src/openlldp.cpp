#include <stdio.h>
#include "include/openlldp.h"

extern "C"
{
#include "include/lldp_debug.h"
//#include "include/lldp_port.h"

#ifdef __LEAK_DETECTOR__
#include "leak_detector_c.h"
#endif


}


OpenLLDP::~OpenLLDP()
{
}



void OpenLLDP::ReportMemLeak()
{
#ifdef __LEAK_DETECTOR__
    printf("OpenLLDP::ReportMemLeak\n");//cli debug menu
    report_mem_leak();
#endif
}

const char* OpenLLDP::GetSysName()
{
    return (const char*)LLDP_GetSysName();
}

void OpenLLDP::SetDebugLevel(char* theDebugLevel)
{
    if (theDebugLevel)
    {
        debug_alpha_set_flags((const char *)theDebugLevel);
    }
}


void OpenLLDP::SetDstMac(char* theDstMac)
{
    if (theDstMac)
    {
        LLDP_SetDstMac((const char *)theDstMac);
    }
}


