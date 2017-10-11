#include <stdio.h>

#include "cap/dpdk.h"


int main(int argc, char *argv[])
{
    DpdkRte* dpdk_rte = DpdkRte::Instance();
    dpdk_rte->RteInit(argc, argv);
    dpdk_rte->PrintInfo();

    dpdk_rte->PortsInit();

    
    printf("Hello world\n");

    return 0;
}