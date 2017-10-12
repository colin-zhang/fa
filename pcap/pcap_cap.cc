#include <stdlib.h>
#include <unistd.h>

#include <string>

#include "pcap_cap.h"

PcapCap::PcapCap(const char* if_name)
{
    if_name_ = std::string(if_name);
}


PcapCap::~PcapCap()
{

}

int PcapCap::Open()
{
    char errbuf[PCAP_ERRBUF_SIZE] = {'\0'};
    handle_ = pcap_open_live(if_name_.c_str(), 65535, 1, 500, errbuf);
    if (handle_ == NULL) {
        return -1;
    }
    int datalink;
    if ((datalink = pcap_datalink(handle_)) == -1) {
        fprintf(stderr, "pcap_datalink: %s\n", pcap_geterr(handle_));
        return -1;
    }
    //linkTypeStr_ = pcap_datalink_val_to_name(linkType_);
    switch (datalink) {
    // ethernet packet
    case DLT_EN10MB:
        printf("%s\n", "DLT_EN10MB");
        //linkOffset_ = 14;
        break;
    case DLT_LINUX_SLL:
        printf("%s\n", "DLT_LINUX_SLL");
        //linkOffset_ = 16;
        break;
    case PCAP_ERROR_NOT_ACTIVATED:
        // can never happen
        printf("%s\n", "PCAP_ERROR_NOT_ACTIVATED");
        break;
    default:
        exit(1);
    }
    return 0;
}

int PcapCap::GetNext(PcapPktHdrPtr* pkt_header, uint8_t** pkt_data)
{
    return pcap_next_ex(handle_, pkt_header, (const u_char**)pkt_data);
}

void PcapCap::Stats()
{
    pcap_stat stat;
    pcap_stats(handle_, &stat);
    printf("Capture: receive packet = %d \n"
           "drop by kernel = %d \n"
           "drop by filter = %d \n"
           , stat.ps_recv
           , stat.ps_drop
           , stat.ps_ifdrop
          );
}


