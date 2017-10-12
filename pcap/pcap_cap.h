#ifndef PCAP_CAP_H_
#define PCAP_CAP_H_

#include <stdint.h>
#include <pcap.h>

#include <string>

typedef struct pcap_pkthdr* PcapPktHdrPtr;

class PcapCap
{
public:
    PcapCap(const char* if_name);
    ~PcapCap();

    int Open();

    void Stats();

    int GetNext(PcapPktHdrPtr* pkt_header, uint8_t** pkt_data);
    
private:
    pcap_t* handle_;
    std::string if_name_;
};


#endif
