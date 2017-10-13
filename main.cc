#include <stdio.h>

#include "pcap/pcap_cap.h"
#include "base/packet_header.h"
#include "base/endian.h"

// #include "cap/dpdk.h"


// int main(int argc, char *argv[])
// {
//     DpdkRte* dpdk_rte = DpdkRte::Instance();
//     dpdk_rte->RteInit(argc, argv);
//     dpdk_rte->PrintInfo();

//     dpdk_rte->PortsInit();


//     printf("Hello world\n");

//     return 0;
// }


#include <stdio.h>
#include <pcap.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

//IP层数据包格式
typedef struct {
    int header_len: 4;
    int version: 4;
    u_char tos: 8;
    int total_len: 16;
    int ident: 16;
    int flags: 16;
    u_char ttl: 8;
    u_char proto: 8;
    int checksum: 16;
    u_char sourceIP[4];
    u_char destIP[4];
} IPHEADER;

#if 0
struct ipv4_hdr {
    uint8_t  version_ihl;       /**< version and header length */
    uint8_t  type_of_service;   /**< type of service */
    uint16_t total_length;      /**< length of packet */
    uint16_t packet_id;     /**< packet ID */
    uint16_t fragment_offset;   /**< fragmentation offset */
    uint8_t  time_to_live;      /**< time to live */
    uint8_t  next_proto_id;     /**< protocol ID */
    uint16_t hdr_checksum;      /**< header checksum */
    uint32_t src_addr;      /**< source address */
    uint32_t dst_addr;      /**< destination address */
} __attribute__((__packed__));
#endif

//协议映射表
const char* Proto[] = {
    "Reserved", "ICMP", "IGMP", "GGP", "IP", "ST", "TCP"
};


void pcap_handle(PcapPktHdrPtr header, uint8_t* pkt_data)
{
    EtherHdr* eth_header = reinterpret_cast<EtherHdr*>(pkt_data);
    uint16_t l2_type = ntoh16(eth_header->ether_type);
    printf("---------------Begin Analysis-----------------\n");
    printf("Packet length: %d \n", header->len);
    //解析数据包IP头部
    if (header->len >= 14) {
        //ether_hdr* ether_header = reinterpret_cast<ether_hdr*>(pkt_data);
        IPHEADER *ip_header = (IPHEADER*)(pkt_data + 14);
        //解析协议类型
        char strType[100];
        if (ip_header->proto > 7)
            strcpy(strType, "IP/UNKNWN");
        else
            strcpy(strType, Proto[ip_header->proto]);

        printf("Source MAC : %02X-%02X-%02X-%02X-%02X-%02X==>", 
                eth_header->s_addr.addr_bytes[0], eth_header->s_addr.addr_bytes[1], eth_header->s_addr.addr_bytes[2], 
                eth_header->s_addr.addr_bytes[3], eth_header->s_addr.addr_bytes[4], eth_header->s_addr.addr_bytes[5]);
        printf("Dest   MAC : %02X-%02X-%02X-%02X-%02X-%02X\n", 
                eth_header->d_addr.addr_bytes[0], eth_header->d_addr.addr_bytes[1], eth_header->d_addr.addr_bytes[2], 
                eth_header->d_addr.addr_bytes[3], eth_header->d_addr.addr_bytes[4], eth_header->d_addr.addr_bytes[5]);

        printf("Source IP : %d.%d.%d.%d==>", ip_header->sourceIP[0], ip_header->sourceIP[1], ip_header->sourceIP[2], ip_header->sourceIP[3]);
        printf("Dest   IP : %d.%d.%d.%d\n", ip_header->destIP[0], ip_header->destIP[1], ip_header->destIP[2], ip_header->destIP[3]);

        printf("Protocol : %s\n", strType);

        //显示数据帧内容
        // int i;
        // for(i=0; i<(int)header->len; ++i)  {
        //     printf(" %02x", pkt_data[i]);
        //     if( (i + 1) % 16 == 0 )
        //         printf("\n");
        // }
        printf("\n\n");
    }
}

int main(int argc, char const *argv[])
{
    PcapCap ppcap("eno2");
    ppcap.Open();

    while (1) {
        PcapPktHdrPtr ptr;
        uint8_t* data;
        if (ppcap.GetNext(&ptr, &data) > 0) {
            pcap_handle(ptr, data);   
        }
    }

    return 0;
}