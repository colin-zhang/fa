#include "dpdk.h"

#include <string>

DpdkRte* DpdkRte::rte_ = nullptr;
std::mutex DpdkRte::mutex_;

// static const struct rte_eth_conf port_conf_default = {
//     .rxmode = {
//         .mq_mode = ETH_MQ_RX_NONE,
//         .max_rx_pkt_len = ETHER_MAX_LEN,
//     }
// };

DpdkRte::~DpdkRte()
{

}

DpdkRte* DpdkRte::Instance() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (rte_ == nullptr) {
        rte_ = new DpdkRte;
    }
    return rte_;
}

int DpdkRte::RteInit(int argc, char *argv[]) {
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
    cap_core_num = 2;
    core_num = rte_lcore_count();
    port_num = rte_eth_dev_count();
    return ret;
}

int DpdkRte::PortsInit()
{
    for (int i = 0; i < port_num; i++) {
        DpdkPort* port = new DpdkPort(i, cap_core_num, 0);
        ports_.push_back(port);
        uint8_t socketid = port->SocketId();
        if (ports_mempools_.count(socketid) == 0) {
            unsigned n = (port->RxRings() * port->RxDesc() + port->TxRings() * port->TxDesc())
                         * cap_core_num + 1024;
            RteMemPoolPtr mbuf_pool = rte_pktmbuf_pool_create("DpdkRte_MBUF_POOL", n,
                                        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, socketid);
            if (mbuf_pool == NULL) {
                rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
            }
            printf("mbuf_pool@%p\n", mbuf_pool);

            ports_mempools_[socketid] = mbuf_pool;
        }
    }

    for (std::vector<DpdkPort*>::iterator x = ports_.begin(); x != ports_.end(); x++) {
        (*x)->Setup(ports_mempools_[(*x)->SocketId()]);
    }
    return 0;
}

void DpdkRte::PrintInfo() {
    printf("core_num = %d\n", core_num);
    printf("port_num = %d\n", port_num);    
}

DpdkPort::DpdkPort(uint8_t port_id, uint16_t rx_rings, uint16_t tx_rings)
    : port_id_(port_id),
      rx_rings_(rx_rings),
      tx_rings_(tx_rings),
      num_rxdesc_(512),
      num_txdesc_(512)
{
    char dev_name[128];
    port_conf_.rxmode.mq_mode = ETH_MQ_RX_RSS;
    port_conf_.rx_adv_conf.rss_conf.rss_key = nullptr; // use defaut DPDK-key
    port_conf_.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_IP | ETH_RSS_TCP | ETH_RSS_UDP;
    // Tune tx
    port_conf_.txmode.mq_mode = ETH_MQ_TX_NONE;

    if (rte_eth_dev_is_valid_port(port_id_) == 0) {
        rte_exit(EXIT_FAILURE, "fail to get port name \n");
    }

    if (rte_eth_dev_get_name_by_port(port_id_, dev_name) != 0) {
        rte_exit(EXIT_FAILURE, "fail to get port name \n");
    }
    dev_name_ = std::string(dev_name);

    socket_id_ = rte_eth_dev_socket_id(port_id_);
    core_id_  = rte_lcore_id();
    printf("port_id_ = %d, socket_id_ = %d, core_id_ = %d\n", 
            port_id_,
            socket_id_,
            core_id_
            );
    rte_eth_dev_info_get(1, &dev_info_);
}

DpdkPort::~DpdkPort()
{

}

int DpdkPort::Setup(struct rte_mempool* mbuf_pool)
{
    int ret = 0;
    if (rx_rings_ > 1) {
        port_conf_.rxmode.mq_mode = ETH_MQ_RX_RSS;
        port_conf_.rx_adv_conf.rss_conf.rss_key = nullptr;
        port_conf_.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_PROTO_MASK;
    }
    //发包时是否释放mbuf的阈值，可以配置

    ret = rte_eth_dev_configure(port_id_, rx_rings_, tx_rings_, &port_conf_);
    if (ret) {
        //RTE_LOG(ERR, DPDKCAP, "rte_eth_dev_configure(...): %s\n", rte_strerror(-ret));
        return ret;
    }

    for (int q = 0; q < rx_rings_; q++) {
        ret = rte_eth_rx_queue_setup(port_id_, q, num_rxdesc_, socket_id_, nullptr, mbuf_pool);
        if (ret) {
            //RTE_LOG(ERR, DPDKCAP, "rte_eth_rx_queue_setup(...): %s\n", rte_strerror(-ret));
            return ret;
        }
    }

    for (int q = 0; q < tx_rings_; q++) {
        ret = rte_eth_tx_queue_setup(port_id_, q, num_txdesc_, socket_id_, nullptr);
        if (ret) {
            //RTE_LOG(ERR, DPDKCAP, "rte_eth_tx_queue_setup(...): %s\n", rte_strerror(-ret));
            return ret;
        }
    }
    
    rte_eth_promiscuous_enable(port_id_);

    return 0;
}

int DpdkPort::Start()
{
    int ret = rte_eth_dev_start(port_id_);
    if (ret) {
        rte_exit(EXIT_FAILURE, "Cannot start port %d \n", port_id_);
    }
    return 0;
}

void DpdkPort::Stop()
{
    rte_eth_dev_stop(port_id_);
}
