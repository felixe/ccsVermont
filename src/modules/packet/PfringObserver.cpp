/*
 PSAMP Reference Implementation
 PfringObserver.cpp
 Implementation of the packet capturing thread, now improved performancewise with pfring ZC
 Author of original Observer.cpp: Michael Drueing <michael@drueing.de>
 	 changed by: Ronny T. Lampert
             	 Gerhard Münz

 pfring enhancement: Felix Erlacher
 */

//following flag is set within cmake
#ifdef PFRING_ZC_ENABLED

#include "PfringObserver.h"

/* Code adopted from tcpreplay: */
/* subtract uvp from tvp and store in vvp */
#ifndef timersub
#define timersub(tvp, uvp, vvp)                 \
     do {                                        \
         (vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;      \
         (vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;   \
         if ((vvp)->tv_usec < 0) {               \
             (vvp)->tv_sec--;                    \
             (vvp)->tv_usec += 1000000;          \
         }                                       \
     } while (0)
#endif
/* add tvp and uvp and store in vvp */
#ifndef timeradd
#define timeradd(tvp, uvp, vvp)                 \
    do {                                        \
        (vvp)->tv_sec = (tvp)->tv_sec + (uvp)->tv_sec;      \
        (vvp)->tv_usec = (tvp)->tv_usec + (uvp)->tv_usec;   \
        if ((vvp)->tv_usec >= 1000000) {        \
            (vvp)->tv_sec++;                    \
            (vvp)->tv_usec -= 1000000;          \
        }                                       \
    } while (0)
#endif
/* compare tvp and uvp using cmp */
#ifndef timercmp
#define timercmp(tvp, uvp, cmp)                 \
    (((tvp)->tv_sec == (uvp)->tv_sec) ?         \
    ((tvp)->tv_usec cmp (uvp)->tv_usec) :       \
    ((tvp)->tv_sec cmp (uvp)->tv_sec))
#endif
/* multiply tvp by x and store in uvp */
#define timermul(tvp, uvp, x)                   \
    do {                                        \
        (uvp)->tv_sec = (tvp)->tv_sec * x;      \
        (uvp)->tv_usec = (tvp)->tv_usec * x;    \
        while((uvp)->tv_usec > 1000000) {       \
            (uvp)->tv_sec++;                    \
            (uvp)->tv_usec -= 1000000;          \
        }                                       \
    } while(0)
/* multiply tvp by x and store in uvp (with cast) */
#define timermulfloat(tvp, uvp, x)              \
    do {                                        \
        (uvp)->tv_sec = (time_t)((tvp)->tv_sec * x);      \
        (uvp)->tv_usec = (suseconds_t)((tvp)->tv_usec * x);    \
        while((uvp)->tv_usec > 1000000) {       \
            (uvp)->tv_sec++;                    \
            (uvp)->tv_usec -= 1000000;          \
        }                                       \
    } while(0)

using namespace std;

int PfringObserver::noInstances;
//this buffer should be able to hold all packets coming in case of a packet burst
pfring_zc_pkt_buff *buffers[BURST_LEN];

PfringObserver::PfringObserver(const std::string& interface, uint64_t maxpackets, int instances = 0) : thread(PfringObserver::PfringObserverThread), allDevices(NULL),
	captureDevice(NULL), capturelen(PCAP_DEFAULT_CAPTURE_LENGTH),
	maxPackets(maxpackets), ready(false), observationDomainID(0), // FIXME: this must be configured!
	receivedBytes(0), lastReceivedBytes(0), processedPackets(0),
	lastProcessedPackets(0),
	captureInterface(NULL),
	slowMessageShown(false),
	statTotalLostPackets(0), statTotalRecvPackets(0)
{
	cluster_id = DEFAULT_CLUSTER_ID;
	bind_core=-1;
	captureInterface = (char*)malloc(interface.size() + 1);
	strcpy(captureInterface, interface.c_str());
	usedBytes += sizeof(PfringObserver)+interface.size()+1;

	if(capturelen > PCAP_MAX_CAPTURE_LENGTH) {
		THROWEXCEPTION("compile-time parameter PCAP_DEFAULT_CAPTURE_LENGTH (%d) exceeds maximum capture length %d, "
				"adjust compile-time parameter PCAP_MAX_CAPTURE_LENGTH!", capturelen, PCAP_DEFAULT_CAPTURE_LENGTH);

	}
	int cluster_id = DEFAULT_CLUSTER_ID;
	// initialize the InstanceManager
    noInstances = instances;
	getPacketManager();
};

PfringObserver::~PfringObserver()
{
	msg(MSG_DEBUG, "PfringObserver: destructor called");

	// to make sure that exitFlag is set and performShutdown() is called
	shutdown(false);

	/* collect and output statistics */
	pcap_stat pstats;
	if (captureDevice && pcap_stats(captureDevice, &pstats)==0) {
		msg(MSG_DIALOG, "PCAP statistics (INFO: if statistics were activated, this information does not contain correct data!):");
		msg(MSG_DIALOG, "Number of packets received on interface: %u", pstats.ps_recv);
		msg(MSG_DIALOG, "Number of packets dropped by PCAP: %u", pstats.ps_drop);
	}

	msg(MSG_DEBUG, "freeing pcap/devices");
	if(captureDevice) {
		pcap_close(captureDevice);
	}

	/* no pcap_freecode here, is already done after attaching the filter */

	if(allDevices) {
		pcap_freealldevs(allDevices);
	}

	free(captureInterface);
	msg(MSG_DEBUG, "successful shutdown");
}

/*
 This is the main PfringObserver loop. I uses pfring zero copy to fetch packets from the NIC. It is a thread started in performStart().
 */
void *PfringObserver::PfringObserverThread(void *arg)
{

	/* first we need to get the instance back from the void *arg */
	PfringObserver *obs=(PfringObserver *)arg;
	InstanceManager<Packet>& packetManager = getPacketManager();

	Packet *p = NULL;
	//ist eigentlich u_char:
	char *pkt_data;
	//header for packets captured with pfring_zc
	struct pfring_pkthdr pfringHdr;;
	bool have_send = false;
	obs->registerCurrentThread();
	bool file_eof = false;

	msg(MSG_INFO, "PfringObserver started with following parameters:");
	if (obs->captureInterface) msg(MSG_INFO, "  - captureInterface=%s", obs->captureInterface);
	//msg(MSG_INFO, "  - filterString='%s'", (obs->filter_exp ? obs->filter_exp : "none"));
	msg(MSG_INFO, "  - maxPackets=%u", obs->maxPackets);
	msg(MSG_INFO, "  - capturelen=%d", obs->capturelen);
	msg(MSG_INFO, " - dataLinkType=%d", obs->dataLinkType);

	// start capturing packets
	msg(MSG_INFO, "now running capturing thread for device %s", obs->captureInterface);


	while(!obs->exitFlag&& (obs->maxPackets==0 || obs->processedPackets<obs->maxPackets)){
		DPRINTFL(MSG_VDEBUG, "trying to get packet from pcap");
		//third parameter is "wait for packet"
		if(pfring_zc_recv_pkt(obs->zq, &buffers[0], 1) > 0) {
					DPRINTFL(MSG_VDEBUG, "got new packet!");
					p = packetManager.getNewInstance();
					//pfring_zc_pkt_buff_data returns a pointer to the actual packet data
					pkt_data=(char*)pfring_zc_pkt_buff_data(buffers[0], obs->zq);

					memset(&pfringHdr, 0, sizeof(pfringHdr));
					pfringHdr.len = buffers[0]->len, pfringHdr.caplen = buffers[0]->len;

					//arguments 5,1,1 --> layer 5, add_timestamp =1, add_hash=1
					//TODO: do we need to parse lower layers too?
					pfring_parse_pkt((u_char *) pkt_data, &pfringHdr, 5, 1, 1);

					/*initialize packet structure (init copies packet data).*/
					//With hardcoded dataLinkType, not super pretty but works!
					p->init(pkt_data, pfringHdr.caplen, pfringHdr.ts, obs->observationDomainID, pfringHdr.len, DLT_EN10MB);
					DPRINTFL(MSG_VDEBUG,"received packet at %u. %04u, len=%d",
							(unsigned)p->timestamp.tv_sec,
							(unsigned)p->timestamp.tv_usec / 1000,
							pfringHdr.caplen
					);

					// update statistics
					obs->receivedBytes += pfringHdr.caplen;
					obs->processedPackets++;

					while (!obs->exitFlag) {
						DPRINTFL(MSG_VDEBUG, "trying to push packet to queue");
						if ((have_send = obs->send(p))) {
							DPRINTFL(MSG_VDEBUG, "packet pushed");
							break;
						}
					}
		}//if recv_pkt
	}//while

	msg(MSG_DEBUG, "exiting PfringObserver thread");
	obs->unregisterCurrentThread();
	pthread_exit((void *)1);
}


/*
 call after an PfringObserver has been created
 error checking on pcap here, because it can't be done in the constructor
 and it may be too late, if done in the thread
 */
bool PfringObserver::prepare()
{
	//TODO: not needed?!:
	//struct in_addr i_netmask, i_network;

	zc = pfring_zc_create_cluster(cluster_id, capturelen,0,MAX_CARD_SLOTS + BURST_LEN,pfring_zc_numa_get_cpu_node(bind_core),NULL /* auto hugetlb mountpoint */);

	if(zc == NULL) {
		msg(MSG_FATAL, "PfringObserver: pfring_zc_create_cluster error. Please check that pf_ring.ko is loaded and hugetlb fs is mounted\n");
		return false;
		}

	zq = pfring_zc_open_device(zc, captureInterface, rx_only, 0);

	if(zq == NULL) {
		msg(MSG_FATAL, "PfringObserver:pfring_zc_open_device error. Please check that given network device is up and not already used\n");
		return false;
		}

	for (int i = 0; i < BURST_LEN; i++) {
		buffers[i] = pfring_zc_get_packet_handle(zc);
		if (buffers[i] == NULL) {
			msg(MSG_FATAL, "pfring_zc_get_packet_handle error\n");
			return false;
			}
	}

	ready=true;
	return true;

}

/*
   call to get the main capture thread running
   open() has to be called before
*/
void PfringObserver::performStart()
{
	if(!ready)
		THROWEXCEPTION("Can't start capturing, PfringObserver is not ready");

	msg(MSG_DEBUG, "now starting capturing thread");
	thread.run(this);
};

void PfringObserver::performShutdown()
{
	/* be sure the thread is ending */
	msg(MSG_DEBUG, "joining the PfringObserverThread, may take a while (until next pcap data is received)");
	connected.shutdown();
	thread.join();
	msg(MSG_DEBUG, "PfringObserverThread joined");
}


/* you cannot change the caplen of an already running PfringObserver */
bool PfringObserver::setCaptureLen(int x)
{
	msg(MSG_DEBUG, "PfringObserver: setting capture length to %d bytes", x);
	/* we cant change pcap caplen if alredy pcap_open() called */
	if(ready) {
		THROWEXCEPTION("changing capture len on-the-fly is not supported by pcap");
	}
	if (x>PCAP_MAX_CAPTURE_LENGTH) {
		THROWEXCEPTION("maximum capture length is limited by constant PCAP_MAX_CAPTURE_LENGTH (%d), "
				"given value %d is too big", PCAP_MAX_CAPTURE_LENGTH, x);
	}
	capturelen=x;
	return true;
}

int PfringObserver::getCaptureLen()
{
	return capturelen;
}

/*
   get some capturing statistics
   struct pcap_stat is defined in pcap.h and has at least 3 u_int variables:
   ps_recv, ps_drop, ps_ifdrop

   should return: -1 on failure, 0 on OK
   */
int PfringObserver::getPcapStats(struct pcap_stat *out)
{
	return(pcap_stats(captureDevice, out));
}

/**
 * Initializes the instance manager on first use.
 * The first initialized PfringObserver determines the number of preallocated and memory resident instances,
 * which are shared by all PfringObservers.
 * @return the single instance of the used PacketManager
 */
InstanceManager<Packet>& PfringObserver::getPacketManager() {
    static InstanceManager<Packet>* packetManager = new InstanceManager<Packet>("Packet", noInstances);
    return *packetManager;
}

/*
 this function is called by the logger timer thread and should dump
 some nice info using msg_stat
 */
void PfringObserver::doLogging(void *arg)
{
	PfringObserver *obs=(PfringObserver *)arg;
	pfring_zc_stat stats;
	// update statistics
	if (pfring_zc_stats(obs->zq, &stats) == 0){
		msg_stat("%u recv, %u drop", stats.recv, stats.drop);
	}else{
		msg(MSG_INFO,"doLogging: Currently no stats available");
	}

}

/**
 * statistics function called by StatisticsManager
 */
std::string PfringObserver::getStatisticsXML(double interval)
{
	pfring_zc_stat stats;
	ostringstream oss;
	// update statistics
	if (pfring_zc_stats(this->zq, &stats) == 0){

	}else{
		msg(MSG_INFO,"Currently no new stats available, retry in %d", interval);
	}

		oss << "<pfringObserver>";
		oss << "<totalReceived type=\"packets\">" << stats.recv << "</totalReceived>";
		oss << "<totalReceived type=\"bytes\">" << this->receivedBytes << "</totalReceived>";
		oss << "<totalDropped type=\"packets\">" << stats.drop << "</totalDropped>";
		oss << "</pfringObserver>";

	return oss.str();
}
#endif /*pfringZC*/
