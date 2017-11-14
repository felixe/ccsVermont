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
//for the moment this seems the right thing to do:
//TODO: maybe make user definable in future?!?
int num_threads = 1;
u_int8_t wait_for_packet = 1;
//zc only supports rx, for everything else rx_and_tx_direction would be ok
packet_direction direction = rx_only_direction;

PfringObserver::PfringObserver(const std::string& interface, uint64_t maxpackets, int instances = 0) : thread(PfringObserver::PfringObserverThread), allDevices(NULL),
	captureDevice(NULL), capturelen(PCAP_DEFAULT_CAPTURE_LENGTH),
	maxPackets(maxpackets), ready(false), observationDomainID(0), // FIXME: this must be configured!
	receivedBytes(0), lastReceivedBytes(0), processedPackets(0),
	lastProcessedPackets(0),
	captureInterface(NULL),
	slowMessageShown(false),
	statTotalLostPackets(0), statTotalRecvPackets(0)
{
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
	pfring_stat pfringStat;
	msg(MSG_DEBUG, "PfringObserver: destructor called");

	// to make sure that exitFlag is set and performShutdown() is called
	shutdown(false);

	msg(MSG_DIALOG, "PfringObserver: PCAP statistics (INFO: if statistics were activated, this information does not contain correct data!):");
	msg(MSG_DIALOG, "PfringObserver: Number of processed packets: %u", this->processedPackets);
	msg(MSG_DIALOG, "PfringObserver: Number of processed bytes: %u", this->receivedBytes);
	if(pfring_stats(this->ring, &pfringStat)){
		msg(MSG_DIALOG, "PfringObserver: Number of packets dropped by PCAP: %u", pfringStat.drop);
	}

	msg(MSG_DEBUG, "PfringObserver: freeing pcap/devices");
	if(captureDevice) {
		pcap_close(captureDevice);
	}
	pfring_close(this->ring);

	/* no pcap_freecode here, is already done after attaching the filter */

	if(allDevices) {
		pcap_freealldevs(allDevices);
	}

	free(captureInterface);
	msg(MSG_DEBUG, "PfringObserver: successful shutdown");
}

/*
 This is the main PfringObserver loop. It uses pfring zero copy to fetch packets from the NIC. It is a thread started in performStart().
 */
void *PfringObserver::PfringObserverThread(void *arg)
{
	/* first we need to get the instance back from the void *arg */
	PfringObserver *obs=(PfringObserver *)arg;
	InstanceManager<Packet>& packetManager = getPacketManager();
	u_int numCPU = sysconf( _SC_NPROCESSORS_ONLN );
	u_char buffer[ZC_BUFFER_LEN];
	u_char *bufferPointer = buffer;
	int rc;
	Packet *p = NULL;
	//header for packets captured with pfring_zc
	struct pfring_pkthdr pfringHdr;
	bool have_send = false;
	obs->registerCurrentThread();
	bool file_eof = false;

	//TODO: until now num_threads is hardcoded to 1. Ev. implement else branch and think about making core id user definable
	if(num_threads <= 1) {
		//2. arg is core id,
		if((rc = obs->bindthread2core(pthread_self(), 0)) !=0){
			msg(MSG_FATAL, "PfringObserver: bindthread2core returned %d", rc);
		}
	}

	memset(&pfringHdr, 0, sizeof(pfring_pkthdr));
	memset(&pfringHdr.extended_hdr.parsed_pkt, 0, sizeof(struct pkt_parsing_info));

	obs->ring->break_recv_loop = 0;

	msg(MSG_INFO, "PfringObserver started with following parameters:");
	if (obs->captureInterface) msg(MSG_INFO, "  - captureInterface=%s", obs->captureInterface);
	msg(MSG_INFO, "  - maxPackets=%u", obs->maxPackets);
	msg(MSG_INFO, "  - capturelen=%d", obs->capturelen);
	msg(MSG_INFO, " - dataLinkType=%d", obs->dataLinkType);

	// start capturing packets
	msg(MSG_INFO, "PfringObserver: now running capturing thread for device %s", obs->captureInterface);



	while(!obs->exitFlag&& (obs->maxPackets==0 || obs->processedPackets<obs->maxPackets && !obs->ring->break_recv_loop)){
		DPRINTFL(MSG_VDEBUG, "PfringObserver: trying to get packet from pfring");
	    if((rc = pfring_recv(obs->ring, &bufferPointer, ZC_BUFFER_LEN, &pfringHdr, wait_for_packet)) > 0) {
			p = packetManager.getNewInstance();
			/*initialize packet structure (init copies packet data).*/
			//With hardcoded dataLinkType, not super pretty but works!
			p->init((char*)bufferPointer, pfringHdr.caplen, pfringHdr.ts, obs->observationDomainID, pfringHdr.len, DLT_EN10MB);
			DPRINTFL(MSG_VDEBUG,"PfringObserver: received packet at %u. %04u, len=%d",
					(unsigned)p->timestamp.tv_sec,
					(unsigned)p->timestamp.tv_usec / 1000,
					pfringHdr.caplen
			);

			// update statistics
			obs->receivedBytes += pfringHdr.caplen;
			obs->processedPackets++;

			while (!obs->exitFlag) {
				DPRINTFL(MSG_VDEBUG, "PfringObserver: trying to push packet to queue");
				if ((have_send = obs->send(p))) {
					DPRINTFL(MSG_VDEBUG, "PfringObserver: packet pushed");
					break;
				}
			}
	    }
	}//while

	msg(MSG_DEBUG, "PfringObserver: exiting PfringObserver thread");
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
	int rc;
	u_int32_t flags = 0;
    int ifindex = -1;
	flags |= PF_RING_PROMISC;
	flags |= PF_RING_ZC_SYMMETRIC_RSS;  /* Note that symmetric RSS is ignored by non-ZC drivers */

//THESE ARE ALL OTHER POSSIBLE FLAGS
//	if(num_threads > 1)         flags |= PF_RING_REENTRANT;
//	  if(use_extended_pkt_header) flags |= PF_RING_LONG_HEADER;
//	  if(enable_hw_timestamp)     flags |= PF_RING_HW_TIMESTAMP;
//	  if(!dont_strip_timestamps)  flags |= PF_RING_STRIP_HW_TIMESTAMP;
//	  if(chunk_mode)              flags |= PF_RING_CHUNK_MODE;
//	  if(enable_ixia_timestamp)   flags |= PF_RING_IXIA_TIMESTAMP;

	ring = pfring_open(captureInterface, capturelen, flags);

	if(ring == NULL) {
	  msg(MSG_FATAL, "PfringObserver: pfring_open error [%s] (pf_ring not loaded or interface %s is down ?)",
		strerror(errno), captureInterface);
	  return false;
	} else {
	u_int32_t version;
	pfring_set_application_name(ring, "Vermont");
	pfring_version(ring, &version);

	msg(MSG_INFO, "PfringObserver: Using PF_RING v.%d.%d.%d",
			 (version & 0xFFFF0000) >> 16,
			 (version & 0x0000FF00) >> 8,
			 version & 0x000000FF);
	}

    //msg(MSG_INFO, "Capturing from %s", device);
	msg(MSG_INFO, "PfringObserver: Device RX channels: %d", pfring_get_num_rx_channels(ring));
	msg(MSG_INFO, "PfringObserver: Polling threads:    %d", num_threads);

	if((rc = pfring_set_direction(ring, direction)) != 0){
	  msg(MSG_FATAL, "PfringObserver: pfring_set_direction returned %d (perhaps you use a direction other than rx only with ZC?)", rc);
	  return false;
	}

	switch(direction){
		case rx_and_tx_direction:
			msg(MSG_INFO, "PfringObserver: pfring capture direction is rx and tx");
			break;
		case rx_only_direction:
			msg(MSG_INFO, "PfringObserver: pfring capture direction is rx only");
			break;
		case tx_only_direction:
			msg(MSG_INFO, "PfringObserver: pfring capture direction is tx only");
			break;
	}

	if((rc = pfring_set_socket_mode(ring, recv_only_mode)) != 0){
	  msg(MSG_FATAL, "PfringObserver: pfring_set_socket mode returned %d", rc);
	  return false;
	}

	if (pfring_enable_ring(ring) != 0) {
		msg(MSG_FATAL, "PfringObserver: Unable to enable pfring ring");
		pfring_close(ring);
		return false;
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
		THROWEXCEPTION("PfringObserver: Can't start capturing, PfringObserver is not ready");

	msg(MSG_DEBUG, "PfringObserver: now starting capturing thread");
	thread.run(this);
};

void PfringObserver::performShutdown()
{
	/* be sure the thread is ending */
	msg(MSG_DEBUG, "PfringObserver: joining the PfringObserverThread, may take a while (until next pcap data is received)");
	connected.shutdown();
	thread.join();
	msg(MSG_DEBUG, "PfringObserver: PfringObserverThread joined");
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
		THROWEXCEPTION("PfringObserver: maximum capture length is limited by constant PCAP_MAX_CAPTURE_LENGTH (%d), "
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
	pfring_stat pfringStat;

	if(pfring_stats(obs->ring, &pfringStat)){
		msg_stat("%u pkts recv, %u B recv", obs->processedPackets, obs->receivedBytes);
	}else{
		msg_stat("%u pkts recv, %u B recv, %u pkts dropped", obs->processedPackets, obs->receivedBytes, pfringStat.drop);
	}
}

/**
 * statistics function called by StatisticsManager
 */
std::string PfringObserver::getStatisticsXML(double interval)
{
	pfring_stat pfringStat;
	ostringstream oss;
	// update statistics
	if(pfring_stats(this->ring, &pfringStat)){

	}else{
		msg(MSG_INFO,"Currently no new stats available, retrying in %d", interval);
	}

	oss << "<pfringObserver>";
	oss << "<totalReceived type=\"packets\">" << this->processedPackets << "</totalReceived>";
	oss << "<totalReceived type=\"bytes\">" << this->receivedBytes << "</totalReceived>";
	oss << "<totalReceivedPfring type=\"packets\">" << pfringStat.recv<< "</totalDropped>";
	oss << "<totalDroppedPfring type=\"packets\">" << pfringStat.drop << "</totalDropped>";
	oss << "<totalShuntPfring type=\"packets\">" << pfringStat.shunt << "</totalDropped>";
	oss << "</pfringObserver>";

	return oss.str();
}

u_int8_t PfringObserver::pfring_get_num_rx_channels(pfring *ring) {
  if(ring && ring->get_num_rx_channels)
    return ring->get_num_rx_channels(ring);

  return 1;
}

/* Bind this thread to a specific core */

int PfringObserver::bindthread2core(pthread_t thread_id, u_int core_id) {
#ifdef HAVE_PTHREAD_SETAFFINITY_NP
  cpu_set_t cpuset;
  int s;

  CPU_ZERO(&cpuset);
  CPU_SET(core_id, &cpuset);
  if((s = pthread_setaffinity_np(thread_id, sizeof(cpu_set_t), &cpuset)) != 0) {
    msg(MSG_FATAL, "Error while binding to core %u: errno=%i", core_id, s);
    return(-1);
  } else {
    return(0);
  }
#else
  msg(MSG_DIALOG, "WARNING: your system lacks of pthread_setaffinity_np() (not core binding)");
  return(0);
#endif
}
#endif /*pfringZC*/
