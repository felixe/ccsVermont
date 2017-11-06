/*
 PSAMP Reference Implementation
 PfringObserver.cpp
 Declarations for observing process
 Author of original Observer.h: Michael Drueing <michael@drueing.de>
 	 changed by: Ronny T. Lampert
 	 changed by: Lothar Braun

 pfringZC enhancement: Felix Erlacher
 */

//following flag is set within cmake
#ifdef PFRING_ZC_ENABLED

#ifndef PFRINGOBSERVER_H
#define PFRINGOBSERVER_H


/*
 the to_ms arg to pcap_open_live() - wait this long until returning from pcap_next()
 some platforms don't support it, though.
 FIXME: HOW LONG? 2000ms is REALLY REALLY LONG!
 On a busy network we may want to have it shorter.
 Maybe this should be runtime-configurable.
 */
#define PCAP_TIMEOUT 100
//pfring zerocopy stuff
#define DEFAULT_CLUSTER_ID          99
#define MAX_CARD_SLOTS      32768
//TODO: make this user definable?
#define BURST_LEN   32

#include "Packet.h"

#include "common/msg.h"
#include "common/Thread.h"
#include "common/ConcurrentQueue.h"
#include "common/defs.h"

#include "core/InstanceManager.h"
#include "core/Source.h"
#include "core/Module.h"

#include <unistd.h>
#include <iostream>
#include <sstream>
#include <math.h>
#include <vector>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>

#include "common/pfring/pfring_utils.h"
#include "pfring.h"
#include "pfring_zc.h"





class PfringObserver : public Module, public Source<Packet*>, public Destination<NullEmitable*>
{
public:
	PfringObserver(const std::string& interface, uint64_t maxpackets, int instances);
	~PfringObserver();

	virtual void performStart();
	virtual void performShutdown();
	bool setCaptureLen(int x);
	int getCaptureLen();
	int getPcapStats(struct pcap_stat *out);
	bool prepare();
	static void doLogging(void *arg);
	virtual std::string getStatisticsXML(double interval);
	static InstanceManager<Packet>& getPacketManager();

protected:
	Thread thread;

	// pointer to list of pcap-devices
	pcap_if_t *allDevices;

	// pcap descriptor of device
	pcap_t *captureDevice;

	// IPv4 netmask + network bitmasks the interface is on
	uint32_t netmask, network;

	// pcap reports error nicely, this is the used buffer
	char errorBuffer[PCAP_ERRBUF_SIZE];

	// also called snaplen; only sniff this much bytes from each packet
	uint32_t capturelen;

	// maximum number of packets to capture, then stop processing
	// 0 == do not stop
	uint64_t maxPackets;

	// set to true if prepare() was successful
	bool ready;

	uint32_t observationDomainID;

	// number of received bytes (used for statistics)
	// attention: value may sometimes be incorrect caused by multithreading issues
	volatile uint64_t receivedBytes;
	volatile uint64_t lastReceivedBytes;

	// number of processed packets (used for statistics)
	// attention: value may sometimes be incorrect caused by multithreading issues
	volatile uint64_t processedPackets;
	volatile uint64_t lastProcessedPackets;

	// interface we capture traffic on - string
	char *captureInterface;

	bool slowMessageShown;	// true if message was shown that vermont is too slow to read file in time

	uint32_t statTotalLostPackets;
	uint32_t statTotalRecvPackets;

	static void *PfringObserverThread(void *);

	int dataLinkType; // contains the datalink type of the capturing device

    static int noInstances; // defines the number of packet instances which should be preallocated by the instance manager

	//pfring zeroCopy specific stuff:
	int cluster_id;
	int bind_core;
	pfring_zc_cluster *zc;
	pfring_zc_queue *zq;
};

#endif /*PFRINGOBSERVER_H*/
#endif
