/*
 PSAMP Reference Implementation
 LibzeroObserver.cpp
 Declarations for observing process
 Author: Michael Drueing <michael@drueing.de>

 changed by: Ronny T. Lampert
 changed by: Lothar Braun
 */

#ifdef LIBZERO_SUPPORT_ENABLED

#ifndef LIBZEROOBSERVER_H
#define LIBZEROOBSERVER_H


/*
 the to_ms arg to pcap_open_live() - wait this long until returning from pcap_next()
 some platforms don't support it, though.
 FIXME: HOW LONG? 2000ms is REALLY REALLY LONG!
 On a busy network we may want to have it shorter.
 Maybe this should be runtime-configurable.
 */


#include "Packet.h"

#include "common/msg.h"
#include "common/Thread.h"
#include "common/ConcurrentQueue.h"
#include "common/Mutex.h"

#include "core/InstanceManager.h"
#include "core/Source.h"
#include "core/Module.h"

#include <vector>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include<pfring.h>
#undef max


// Define what properties are used to distriubte packets to LibzeroObservers
#define IP_ADDR 0 // IP addresses (src + dest); default
#define MAC 1 // MAC addresses (src + dest)

class LibzeroObserver : public Module, public Source<Packet*>, public Destination<NullEmitable*>
{
public:
	LibzeroObserver(const std::string& interfaces, int numLibzeroObservers, uint64_t maxpackets);
	~LibzeroObserver();

	virtual void performStart();
	virtual void performShutdown();
	bool setCaptureLen(int x);
	void setOfflineAutoExit(bool autoexit);
	int getCaptureLen();
	bool setPacketTimeout(int ms);
	int getPacketTimeout();
	void replaceOfflineTimestamps();
	void setOfflineSpeed(float m);
	int getPfRingStats(pfring_stat *out);
	//bool prepare(const std::string& filter);
	bool prepare(int cluster_id, int hash_mode);
	static void doLogging(void *arg);
	virtual std::string getStatisticsXML(double interval);
	int getDataLinkType();
    int getNumLibzeroObservers();


protected:
	Thread thread;

    pfring *ring;

	// IPv4 netmask + network bitmasks the interface is on
	//uint32_t netmask, network;

	// holding the pcap filter program
	//struct bpf_program pcap_filter;

	// also called snaplen; only sniff this much bytes from each packet
	uint32_t capturelen;

	// maximum number of packets to capture, then stop processing
	// 0 == do not stop
	uint64_t maxPackets;

	// set to true if prepare() was successful
	bool ready;

	// save the given filter expression
	char* filter_exp;

	// manages instances of Packets
	InstanceManager<Packet> packetManager;

	uint32_t observationDomainID;

	// number of received bytes (used for statistics)
	// attention: value may sometimes be incorrect caused by multithreading issues
	volatile uint64_t receivedBytes;
	volatile uint64_t lastReceivedBytes;

	// number of processed packets (used for statistics)
	// attention: value may sometimes be incorrect caused by multithreading issues
	volatile uint64_t processedPackets;
	volatile uint64_t lastProcessedPackets;

	// interfaces we capture traffic on - string
	char *captureInterfaces;

	bool slowMessageShown;	// true if message was shown that vermont is too slow to read file in time

	uint32_t statTotalLostPackets;
	uint32_t statTotalRecvPackets;

	static void *observerThread(void *);

    int numLibzeroObservers; // needed to configurate the DNA-Cluster

    // all LibzeroObservers share this DNA Cluster
    static Mutex mutex;
    static pfring_dna_cluster *cluster;
    static int clusterId;
    static int slavecount;
    static int hashMode;

    static int masterDistributionFunction(const u_char *buffer, const u_int16_t buffer_len,
        const pfring_dna_cluster_slaves_info *slaves_info, u_int32_t *id_mask, u_int32_t *hash);
    static u_int32_t masterCustomHashFunction(const u_char *buffer, const u_int16_t buffer_len);
};

#endif

#endif //LIBZERO_SUPPORT_ENABLED
