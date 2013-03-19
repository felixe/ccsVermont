/*
 PSAMP Reference Implementation
 LibzeroObserver.cpp
 Implementation of the packet capturing thread
 Author: Michael Drueing <michael@drueing.de>

 changed by: Ronny T. Lampert
             Gerhard Münz
 */
 // TODO: credits


#include "LibzeroObserver.h"

#include "common/msg.h"
#include "common/Thread.h"
#include "common/defs.h"

//#include <pcap.h>
#include <unistd.h>
#include <iostream>
#include <sstream>
#include <math.h>

//#include "/home/martin/ntop/userland/lib/pfring.h"

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


LibzeroObserver::LibzeroObserver(const std::string& interface, int numLibzeroObservers, uint64_t maxpackets) : thread(LibzeroObserver::observerThread), 
	capturelen(PCAP_DEFAULT_CAPTURE_LENGTH), 
	maxPackets(maxpackets), ready(false), filter_exp(0), observationDomainID(0), // FIXME: this must be configured!
	receivedBytes(0), lastReceivedBytes(0), processedPackets(0),
	lastProcessedPackets(0),
	captureInterface(NULL), 
	slowMessageShown(false),
	statTotalLostPackets(0), statTotalRecvPackets(0), packetManager("Packet")
{
	captureInterface = (char*)malloc(interface.size() + 1);
    strcpy(captureInterface, interface.c_str());


	usedBytes += sizeof(LibzeroObserver)+interface.size()+1;

	if(capturelen > PCAP_MAX_CAPTURE_LENGTH) {
		THROWEXCEPTION("compile-time parameter PCAP_DEFAULT_CAPTURE_LENGTH (%d) exceeds maximum capture length %d, "
				"adjust compile-time parameter PCAP_MAX_CAPTURE_LENGTH!", PCAP_DEFAULT_CAPTURE_LENGTH, PCAP_MAX_CAPTURE_LENGTH);

	}

    msg(MSG_INFO, "there are %d observers\n", numLibzeroObservers);
};

LibzeroObserver::~LibzeroObserver()
{
	msg(MSG_DEBUG, "LibzeroObserver: destructor called");

	// to make sure that exitFlag is set and performShutdown() is called
	shutdown(false);

	/* collect and output statistics */
	pfring_stat ringStats;
	if (ring && pfring_stats(ring, &ringStats)>=0) {
		msg(MSG_DIALOG, "PF_RING statistics (INFO: if statistics were activated, this information does not contain correct data!):");
		msg(MSG_DIALOG, "Number of packets received on interface: %u", ringStats.recv);
		msg(MSG_DIALOG, "Number of packets dropped by PF_RING: %u", ringStats.drop);
	}


	/* no pcap_freecode here, is already done after attaching the filter */

	free(captureInterface);
	delete[] filter_exp;
	msg(MSG_DEBUG, "successful shutdown");
}
/*
 This is the main observer loop. It graps packets from libpcap and
 dispatches them to the registered receivers.
 */
void *LibzeroObserver::observerThread(void *arg)
{
	/* first we need to get the instance back from the void *arg */
	LibzeroObserver *obs=(LibzeroObserver *)arg;
	InstanceManager<Packet>& packetManager = obs->packetManager;

    /*
	const unsigned char *pcapData;
	obs->registerCurrentThread();
    */
	bool have_send = false;
    bool file_eof = false;

    Packet *p = NULL;
    int i, rc;
    struct pfring_pkthdr hdr;
    u_char buf[obs->capturelen];
    u_char *buffer = buf;


	msg(MSG_INFO, "LibzeroObserver started with following parameters:");
	if (obs->captureInterface) msg(MSG_INFO, "  - captureInterface=%s", obs->captureInterface);
	msg(MSG_INFO, "  - filterString='%s'", (obs->filter_exp ? obs->filter_exp : "none"));
	msg(MSG_INFO, "  - maxPackets=%u", obs->maxPackets);
	msg(MSG_INFO, "  - capturelen=%d", obs->capturelen);

	// start capturing packets
	msg(MSG_INFO, "now running capturing thread for device %s", obs->captureInterface);

    while(!obs->exitFlag && (obs->maxPackets==0 || obs->processedPackets<obs->maxPackets)) {
        rc = pfring_recv(obs->ring, &buffer, obs->capturelen, &hdr, 1);
        if (rc > 0) {

            // initialize packet structure (init copies packet data)
            p = packetManager.getNewInstance();
            p->init((char*)buffer, hdr.caplen, hdr.ts, obs->observationDomainID, hdr.len);

            DPRINTF("received packet at %u.%04u, len=%d",
                (unsigned)p->timestamp.tv_sec,
                (unsigned)p->timestamp.tv_usec / 1000,
                hdr.caplen
            );

            // update statistics
            obs->receivedBytes += hdr.caplen;
            obs->processedPackets++;

            while (!obs->exitFlag) {
                DPRINTFL(MSG_VDEBUG, "trying to push packet to queue");
                if ((have_send = obs->send(p))) {
                    DPRINTFL(MSG_VDEBUG, "packet pushed");
                    break;
                }
            }
        }
    }

    /*
	if (obs->autoExit && (file_eof || (obs->maxPackets && obs->processedPackets>=obs->maxPackets)) ) {
		// notify Vermont to shut down
		DPRINTF("notifying Vermont to shut down, as all PCAP file data was read, or maximum packet count was reached");
		obs->shutdownVermont();
	}
    */

	msg(MSG_DEBUG, "exiting observer thread");
	obs->unregisterCurrentThread();
	pthread_exit((void *)1);
}


/*
 call after an LibzeroObserver has been created
 error checking on pcap here, because it can't be done in the constructor
 and it may be too late, if done in the thread
 */
bool LibzeroObserver::prepare(const std::string& filter)
{
	struct in_addr i_netmask, i_network;

	// we need to store the filter expression, because pcap needs
	// a char* and doesn't accept a const char* ... nasty pcap-devs!!!
	if (!filter.empty()) {
		filter_exp = new char[filter.size() + 1];
		strcpy(filter_exp, filter.c_str());
		usedBytes += filter.size()+1;
	}

    msg(MSG_INFO, "pf_ring opening interface='%s', snaplen=%d",
        captureInterface, capturelen);

    ring = pfring_open(captureInterface, capturelen, PF_RING_PROMISC);
    if (ring == NULL) {
        msg(MSG_FATAL, "Failed to open PF_RING for device %s", captureInterface);
        goto out;
    }

    if(pfring_set_socket_mode(ring, recv_only_mode) < 0) {
        msg(MSG_ERROR, "failed to set pf_ring socket mode to 'recv_only'\n");
        goto out1;
    }

    pfring_enable_ring(ring);
    msg(MSG_INFO, "ring enabled\n");


    /* TODO: use filters for pf_ring?
	if (filter_exp) {
		msg(MSG_DEBUG, "compiling pcap filter code from: %s", filter_exp);
		if(pcap_compile(captureDevice, &pcap_filter, filter_exp, 1, netmask) == -1) {
			msg(MSG_FATAL, "unable to validate+compile pcap filter");
			goto out2;
		}

		if(pcap_setfilter(captureDevice, &pcap_filter) == -1) {
			msg(MSG_FATAL, "unable to attach filter to pcap: %s", pcap_geterr(captureDevice));
			goto out3;
		}
		// you may free an attached code, see man-page
		pcap_freecode(&pcap_filter);
	} else {
		msg(MSG_DEBUG, "using no pcap filter");
	}
    */

	ready=true;

	return true;

out1:
    pfring_close(ring);
out:
	return false;
}


/*
 this function is called by the logger timer thread and should dump
 some nice info using msg_stat
 */
void LibzeroObserver::doLogging(void *arg)
{
	LibzeroObserver *obs=(LibzeroObserver *)arg;
	pfring_stat stats;

	 //pcap_stats() will set the stats to -1 if something goes wrong
	 //so it is okay if we dont check the return code
	obs->getPfRingStats(&stats);
	msg_stat("%6d recv, %6d drop", stats.recv, stats.drop);
}

/*
   call to get the main capture thread running
   open() has to be called before
*/
void LibzeroObserver::performStart()
{
	if(!ready)
		THROWEXCEPTION("Can't start capturing, observer is not ready");

	msg(MSG_DEBUG, "now starting capturing thread");
	thread.run(this);
};

void LibzeroObserver::performShutdown()
{
	/* be sure the thread is ending */
	msg(MSG_DEBUG, "joining the LibzeroObserverThread, may take a while (until next pcap data is received)");
	connected.shutdown();
	thread.join();
	msg(MSG_DEBUG, "LibzeroObserverThread joined");
}


/* you cannot change the caplen of an already running observer */
bool LibzeroObserver::setCaptureLen(int x)
{
	msg(MSG_DEBUG, "LibzeroObserver: setting capture length to %d bytes", x);
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

int LibzeroObserver::getCaptureLen()
{
	return capturelen;
}


/*
   get some capturing statistics
   struct pcap_stat is defined in pcap.h and has at least 3 u_int variables:
   ps_recv, ps_drop, ps_ifdrop

   should return: -1 on failure, 0 on OK
   */
int LibzeroObserver::getPfRingStats(pfring_stat *out)
{
	return(pfring_stats(ring, out));
}

/**
 * statistics function called by StatisticsManager
 */
std::string LibzeroObserver::getStatisticsXML(double interval)
{
	ostringstream oss;
	pfring_stat ringStats;
	if (ring && pfring_stats(ring, &ringStats)>=0) {
		unsigned int recv = ringStats.recv;
		unsigned int dropped = ringStats.drop;

		oss << "<pf_ring>";
		oss << "<received type=\"packets\">" << (uint32_t)((double)(recv-statTotalRecvPackets)/interval) << "</received>";
		oss << "<dropped type=\"packets\">" << (uint32_t)((double)(dropped-statTotalLostPackets)/interval) << "</dropped>";
		oss << "<totalReceived type=\"packets\">" << statTotalRecvPackets << "</totalReceived>";
		oss << "<totalDropped type=\"packets\">" << statTotalLostPackets << "</totalDropped>";
		oss << "</pf_ring>";
		statTotalLostPackets = dropped;
		statTotalRecvPackets = recv;
	}
	uint64_t diff = receivedBytes-lastReceivedBytes;
	lastReceivedBytes += diff;
	oss << "<observer>";
	oss << "<processed type=\"bytes\">" << (uint32_t)((double)diff/interval) << "</processed>";
	diff = processedPackets-lastProcessedPackets;
	lastProcessedPackets += diff;
	oss << "<processed type=\"packets\">" << (uint32_t)((double)diff/interval) << "</processed>";
	oss << "<totalProcessed type=\"packets\">" << processedPackets << "</totalProcessed>";
	oss << "</observer>";
	return oss.str();
}
