/*
 this is vermont.
 released under GPL v2

 (C) by Ronny T. Lampert

 */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>

/* 
 foreign subsystems: sampler
 */
#include "ipfixlolib.h"
#include "Packet.h"
#include "Observer.h"
#include "PacketSink.h"
#include "ExporterSink.h"
#include "Filter.h"
#include "Template.h"
#include "IPHeaderFilter.h"

/* collector */


/* own systems */
#include "iniparser.h"
#include "msg.h"
#include "subsystems.h"


static void usage();
static void sig_handler(int x);
static int setup_signal(int signal, void (*handler)(int));
int vermont_readconf(char *file, dictionary **conf);
static Template * configure_template(char *list);

/* initialized subsystems */
unsigned int v_subsystems;

/* holding all objects/handles/... for the subsystems like sampler and collector */
struct {

	/* for sampler */
	Observer *observer;
	vector<Filters *> filters;
	vector<PacketProcessor *> processors;
	Template *template;
	ExporterSink *exporter;
		
	/* for collector */
	int collector_handle;
	/* callbacks ... ? */

} v_objects;


int main(int ac, char **dc)
{
	dictionary *config;
	int c, debug_level=MSG_DEFAULT;
        char *config_file=NULL;

	/* parse command line */
	while((c=getopt(ac, dc, "hf:d")) != -1) {

		switch(c) {

		case 'f':
			config_file=optarg;
			break;

		case 'd':
			debug_level++;
                        break;

		case 'h':
			usage();
                        return 0;

		default:
			usage();
                        break;
		}
	}

	/* setup verboseness */
	msg_setlevel(debug_level);

	setup_signal(SIGINT, sig_handler);

	if(vermont_readconf(config_file, &config)) {
		exit(-1);
	}

        configure_template(iniparser_getvalue(config, "sampler", "filters"));

	subsys_dump(v_subsystems);
	iniparser_dump(config, stdout);

        return 0;
}


/*
 read the config from *file and attach the iniparser stuff to **conf
 perform basic checks
 */
int vermont_readconf(char *file, dictionary **conf)
{
        dictionary *d;

	/* read configuration */
	d=iniparser_new(file);
	if(!d) {
		msg(MSG_FATAL, "could not open config_file %s", file);
                return(-1);
	}

        /* check if all section we need are present */
	if((iniparser_find_entry(d, "collector") == 1) &&
	   (iniparser_find_entry(d, "sampler") == 1) &&
	   (iniparser_find_entry(d, "main") == 1)
	  ) {
		subsys_on(&v_subsystems, SUBSYS_CONFIG);
		*conf=d;

		return 0;

	} else {
		msg(MSG_FATAL, "not all needed sections in config %s", file);

		return -1;
	}
}


/* configure the sampler template from a "," separated list */
static Template * configure_template(char *list)
{

	Template *t;
	int tmpid;
	char *l, *token;
	
	/* violating the original string is not nice, so copy */
	if(!(l=strdup(list))) {
		goto bad_err;
	}
	
        /* assemble the Template */
	//t=new Template(id);

	while((token=strsep(&l, ","))) {
	
		/* lookup field */
		tmpid=ipfix_name_lookup(token);
		msg(MSG_INFO, "Template: adding %s -> %d", token, tmpid);

		if(tmpid == -1) {
			msg(MSG_ERROR, "Ignoring unknown template field %s", token);
                        continue;
		}
		//t->addField((uint16_t)tmpid, <??>, <??>);
	}

	free(l);
	return t;

bad_err:
        return NULL;

}


/* bla bla bla */
static void usage()
{
	printf(
	       "VERsatile MONitoring Tool - VERMONT\n" \
	       " mandatory:\n" \
	       "    -f <inifile>     load config\n" \
	       " optional:\n" \
	       "    -d               increase debug level\n" \
	      );
}


static int setup_signal(int signal, void (*handler)(int))
{
	struct sigaction sig;

	sig.sa_handler=sig_handler;
        sig.sa_flags=SA_RESTART;
        sigemptyset(&sig.sa_mask);
        return(sigaction(signal, &sig, NULL));
}


/* just shallow right now */
static void sig_handler(int x)
{
        msg(MSG_DIALOG, "got signal %d", x);
}
