#include "autofocus_report.h"
#include "autofocus_attribute.h"

report::report() 
	{
	numTotal = 0;
	}

uint64_t report::getTotal()
	{
	return numTotal();
	}

void report::aggregate(uint64_t p_num) 
	{
	numTotal += p_num;
	}

attribute* rep_payload_tcp::createAttribute()
	{
	return new atr_payload_tcp(this);
	}
report_enum rep_payload_tcp::getID() 
	{
	return report::payload_tcp;
	}

attribute* rep_payload_udp::createAttribute()
	{
	return new atr_payload_udp(this);
	}

report_enum rep_payload_udp::getID() 
	{
	return report::payload_udp;
	}

attribute* rep_fanouts::createAttribute()
	{
	return new atr_fanouts(this);
	}
report_enum rep_payload_tcp::getID() 
	{
	return report::payload_fanouts;
	}

void rep_fanouts::post(treeRecord* currentTree,treeRecord* lastTree,uint32_t index)
	{
	list<treeNode*>::iterator iter = specNodes.begin();

	while (iter != specNodes.end()) 
		{

		uint64_t data = (*iter)->data.attributes[report::fanouts]->numCount;

		double percentage = (double) ((data*100) / (double) numTotal;	

		msg(MSG_FATAL,"SUBNET: %s/%d\t	FANOUTS: %03llu (%01.2f%%)\t",
			IPToString((*iter)->data.subnetIP).c_str(),(*iter)->data.subnetBits,
			data,percentage);

		iter++;
		}
	}

void rep_payload_tcp::post()
	{

	list<treeNode*>::iterator iter = specNodes.begin();

	while (iter != specNodes.end()) 
		{

		uint64_t data = (*iter)->data.attributes[report::payload_tcp]->numCount;

		double percentage = (double) ((data*100) / (double) numTotal;	

		msg(MSG_FATAL,"SUBNET: %s/%d\t\t TRAFFIC: %03llu MB (%01.2f%%)\t",
			IPToString((*iter)->data.subnetIP).c_str(),(*iter)->data.subnetBits,
			(*iter)->data.payload/1024/1024,percentage);

		iter++;
		}
	}

void rep_payload_udp::post()
	{


	}

void report::checkNode(treeNode* newnode,uint64_t numMax)
	{
	int threshold = numTotal / numMax;

	if (newnode->delta > threshold) 
		{
		newnode->ddata = newnode->delta;
		newnode->delta = 0;
		specNodes.push_back(newnode);
		}
	}