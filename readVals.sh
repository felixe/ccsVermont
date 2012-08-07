#!/usr/bin/perl
use XML::Simple;
use Data::Dumper;
$xml = new XML::Simple;
# XML-Datei einlesen



#>> heist zum anhängen öffnen
while (1) {
	open(cpu0, ">>./TestData/cpu00.csv");
	open(cpu1, ">>./TestData/cpu01.csv");
	open(cpu2, ">>./TestData/cpu02.csv");
	open(cpu3, ">>./TestData/cpu03.csv");
	open(cpu4, ">>./TestData/cpu04.csv");
	open(cpu5, ">>./TestData/cpu05.csv");
	open(cpu6, ">>./TestData/cpu06.csv");
	open(cpu7, ">>./TestData/cpu07.csv");
	open(cpu8, ">>./TestData/cpu08.csv");
	open(cpu9, ">>./TestData/cpu09.csv");
	open(cpu10, ">>./TestData/cpu10.csv");
	open(cpu11, ">>./TestData/cpu11.csv");
	open(pcapDrop, ">>./TestData/pcapDropPack.csv");
	open(pcapTotDrop, ">>./TestData/pcapTotDropPack.csv");
	open(pcapRec, ">>./TestData/pcapRecPack.csv");
	open(pcapTotRec, ">>./TestData/pcapTotRecPack.csv");
	open(freeMem, ">>./TestData/freeMem.csv");
	open(totalMem, ">>./TestData/totalMem.csv");
	open(procPack, ">>./TestData/ObserverProcPack.csv");
	open(procBytes, ">>./TestData/ObserverProcBytes.csv");
	open(totPack, ">>./TestData/ObserverTotPack.csv");
	open(pAggEE, ">>./TestData/pAggExportedEntries.csv");
	open(pAggIP, ">>./TestData/pAggIgnoredPackets.csv");
	open(pAggTRP, ">>./TestData/pAggTotalReceivedPackets.csv");
	
	$data = $xml->XMLin("sensor_output.xml");
	# Struktur ausgeben:
	#print Dumper($data);

	print $data->{sensorData}->{epochtime};
	print "\n";
	#print $data->{sensorData}->{sensor}->{observer}->{addInfo}->{observer}->{processed}->[1]->{content};
	print time;
	print "\n";


	print cpu0 "$data->{sensorData}->{epochtime},$data->{sensorData}->{processor}->{0}->{util}->[1]->{content}\n";
	print cpu1 "$data->{sensorData}->{epochtime},$data->{sensorData}->{processor}->{1}->{util}->[1]->{content}\n";
	print cpu2 "$data->{sensorData}->{epochtime},$data->{sensorData}->{processor}->{2}->{util}->[1]->{content}\n";
	print cpu3 "$data->{sensorData}->{epochtime},$data->{sensorData}->{processor}->{3}->{util}->[1]->{content}\n";
	print cpu4 "$data->{sensorData}->{epochtime},$data->{sensorData}->{processor}->{4}->{util}->[1]->{content}\n";
	print cpu5 "$data->{sensorData}->{epochtime},$data->{sensorData}->{processor}->{5}->{util}->[1]->{content}\n";
	print cpu6 "$data->{sensorData}->{epochtime},$data->{sensorData}->{processor}->{6}->{util}->[1]->{content}\n";
	print cpu7 "$data->{sensorData}->{epochtime},$data->{sensorData}->{processor}->{7}->{util}->[1]->{content}\n";
	print cpu8 "$data->{sensorData}->{epochtime},$data->{sensorData}->{processor}->{8}->{util}->[1]->{content}\n";
	print cpu9 "$data->{sensorData}->{epochtime},$data->{sensorData}->{processor}->{9}->{util}->[1]->{content}\n";
	print cpu10 "$data->{sensorData}->{epochtime},$data->{sensorData}->{processor}->{10}->{util}->[1]->{content}\n";
	print cpu11 "$data->{sensorData}->{epochtime},$data->{sensorData}->{processor}->{11}->{util}->[1]->{content}\n";
	print pcapDrop "$data->{sensorData}->{epochtime},$data->{sensorData}->{sensor}->{observer}->{addInfo}->{pcap}->{dropped}->{content}\n";
	print pcapTotDrop "$data->{sensorData}->{epochtime},$data->{sensorData}->{sensor}->{observer}->{addInfo}->{pcap}->{totalDropped}->{content}\n";
	print pcapRec "$data->{sensorData}->{epochtime},$data->{sensorData}->{sensor}->{observer}->{addInfo}->{pcap}->{received}->{content}\n";
	print pcapTotRec "$data->{sensorData}->{epochtime},$data->{sensorData}->{sensor}->{observer}->{addInfo}->{pcap}->{totalReceived}->{content}\n";
	print freeMem "$data->{sensorData}->{epochtime},$data->{sensorData}->{memory}->{free}->{content}\n";
	print totalMem "$data->{sensorData}->{epochtime},$data->{sensorData}->{memory}->{total}->{content}\n";
	print procPack "$data->{sensorData}->{epochtime},$data->{sensorData}->{sensor}->{observer}->{addInfo}->{observer}->{processed}->[1]->{content}\n";
	print procBytes "$data->{sensorData}->{epochtime},$data->{sensorData}->{sensor}->{observer}->{addInfo}->{observer}->{processed}->[0]->{content}\n";
	print totPack "$data->{sensorData}->{epochtime},$data->{sensorData}->{sensor}->{observer}->{addInfo}->{observer}->{totalProcessed}->{content}\n";
	print pAggEE "$data->{sensorData}->{epochtime},$data->{sensorData}->{sensor}->{packetAggregator}->{addInfo}->{hashtable}->{exportedEntries}\n";
	print pAggIP "$data->{sensorData}->{epochtime},$data->{sensorData}->{sensor}->{packetAggregator}->{addInfo}->{ignoredPackets}\n";
	print pAggTRP "$data->{sensorData}->{epochtime},$data->{sensorData}->{sensor}->{packetAggregator}->{addInfo}->{totalReceivedPackets}\n";
	#close(tolleDatei);
	sleep(1);
}



