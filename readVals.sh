#!/usr/bin/perl
use XML::Simple;
use Data::Dumper;
$xml = new XML::Simple;
# XML-Datei einlesen




while (1) {
	open(cpu0, ">>./TestData/cpu0.csv");
	open(cpu1, ">>./TestData/cpu1.csv");
	open(cpu2, ">>./TestData/cpu2.csv");
	open(cpu3, ">>./TestData/cpu3.csv");
	open(cpu4, ">>./TestData/cpu4.csv");
	open(cpu5, ">>./TestData/cpu5.csv");
	open(cpu6, ">>./TestData/cpu6.csv");
	open(cpu7, ">>./TestData/cpu7.csv");
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



