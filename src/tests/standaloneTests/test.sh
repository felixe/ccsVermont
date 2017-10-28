#!/bin/bash
#Author: Felix Erlacher
#
#Simple and rudimentary standalone test script to check functionalities in a black box manner.
#We compare output of vermont in different configurations to expected output
#This test script does not require any library and should run in any bash (version > 4).
#requires the command ngrep
#has to be executed from within the ./standaloneTests/ folder

################################
#1
#simplest test case, does vermont run at all?
echo "TEST 1: check output of vermont command"
if [ "$(diff 1-output.txt <(../../../vermont|tail -n5))" != "" ]
	then
		echo "1:FAILED!!!!! Command Vermont does not produce expected output!!!!!"
	else
		echo "1: OK"
fi

################################
#2
#check ipfix export capabilities
echo "TEST 2: check output of vermont HTTP ipfix aggregation"
echo "checking contents of flows.dat:"
../../../vermont -f 2-vermontIpfixExportConfig.xml>/dev/null
if [ -f "flows.dat" ]
then :
else
        echo "ERROR:"
        echo "flows.dat not found. Are you sure you are in the right folder, or executed the script from the right folder?"; exit 0;
fi

#following case statement checks for different substrings, it prints OK if matched and increases a counter, and nothing if no match. If the counter in the end is not like expected (=number of checks) an error message is printed.
NUMCHECK=0;
case "$(cat flows.dat)" in
	*Template* ) echo "2.1:OK"; let "NUMCHECK++";;& #check if it contains ipfix template
	*'pen=2003828736'* ) echo "2.2:OK"; let "NUMCHECK++";;& #check if vermont pen is used
	*': 10.0.2.15/32'* ) echo "2.3:OK"; let "NUMCHECK++";;& #check ip address
	*': 16709'* ) echo "2.4:OK"; let "NUMCHECK++";;& #check src port
	*': 80'* ) echo "2.5:OK"; let "NUMCHECK++";;& #check dst port
	*'GET /bla/a=YWZmaWQ9MDUyODg HTTP/1.1\r\n'* ) echo "2.6:OK"; let "NUMCHECK++";;& #check payload 
	*'HTTP/1.1 404 Not Found\r\nDate: Wed, 09 Aug 2017 13:01:20 GMT\r\nServer:'* ) echo "2.7:OK"; let "NUMCHECK++";;& #check rev payload
	*"httpRequestMethod (id=459, length=16)                       : 'GET'"* ) echo "2.8:OK"; let "NUMCHECK++";;& #check method IE
	*"httpRequestTarget (id=461, length=150)                      : '/bla/a=YWZmaWQ9MDUyODg'"* ) echo "2.9:OK"; let "NUMCHECK++";;& #check target IE
	*"httpMessageVersion (id=462, length=8)                       : 'HTTP/1.1'"* ) echo "2.10:OK"; let "NUMCHECK++";;& #check Version IE
	*"httpRequestHost (id=460, length=50)                         : '10.0.2.4'"* ) echo "2.11:OK"; let "NUMCHECK++";;& #check Host IE
	*"httpRespMessageVersion (id=12, pen=2003828736 [vermont], length=8): 'HTTP/1.1'"* ) echo "2.12:OK"; let "NUMCHECK++";;& #check respMessagVErsion IE
	*"httpStatusCode (id=457, length=2)                           : 404"* ) echo "2.13:OK"; let "NUMCHECK++";;& #check statusCode IE
	*"httpStatusPhrase (id=10, pen=2003828736 [vermont], length=32): 'Not Found'"* ) echo "2.14:OK"; let "NUMCHECK++";; #check statusPhrase IE
esac

if [ $NUMCHECK != 14 ]
	then	echo "2:FAILED!!!!! flows.dat does not have expected content. Only $NUMCHECK of 14 tests succesful!!!!!"
	else rm flows.dat
fi

echo "checking contents of exportet pcap file"
if [[ "$(ngrep -I pcap.dump GET)" == *"YWZmaWQ9MDUyODg"* ]] #this pattern should be contained in the http payload
	then echo "2.pcap:OK"; rm pcap.dump
	else echo "2.pcap:FAILED!!!!! pcap file does not contain expected payload!!!!!"
fi

echo "checking contents of sensor_output file"
if [[ "$(cat sensor_output.xml)" == *"type=\"packets\">6</totalProcessed>"* ]]
	then echo "2.sensor:OK"; rm sensor_output.xml
	else echo "2.sensor:FAILED!!!!! sensor_output.xml does not contain expected content!!!!!"
fi
