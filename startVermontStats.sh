#!/bin/bash
#start readVals in new screen named blabla
screen -d -m -S blabla ./readVals.sh
#start vermont with command line parameter as config
./vermont -f $1 > ./TestData/vermont.log 
#sleep 10
#now that vermont is finished quit blabla 
screen -S blabla -X quit
#create plots
R < plotPDF.r --vanilla
#and move every interesting file in new folder
momDate=$(date +%F_%R)
mkdir ./TestData/$momDate
cp $1 ./TestData/$momDate
#move only files into subfolder
find ./TestData -maxdepth 1 -type f -exec mv {} ./TestData/$momDate \;
