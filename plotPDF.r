csvDir <- "./TestData"
#
#get plot label from a given header name
#
y_names <- c("cpu0","cpu1","cpu2","cpu3","cpu4","cpu5","cpu6","cpu7","freeMem","totalMem","ObserverProcPack","ObserverProcBytes","ObserverTotPack","pAggExportedEntries","pAggIgnoredPackets","pAggTotalReceivedPackets")
y_units <- c("User CPU usage [%]","User CPU usage [%]","User CPU usage [%]","User CPU usage [%]","User CPU usage [%]","User CPU usage [%]","User CPU usage [%]","User CPU usage [%]","Free memory [bytes]","Total memory [bytes]","Processed packets on PCAP [packets/s]","Processed bytes on PCAP [bytes/s]","Total packets on PCAP [packets]","Exported entries in PacketAggregator [entries]","Ignored Packets in PacketAggregator [Packets]","Total received packets in PacketAggregator [packets/s]")
getylabelfromname <- function(header) {
  index <- 1
  for(i in y_names) {
     if(length(grep(i,header,ignore.case=TRUE)) != 0) {
       return(y_units[index])
     }
     index <- index+1
  }
  return("N/A")
}

#
#cuts of a given number of rows from a data frame
#
cutdatarows <- function(data,front,back) {
  #drop first N data rows
  for(i in 1:front) {
    data <- data[-1,]
  }
  
  #drop last N data rows
  for(i in 1:front) {
    data <- data[-length(data[,1]),]
  }
  return(data)
}

#
#standard Plot function
#
myPlot <- function(csvFile,xlabel,title){
	pdfName <- paste(title,".pdf",sep="")
	#print(pdfName,stdout())
	pdf(pdfName,width=27,height=8.26)
	par(mfcol=c(1,1))
	MyVals <- read.delim(csvFile,sep=",")
	#sometimes first two lines contain broken data
	MyVals <- cutdatarows(MyVals,2,0)

	x<-MyVals[,1]
	#epochtime, but we want to start from zero
	times <- x-x[1]
	y<-MyVals[,2]
	plot(times,y,col="red",type="l",xlab=xlabel,ylab=getylabelfromname(title))
}

#------------
#MAIN
#-----------
fl <- list.files(path=csvDir,recursive = FALSE, pattern=".*csv$")
setwd(csvDir)
for(i in fl){
	#filePath <-paste(csvDir,i,sep="/")
	if(file.info(i)$size!=0){
		flname<-i
		#substitute .csv with nothing	
		flname<-sub(".csv","",flname)
#		write(flname,stdout())
		myPlot(i,"Time[s]",flname)
	}
}
dev.off()
