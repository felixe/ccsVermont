csvDir <- "./TestData"
#
#get plot label from a given header name
#
y_names <- c("cpu0","cpu1","cpu2","cpu3","cpu4","cpu5","cpu6","cpu7","freeMem","totalMem","ObserverProcPack","ObserverProcBytes","ObserverTotPack","pAggExportedEntries","pAggIgnoredPackets","pAggTotalReceivedPackets","Overall CPU Utilization","pcapDropPack","pcapRecPack","pcapTotDropPack","PcapTotRecPack")
y_units <- c("User CPU usage [%]","User CPU usage [%]","User CPU usage [%]","User CPU usage [%]","User CPU usage [%]","User CPU usage [%]","User CPU usage [%]","User CPU usage [%]","Free memory [bytes]","Total memory [bytes]","Processed packets at Observer [packets/s]","Processed bytes at Observer [bytes/s]","Total packets at Observer [packets]","Exported entries in PacketAggregator [entries]","Ignored Packets in PacketAggregator [Packets]","Total received packets in PacketAggregator [packets/s]","CPU usage [%]","Dropped packets at PCAP [packets/s]","Received packets at PCAP [packets/s]","Total dropped packets at PCAP [packets]","Total received packets at PCAP [packets]")
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

#
#do a stack plot for some given files
#
dostackplot <- function(fl,title,ylabel) {
  colors <- c("orange","blue","green","red","yellow","black","brown","pink","blueviolet","burlywood","azure4","coral4");
#  colors <- c("black","blue3","cornflowerblue","cyan","aquamarine","darkolivegreen1","chartreuse1","chartreuse4");
  ci <- 1 # current color index  
  dnames <- c()
  dcols <- c()
  
  #read first data set to get some X/Y ranges
  fu <- read.delim(fl[1],na.strings="nan",sep=",")
  fu <- cutdatarows(fu,3,3) # cut of values which are corrupt in some cases
  
  u <- fu[,2]

  times <- fu[,1]
  tmpvals <- u
  dl <- length(times)
  

  #iterate over all data sets to determine stack maximum 
  sum <- seq(0,0,len=dl)
  for(i in fl) {
    #get header values
    u2 <- read.delim(i,na.strings="nan",nrows=2,sep=",")
    #get name for legend
    dnames <- c(dnames,sub(".csv","",i))

    #get data values
    fu <- read.delim(i,na.strings="nan",sep=",")
    fu <- cutdatarows(fu,3,3)

    u <- fu[,2]

    #sum up data vectors
    sum <- sum + u
  }
  
  #bring X/Y values to identical sizes
  pl <- min(length(times),length(tmpvals))
  times <- times[1:pl]
  tmpvals <- tmpvals[1:pl]

  timeN <- times-times[1]
  #set plot ranges
  minx <- min(timeN,na.rm=TRUE)
  maxx <- max(timeN,na.rm=TRUE)
  xlimits <- c(minx,maxx) 
  miny <- 0
  maxy <- max(sum,na.rm=TRUE)
 #maxy <- max(sum,na.rm=TRUE)
  ylimits <- c(0,maxy)

  plot(timeN,tmpvals,xlim=xlimits,ylim=ylimits,type="n",main=title,xlab="time [s]",ylab=ylabel) #type=n means only axes no x or y drawn
  
  #if we plot data from top to bottom we can use the histogram type to create a stack plot...
  for(i in fl) {
     dcols <- c(dcols,colors[ci])
     sum <- sum[1:pl]
     lines(timeN,sum,col=colors[ci],type="h") #add data set by drawing a line from x to y in type=h ->hystogram style
     
     fu <- read.delim(i,na.strings="nan",sep=",") #get next data set
     fu <- cutdatarows(fu,3,3)

     u <- fu[,2]
     
     sum <- sum - u #go down
     ci <- ci+1 #increment color index
  } 
  
  legend(minx,maxy,dnames, cex=0.8,col=dcols,pch=21:22, lty=1:2,)
}

#plots a graph with the difference vectors of two given file names
#plottypes: 0 = both, 1=plot only, 2=boxplot only
dodiffplot <- function(file1,file2,title,ylabel,plottype) {

  #get data values
  fu1 <- read.delim(file1,na.strings="nan",sep=",")
  fu1 <- cutdatarows(fu1,3,3) # cut of values which are corrupt in some cases

  fu2 <- read.delim(file2,na.strings="nan",sep=",")
  fu2 <- cutdatarows(fu2,3,3) # cut of values which are corrupt in some cases

  u1 <- fu1[,2]
  u2 <- fu2[,2]
  times1 <- fu1[,1]
  times2 <- fu2[,1]

  #check if starting timestamps match
  #if(times1[1,1] != times2[1,1])
  #  print("dodiffplot time [s] values are not identical!")
  
  #bring X/Y values to identical sizes
  pl <- min(length(fu1[,1]),length(fu2[,1]),length(u1),length(u2))
  times <- fu1[,1]
  times <- times[1:pl]  
  vals1 <- u1
  vals1 <- vals1[1:pl]
  vals2 <- u2
  vals2 <- vals2[1:pl]

  vals3 <- vals1-vals2

  normalizedTimes <- times-times[1]

  if(plottype == 0 || plottype == 1) {
    plot(normalizedTimes,vals3,col="red",type="l",main=title,xlab="time [s]",ylab=ylabel)
  }
  if(plottype == 0 || plottype == 2) {
    boxplot(vals3,main="tscheckTscheck",xlab="time [s]",ylab=ylabel);
  }
}

#------------
#MAIN
#-----------
	fl <- list.files(path=csvDir,recursive = FALSE, pattern=".*csv$")
	setwd(csvDir)
	
        cat(names(fl),sep="\n")
	#do simple plot for all files
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

	#do stackplot for all cpu files
	#all cpu files from working dir, changed already above
	cpufiles <- list.files(getwd(),recursive = FALSE, pattern="cpu.*csv$")
	pdf("OverallCPU.pdf",paper="a4r",width=50,height=20)
	par(mfcol=c(1,1))
	dostackplot(cpufiles,"Overall CPU Utilization","CPU Usage [%]")
	dev.off()
	
	totDropFile <- "pcapDropPack.csv"
	totRecFile <- "pcapRecPack.csv"
	pdf("pcapProcPack.pdf",paper="a4r", width=50, height=20)
	par(mfcol=c(1,1))
	dodiffplot(totRecFile,totDropFile,"Processed Packets on PCAP","Processed packets [packets/s]",1)
	dev.off()
