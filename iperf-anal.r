#!/usr/local/bin/r

## iperf Test Summary

## Generate a summary plot from iperfsum output
## Jon Meek - April 2016

## Assume synchronized clocks, could add option to align
## Assume that file names are 'synchronized', see below for examples, manually re-name if needed


## iperf-anal.r --outdir /n2/r-reports --datadir /home/meekj/temp/tcpd/iperf-20160410 --test t1-192.168.205.10
## iperf-anal.r --outdir /n2/r-reports --datadir /home/meekj/temp/tcpd/iperf-20160410 --test t2-192.168.205.10

## iperf-anal.r --outdir /Users/meekj/r-reports --datadir /Users/meekj/data/tcpd/iperf-20160410 --test t1-192.168.205.48


## iperf-anal.r --datadir /home/meekj/temp/tcpd/iperf-20160410 --test t2-192.168.205.10

## Sample file names:
##  fSnd <- 't1-192.168.205.48-snd.dat'
##  fRcv <- 't1-192.168.205.48-rcv.dat'

RSCid <- "$Id: iperf-anal.r,v 1.5 2016/04/30 15:28:04 meekj Exp $"

USE_XTABLE <- FALSE

suppressMessages(library(ggplot2))
suppressMessages(library(dplyr))
suppressMessages(library(gridExtra))
suppressMessages(library(stringr))
suppressMessages(library(knitr))
suppressMessages(library(docopt))




doc <- "Usage: iperf-anal.r [--help --datadir <datadir> --outdir <outdir> --test <test>]

-h --help           Show this help text
--datadir <datadir> Data directory
--outdir <outdir>   Report directory, default is data directory
--test <test>       Name of the test, filename without trailing -snd.dat / -rcv.dat
"
opt <- docopt(doc)

FileDir  <- opt[["datadir"]]
OutDir   <- opt[["outdir"]]
TestName <- opt[["test"]]

if (is.null(opt[["outdir"]])) { # --test not specified, so put report in the data directory
    OutDir <- FileDir
}
OutFile <- paste(OutDir, '/', TestName, '.html', sep = '')
## OutFile <- paste(OutDir, '/', TestName, '.pdf', sep = '')

setwd(OutDir) # This will put the 'figure' directory with temporary image files in the same directory as the output


## Form the data file names
FileSnd <- paste(FileDir, '/', TestName, '-snd.dat', sep = '')
FileRcv <- paste(FileDir, '/', TestName, '-rcv.dat', sep = '')


cat("TestName",TestName , "\n")
cat("FileSnd", FileSnd, "\n")
cat("FileRcv", FileRcv, "\n")


## Add check that files actually exist

PointSize <- 4 # This needs to increase if Figure{Width, Height} are increased

FigureWidth  <- 20 # For knitr
FigureHeight <- 10

theme_jm1 <- theme_bw() +
    theme(
        plot.title  = element_text(size = rel(1.5), family = 'Helvetica', face = 'bold'),
        axis.title  = element_text(size = rel(1.5), colour = "black", face = 'bold'),
        axis.text.x = element_text(size = rel(1.5), lineheight = 0.9, colour = "black", vjust = 1, face = 'bold'),
        axis.text.y = element_text(size = rel(1.5), lineheight = 0.9, colour = "black", hjust = 1, face = 'bold'),
        strip.text.y = element_text(size = rel(1.7), colour = "black", face = 'bold'),
        legend.text = element_text(size = rel(1.3))
    )



Sys.setenv(TZ="UTC")

HeaderLinesCount <- 3

l1 <- readLines(FileSnd, n = HeaderLinesCount)

Title <- paste(word(l1[2], start = 2), word(l1[3], start = 2, end = 3), sep = '   ') # Not a great method...

TestDirection <- word(l1[2], start = 2)
TestDateTime  <- word(l1[3], start = 2, end = 3)

t1      <- read.table(FileSnd, skip=HeaderLinesCount, header = TRUE)
t1$Time <- as.POSIXct(strptime(as.character(t1$Time), format = "%Y-%m-%dT%H:%M:%S"))
t1$View <- 'snd'

t2      <- read.table(FileRcv, skip=HeaderLinesCount, header = TRUE)
t2$Time <- as.POSIXct(strptime(as.character(t2$Time), format = "%Y-%m-%dT%H:%M:%S"))
t2$View <- 'rcv'

iperf <- rbind(t1, t2)
iperf <- iperf %>% mutate(RetransPct = 100 * ReTrans / Packets)
iperf$View <- factor(iperf$View, c('snd', 'rcv'))

dup_pkts_rcv <- sum(iperf %>% filter(View == 'rcv') %>% select(ReTrans))

if (dup_pkts_rcv == 0) {
    iperf_retrans <- iperf %>% filter(View == 'snd')
} else {
    iperf_retrans <- iperf
}

rt_ymax <- 1.1 * max(iperf_retrans$RetransPct)
if (rt_ymax == 0) {rt_ymax = 0.5}

## Header & summary plot, in character vector

knitr_data <- c(
    "# iperf Test Results",
    "### Test: `r TestName`",
    "### Direction: `r TestDirection`",
    "### Start time: `r TestDateTime`",
    "```{r plot1, echo=FALSE, message=FALSE, fig.width = FigureWidth, fig.height = FigureHeight}",
    "p1 <- ggplot(iperf) +",
    "     geom_line(aes(x = Time,  y = kbps / 1e3, colour = View), size=0.06) +",
    "     geom_point(aes(x = Time, y = kbps / 1e3, colour = View), size=PointSize, shape=19) +",
    "     xlab(\"\") + ylab(\"Throughput, Mbps\") + ggtitle(Title) +",
    "     scale_colour_manual(values=c(\"red\", \"blue\", \"green\", \"yellow\")) + theme_jm1",

    "p2 <- ggplot(iperf_retrans) +",
    "     geom_line(aes(x = Time,  y = RetransPct, colour = View), size=0.06) +",
    "     geom_point(aes(x = Time, y = RetransPct, colour = View), size=PointSize, shape=19) +",
    "     xlab(\"\") + ylab(\"% Retransmits\") + ylim(c(0, rt_ymax)) +",
    "     scale_colour_manual(values=c(\"red\", \"blue\", \"green\", \"yellow\")) + theme_jm1",

    "p <- arrangeGrob(p1, p2, ncol = 1, heights = c(2, 1))",
    "grid.arrange(p)",
    "```")

## Build a summary table

tsnd <- t1 %>% select(Time, Packets, kbps, ReTrans)
trcv <- t2 %>% select(Time, Packets, kbps, ReTrans)

tsnd$kbps <- tsnd$kbps / 1000
trcv$kbps <- trcv$kbps / 1000

names(tsnd) <- c('Time', 'PacketsSent', 'MbpsSent', 'PacketsReTrans')
names(trcv) <- c('Time', 'PacketsRecv', 'MbpsRecv', 'DupPackets')

t3 <- full_join(tsnd, trcv, by = 'Time')
twide <- t3 %>% select(PacketsSent, PacketsRecv, MbpsSent, MbpsRecv, PacketsReTrans, DupPackets)
## twide <- t3 %>% select(Time, PacketsSent, PacketsRecv, MbpsSent, MbpsRecv, PacketsReTrans, DupPackets)


if (USE_XTABLE) { # More flexible table formatter, but no benefit so far
    library(xtable)
    p.table <- xtable(twide)

    knitr_data <- c(knitr_data, # Append table data
                    "```{r table1, results='asis', echo=FALSE, message=FALSE}",
                    "print(p.table, include.rownames=TRUE, type='html', comment=FALSE)",
                    "```",
                    '***')

} else { # Use knitr native table formatter

    knitr_data <- c(knitr_data, # Append table data
                    "```{r table1, echo=FALSE, message=FALSE}",
                    "kable(twide, digits = 2, row.names = TRUE)",
                    "```",
                    '***')

}

writeLines(knit2html(text = knitr_data), OutFile)



