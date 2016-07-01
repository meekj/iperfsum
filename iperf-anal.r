#!/usr/bin/Rscript

## iperf Test Summary

## Generate a summary plot from iperfsum output
## Jon Meek - April 2016

## Assume synchronized clocks, could add option to align
## Assume that file names are 'synchronized', see below for examples, manually re-name if needed

## Sample command line:
##  iperf-anal.r --outdir /n2/r-reports --datadir /home/meekj/data/tcpd/20160629 --test apu3-192.168.205.48 --note "Segmentation offload disabled on both sides leads to performance issues"

## Sample file names:
##  fSnd <- 't1-192.168.205.48-snd.dat'
##  fRcv <- 't1-192.168.205.48-rcv.dat'

RSCid <- "$Id: iperf-anal.r,v 1.10 2016/06/30 18:55:19 meekj Exp $"

suppressMessages(library(ggplot2))
suppressMessages(library(dplyr))
suppressMessages(library(gridExtra))
suppressMessages(library(stringr))
suppressMessages(library(knitr))
suppressMessages(library(docopt))

## print(sessionInfo())

TestNote <- ''

doc <- "Usage: iperf-anal.r [--help --datadir <datadir> --outdir <outdir> --test <test> --note <note>]

-h --help           Show this help text
--datadir <datadir> Data directory
--outdir <outdir>   Report directory, default is data directory
--test <test>       Name of the test, filename without trailing -snd.dat / -rcv.dat
--note <note>       Optional note to describe the test
"
opt <- docopt(doc = doc, strict = FALSE, quoted_args = TRUE)

str(opt)

FileDir  <- opt[["datadir"]]
OutDir   <- opt[["outdir"]]
TestName <- opt[["test"]]
TestNote <- opt[["note"]]

if (is.null(opt[["outdir"]])) { # --outdir not specified, so put report in the data directory
    OutDir <- FileDir
}
OutFile <- paste(OutDir, '/', TestName, '.html', sep = '')

setwd(OutDir) # This will put the 'figure' directory with temporary image files in the same directory as the output
              # But be careful with running other programs that might write to the same directory at the same time


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

TotalBytesSent     <- sum(as.numeric(t1$Bytes)) # Need float to prevent integer overflow
TotalBytesReceived <- sum(as.numeric(t2$Bytes))

TotalPayloadSent     <- sum(as.numeric(t1$Payload))
TotalPayloadReceived <- sum(as.numeric(t2$Payload))

TotalPacketsSent     <- sum(as.numeric(t1$Packets))
TotalPacketsReceived <- sum(as.numeric(t2$Packets))

iperf <- rbind(t1, t2)
iperf <- iperf %>% mutate(RetransPct = 100 * ReTrans / Packets)
iperf$View <- factor(iperf$View, c('snd', 'rcv'))

dup_pkts_rcv <- sum( iperf %>% filter(View == 'rcv') %>% select(ReTrans) )

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
    "### Test: `r TestName` -- `r TestDirection`",
    "### Start: `r TestDateTime`")


if (length(TestNote) > 0) {knitr_data <- c(knitr_data, "### Note: `r TestNote`")} # Add note if we have one

knitr_data <- c(knitr_data, "```{r plot1, echo=FALSE, message=FALSE, fig.width = FigureWidth, fig.height = FigureHeight}")

## knitr_data <- NULL                    # For interactive development

knitr_data <- c(knitr_data, 
    "p1 <- ggplot(iperf) +",
    "     geom_line(aes(x = Time,  y = kbps / 1e3, colour = View), size=0.06) +",
    "     geom_point(aes(x = Time, y = kbps / 1e3, colour = View), size=PointSize, shape=19) +",
    "     xlab('') + ylab('Throughput, Mbps') + ggtitle(Title) +",
    "     scale_colour_manual(values=c('red', 'blue', 'green', 'yellow')) + theme_jm1",

    "p2 <- ggplot(iperf_retrans) +",
    "     geom_line(aes(x = Time,  y = RetransPct, colour = View), size=0.06) +",
    "     geom_point(aes(x = Time, y = RetransPct, colour = View), size=PointSize, shape=19) +",
    "     xlab('') + ylab('% Retransmited') + ylim(c(0, rt_ymax)) +",
    "     scale_colour_manual(values=c('red', 'blue', 'green', 'yellow')) + theme_jm1",

    "p <- arrangeGrob(p1, p2, ncol = 1, heights = c(2, 1))",
    "grid.arrange(p)")

## eval(parse(text = knitr_data))       # For interactive development

knitr_data <- c(knitr_data, "```")

## Build a summary table

tsnd <- t1 %>% select(Time, Bytes, Payload, Packets, kbps, ReTrans)
trcv <- t2 %>% select(Time, Bytes, Payload, Packets, kbps, ReTrans)

tsnd$kbps <- tsnd$kbps / 1000
trcv$kbps <- trcv$kbps / 1000

##    Time   Bytes Payload Packets     kbps ReTrans


names(tsnd) <- c('Time', 'BytesSent', 'PayloadSent', 'PacketsSent', 'MbpsSent', 'PacketsReTrans')
names(trcv) <- c('Time', 'BytesRecv', 'PayloadRecv', 'PacketsRecv', 'MbpsRecv', 'DupPackets')

t3 <- full_join(tsnd, trcv, by = 'Time')

FirstTime <- t3$Time[1]

t3 <- t3 %>% mutate(dt = Time - FirstTime)

## t3$MbpsSent - t3$MbpsRecv

## t3$BytesSent - t3$BytesRecv

twide <- t3 %>% select(dt, PacketsSent, PacketsRecv, MbpsSent, MbpsRecv, PacketsReTrans, DupPackets)

## Use knitr native table formatter

knitr_data <- c(knitr_data, # Append table data
                "```{r table1, echo=FALSE, message=FALSE}",
                "kable(twide, digits = 2, row.names = FALSE)",
                "```",
                '***')

medianBWsnd <- boxplot.stats(tsnd$MbpsSent)[["stats"]][3]
medianBWrec <- boxplot.stats(trcv$MbpsRecv)[["stats"]][3]

mC <- lm( tsnd$MbpsSent ~ tsnd$Time, subset=3:(length(tsnd$MbpsSent) - 2) ) # Linear fit, ignoring first and last two periods
fittedBWsnd <- mC$coefficients[1]

mC <- lm( trcv$MbpsRecv ~ trcv$Time, subset=3:(length(trcv$MbpsRecv) - 2) )
fittedBWrcv <- mC$coefficients[1]

## Build a summary table
summary_table <- NULL
summary_table <- rbind(summary_table, list(Data = 'Total', Sent = TotalBytesSent / 1e6, Received = TotalBytesReceived / 1e6, Units = 'MBytes'))
summary_table <- rbind(summary_table, list(Data = 'Payload', Sent = TotalPayloadSent / 1e6, Received = TotalPayloadReceived / 1e6, Units = 'MBytes'))
summary_table <- rbind(summary_table, list(Data = 'Median Throughput', Sent =  medianBWsnd, Received = medianBWrec, Units = 'Mbps'))
summary_table <- rbind(summary_table, list(Data = 'Linear Fit Throughput', Sent = fittedBWsnd, Received = fittedBWrcv, Units = 'Mbps'))

knitr_data <- c(knitr_data, # Append summary table data
                "## Summary",
                "```{r table2, echo=FALSE, message=FALSE}",
                "kable(summary_table, digits = 2, row.names = FALSE)",
                "```",
                '***')

knitr_data <- c(knitr_data, # Append CSS data, need to do it at end to override defaults
    '<style type="text/css">',
    'body {',
    'max-width: 1400px;',   # Make the plots wider, default is 800
    'margin: auto;',
    'padding: 1em;',
    'line-height: 20px ; ',
    '}',
    'table, th {',          # Customize tables a bit
    '   max-width: 95%;',
    '   border: 1px solid #ccc;',
    '   border-spacing: 15px 3px;',
    '}',
    '</style>'
    )

writeLines(knit2html(text = knitr_data), OutFile)

