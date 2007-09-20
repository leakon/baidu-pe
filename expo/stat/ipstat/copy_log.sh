#!/bin/sh
Date=$1
if test "$1" != ""
then
        Date=$1
else
        Date=`date --date='yesterday' +%Y%m%d`
fi
echo $Date

SrcPath="/home/work/build-expo/get_log/logs/ui_log/"
DstPath="/home/rd/likang/expo_stat/build-expo/ipstat/ui_log/"

#head -n 100000 pb_log.20070913.am | cat > /home/rd/likang/expo_stat/build-expo/get_log/logs/ui_log/se07/pb_log.20070913.am
#cd $Path

for dir in se00 se01 se02 se03 se04 se05 se06 se07
do
        FileAM="/pb_log."$Date".am"
        FilePM="/pb_log."$Date".pm"
        echo $SrcPath$dir$FileAM" -> "$DstPath$dir$FileAM

        head -n 100000 $SrcPath$dir$FileAM | cat > $DstPath$dir$FileAM
        head -n 100000 $SrcPath$dir$FilePM | cat > $DstPath$dir$FilePM
done