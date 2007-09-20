# Expo 专用函数库

sub getStatConf {
	my %hashConfig;
	my $strConfigFile = 'conf/stat.conf';
	open (CONF_FILE, "<$strConfigFile") or die "Failed to open conf file!";
	while(<CONF_FILE>){

		my $line = trim($_);

		if ($line) {
			my @arrKeyValue	= parseConfigLine($line);
			if (@arrKeyValue) {
				$hashConfig{$arrKeyValue[0]} = $arrKeyValue[1];
			}
		}

	}
	close (CONF_FILE);
	return(%hashConfig);
}

sub getConfig {
	my $key = shift(@_);
	my %hashStatConf = getStatConf();
	return $hashStatConf{$key};
}

# 得到 expo 词表
sub getExpoWordList {

	my %wordHash;
	my %statConfig = getStatConf();
	my $expoWordFile = $statConfig{"EXPO_WORD"};

	open(FP_WORD, "<$expoWordFile") or die "Failed to open wordlist!";

	while(<FP_WORD>) {
		chop;
		my $word = $_;
		$wordHash{$word} = 1;
	}

	return %wordHash;
}


sub getUILogFile {


	my $strDate		= date("Ymd", time - 86400);	# 昨天的日期

	my $strArgDate		= shift(@_);
	if ($strArgDate) {
		$strDate	= $strArgDate;
	}

	my $strLogPath		= getConfig("UI_LOG_PATH");	# 日志根目录
	my $strLogDirPatterns	= getConfig("UI_LOG_DIR");	# 日志目录的正则表达式		se.*
	my $strLogFile		= getConfig("UI_LOG_FILE");	# 日志文件名的正则表达式	pb_log\.{DATE}.*

	my @arrReturn;
	# 日志目录名的正则表达式数组	( 0 => 'se.*', 1 => 'kk.*', ...)
	my @arrLogDirPatterns	= split(";", $strLogDirPatterns);

	# 读取日志根目录下的所有目录 se00, se01, ...
	opendir(FP_LOG_PATH, $strLogPath);
	my @arrLogDirs		= readdir(FP_LOG_PATH);
	close(FP_LOG_PATH);

	my $intIndex		= 0;

	# 遍历日志跟目录下的每一个目录
	# $strLogDirName 代表日志目录名
	foreach my $strLogDirName (@arrLogDirs){

		# 根据正则匹配目录和文件
		foreach my $strLogDirPattern (@arrLogDirPatterns){
		#	$strLogFile	=~ s/\{LOGDIR\}/$strLogDirPattern/;
        		$strLogFile	=~ s/\{DATE\}/$strDate/;

 	       		if($strLogDirName ne "." && $strLogDirName ne ".." && $strLogDirName =~ /\b$strLogDirPattern\b/){
        	        	$strLogDirName	= $strLogPath . "/" . $strLogDirName;
                		if(-d $strLogDirName){
                        		opendir(LOGDIR, $strLogDirName);
                        		my @arrLogFiles	= readdir(LOGDIR);
                        		foreach my $strFile (@arrLogFiles){
                        	        	if($strFile ne "." && $strFile ne ".."){
                        	                	if($strFile =~/\b$strLogFile\b/){
								$arrReturn[$intIndex]	= "$strLogDirName/$strFile";
        		         				$intIndex++;
                                	        	}
                                		}
                        		}
                        		close(LOGDIR);
                		}
        		}
		}
	}

	return(@arrReturn);
}

sub parseLineToHash {

	my ($strLine)	= @_;
	$strLine	= trim($strLine);
	my @arrLine	= split("\t", $strLine);
	my %hashReturn	= (
		"ip"	=> $arrLine[0],
		"end"	=> $arrLine[1],
		"p"	=> $arrLine[2],
		"c"	=> $arrLine[3],
	);

	return		%hashReturn;
}

sub ipStrToInt {
	my $strIP	= trim(shift(@_));
	my @arrIP	= split('\.', $strIP);
	my $intSize	= @arrIP;
	my $intReturn	= $arrIP[$intSize-1];	# 最末位直接相加

	for(my $i = 0; $i < ($intSize - 1); ++$i) {
		my $intPower	= $intSize - $i - 1;
		$intReturn	+= (256 ** $intPower) * $arrIP[$i];
	}
	return	$intReturn;
}

# 根据优化过的 Map_Range.txt，生成结构化的 IP 查询 Hash Table
sub buildSearchMap {

	my %hashMapping;
	my ($strOptimizedRangeFile) = @_;
	open(FH_ORF, "<$strOptimizedRangeFile") or die "Failed to open Optimized Range File ! $strOptimizedRangeFile";

	my %hashLine;

	while (!(eof FH_ORF)) {
		my $strLine		= <FH_ORF>;
		%hashLine		= parseLineToHash($strLine);

		my $strIPBegin		= $hashLine{"ip"};	# 起始
		my $strIPEnd		= $hashLine{"end"};	# 结束
		my $intIPBegin		= ipStrToInt($strIPBegin);
		my $intIPEnd		= ipStrToInt($strIPEnd);
		my $intIPLength		= $intIPEnd - $intIPBegin;	# 差值
		my @arrIPBegin		= split('\.', $strIPBegin);

		my %hashNode	= (
			"begin"		=> $intIPBegin,
			"end"		=> $intIPEnd,
			"ip"		=> $strIPBegin,
			"to"		=> $strIPEnd,
			"length"	=> $intIPLength,
			"p"		=> $hashLine{"p"},
			"c"		=> $hashLine{"c"}
		);

		if ('61.177.0.0' eq $strIPBegin) {
			print $strLine . "\n";
			hash_dump(\%hashNode);
		}

		if ($intIPLength >= 16777216) {
			# 无效区间
		} elsif ($intIPLength >= 65536) {

			$hashMapping{$arrIPBegin[0]}{"lineNodes"}{$arrIPBegin[1]}	= \%hashNode;

		} elsif ($intIPLength >= 256) {

			$hashMapping{$arrIPBegin[0]}{$arrIPBegin[1]}{"lineNodes"}{$arrIPBegin[2]}	= \%hashNode;

		} else {

			$hashMapping{$arrIPBegin[0]}{$arrIPBegin[1]}{$arrIPBegin[2]}{"lineNodes"}{$arrIPBegin[3]}	= \%hashNode;
		}
	}
	return	%hashMapping;
}

# 根据结构化的 IP Hash Table 查询位置信息，第一个参数是哈希表的引用，第二个是字符串形式的 IP 地址
sub findIPLocation {

	my $refer		= shift(@_);
	my %hashRefer		= %$refer;


	my $strIP		= trim(shift(@_));
	my $intIP		= ipStrToInt($strIP);
	my @arrIP		= split('\.', $strIP);

	my $intCompareCount	= 0;

	# 第 4 段查找
	if ($hashRefer{@arrIP[0]}{@arrIP[1]}{@arrIP[2]}{"lineNodes"}) {

		my %hashFound	= findFromLineNodes(\%{$hashRefer{@arrIP[0]}{@arrIP[1]}{@arrIP[2]}{"lineNodes"}}, $intIP, $intCompareCount);
		if ($hashFound{"p"}) {
			return	%hashFound;
		}
	}

	# 第 3 段查找
	if ($hashRefer{@arrIP[0]}{@arrIP[1]}{"lineNodes"}) {

		my %hashFound	= findFromLineNodes(\%{$hashRefer{@arrIP[0]}{@arrIP[1]}{"lineNodes"}}, $intIP, $intCompareCount);
		if ($hashFound{"p"}) {
			return	%hashFound;
		}
	}

	# 第 2 段查找
	if ($hashRefer{@arrIP[0]}{"lineNodes"}) {

		my %hashFound	= findFromLineNodes(\%{$hashRefer{@arrIP[0]}{"lineNodes"}}, $intIP, $intCompareCount);
		if ($hashFound{"p"}) {
			return	%hashFound;
		}
	}

	my %hashFound	= ("p" => 0);
	return	%hashFound;
}

sub findFromLineNodes {

	my $refer		= shift(@_);
	my %hashObjRefer	= %$refer;
	my $intIP		= shift(@_);
	my $intCompareCount	= shift(@_);
#	print "[ $intCompareCount ]";

	my %hashReturn		= ("p" => 0);

	foreach my $nodesKey (%hashObjRefer) {

		$intCompareCount++;	# 比较计数

		# 当 IP 落在某个区间内时，返回结果
		if ($hashObjRefer{$nodesKey}{"begin"} <= $intIP && $intIP <= $hashObjRefer{$nodesKey}{"end"}) {

			$hashReturn{"x"}	= $intCompareCount;
			$hashReturn{"p"}	= $hashObjRefer{$nodesKey}{"p"};
			$hashReturn{"c"}	= $hashObjRefer{$nodesKey}{"c"};

			return	%hashReturn;
		}
	}
	# 没有找到
	return	%hashReturn;
}


# 找到 IP 库里相同起始 IP 的记录
sub findSameBeginIP {

	my $strFile	= "ip_map/map_range.txt";
#	my $strFile	= "ip_map/map_range2.txt";
	my $strOut	= "ip_map/same_begin.txt";

	open(FH_FILE, "<$strFile");
	open(FH_OUT, ">$strOut");

	my @arrLine;
	$arrLine[0]	= "";

	while(!(eof FH_FILE)) {
		my $line	= <FH_FILE>;
		push(@arrLine, $line);
#		print $line;
	}

#	array_dump(\@arrLine);

	my %hashSame;
	my %hashOut;

	for(my $i = 1; $i < @arrLine; $i++) {

		$arrLine[$i]	= trim($arrLine[$i]);

		my @arrIP	= split("\t", $arrLine[$i]);
		my $strBeginIP	= $arrIP[0];

#		print "[" . $hashSame{$strBeginIP} . "]\t$strBeginIP\n";

		if ($hashSame{$strBeginIP} > 0) {
			# 第 1 次找到相同项，$hashSame{$strBeginIP} 代表相同项的行号

			# 保存相同项
			$hashOut{$hashSame{$strBeginIP}}	= $arrLine[$hashSame{$strBeginIP}];
			# 保存本行
			$hashOut{$i}				= $arrLine[$i];
			# 把相同项的行号置为 0
			$hashSame{$strBeginIP} = -1;

		} elsif ($hashSame{$strBeginIP} == -1) {
			# 第 2+ 次找到相同项，$hashSame{$strBeginIP} 代表相同项的行号

			# 保存本行
			$hashOut{$i}				= $arrLine[$i];

		} else {

			# 保存行号
			$hashSame{$strBeginIP}			= $i;
		}
	}

#	hash_dump(\%hashOut);

	my $strContent = '';
	foreach my $key (sort {$hashOut{$a} <=> $hashOut{$b}} keys %hashOut) {
		$strContent	.= $hashOut{$key} . "\n";
	}

	print FH_OUT $strContent;

	return 1;

}




1;