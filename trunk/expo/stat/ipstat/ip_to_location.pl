require 'require.pl';


my $strRange		= 'map_range';
#$strRange		= 'map_test';
my $strFileRangeOut	= 'ip_map/' . $strRange . '_out.txt';
my $strRangeFile	= $strFileRangeOut;
# 得到 IP 映射表
my %hashSearhMap	= buildSearchMap($strRangeFile);

#hash_dump_r(\%hashSearhMap);exit;

# 读取 stat.pl 分析过的日志目录
my $strLogPath		= getConfig("STAT_LOG");	# 日志根目录
opendir(FP_LOG_PATH, $strLogPath);
my @arrLogDirsTmp	= readdir(FP_LOG_PATH);
close(FP_LOG_PATH);

my @arrLogDirs;
for(my $i = 0; $i < @arrLogDirsTmp; $i++) {
	if ($arrLogDirsTmp[$i] =~ m/xword_to_ip_.*/) {
		push(@arrLogDirs, $arrLogDirsTmp[$i]);
	}
}
#array_dump(\@arrLogDirs);exit;

`rm -rf ip_data/20070919`;

my %hashWordIP;
my %hashFewLines;
for(my $i = 0; $i < @arrLogDirs; $i++) {

	# 处理每个文件	word_to_ip_0.txt, word_to_ip_1.txt, ...
	my $strWordIPFile	= $strLogPath . "/" . $arrLogDirs[$i];

	print $strWordIPFile . "\n";

	open(FH_WORDFILE, "<$strWordIPFile") or die "Failed to open log file! [$strWordIPFile]";


	my %hashWordIP;

	# 装载文件到 hash 数组
	#	[abc]	5	3
	#	219.238.130.5	1
	#	81.65.229.37	1
	#	124.160.121.10	3
	while(!(eof FH_WORDFILE)) {

		my $strLine		= <FH_WORDFILE>;
		$strLine		= trim($strLine);

	#	print "line:\t$strLine \n";

		my @arrWordLine		= split("\t", $strLine);
		my $strWord		= $arrWordLine[0];	# 关键词是 abc
	#	$strWord		=~ s/^\[//;
	#	$strWord		=~ s/\]$//;

		$strWord		= trim_b($strWord);

		if (!$strWord) {
			next;
		}

	#	print "\t" . $strWord . "\n";


		my $intReadLine		= $arrWordLine[2];	# 继续读取后 3 行

		# 继续读取后 3 行
		my @arrFewLines		= readFile(FH_WORDFILE, $intReadLine);

		my %hashFewLines;
		for(my $j = 0; $j < @arrFewLines; ++$j) {

			# 每行拆成 2 个字段，IP 和 Count
			my ($strIP, $intCount)	= split("\t", trim($arrFewLines[$j]));
			$hashWordIP{$strWord}{$strIP}	= $intCount;
		}

	}

	statWordIPHash(\%hashWordIP, $i);

#	print	"ok\n";

	close(FH_WORDFILE);
}


sub statWordIPHash {

	my %hashObj	= %{shift(@_)};
	my $strDat	= date("Ymd", time - 86400);
	my $strPath	= "ip_data/";

	my $intOrder	= shift(@_);

	my $intWordCount	= 0;
#	my $startAt		= date("H:i:s");

#	hash_dump_r(\%hashObj);exit;

	foreach my $strWord (keys %hashObj) {

		$intWordCount++;
		if (($intWordCount % 100) == 0) {
			print date("H:i:s") . "\t" . $intOrder . ":\t" . $intWordCount . "\n";
		}

		my %hashTotal;

		my $strWordStatFile	= getWordStatFile($strWord);
		$strWordStatFile	= $strPath . $strDat . "/" . $strWordStatFile;

	#	print "[$strWord $strLine] \n";


		#	文件格式
		#	[Province]	2
		#	3	19
		#	4	14
		#	[City]	3
		#	7	18
		#	23	15
		#	17	13

		if (-e $strWordStatFile) {
			# 如果文件已经存在，则要预先装载文件里的内容

			open(FH_STAT, "<$strWordStatFile") or die "Failed to read stat file! [$strWordStatFile]";

			# 第一行是关键词
			my $strWordOfFile	= <FH_STAT>;
			$strWordOfFile		= trim($strWordOfFile);
			if (!($strWordOfFile eq $strWord)) {
			#	print "[$strWordOfFile :: $strWord] \n";
				# 关键词不匹配，跳过
				next;
			}


			# 从第二行到最后一行是位置信息

			while(!(eof FH_STAT)) {

				my $strLine		= <FH_STAT>;
				$strLine		= trim($strLine);


			#	print "line:\t$strLine \n";
			#	print "merge file:\t $strWord\t$strWordStatFile\n";

				my ($strType, $intReadLine)	= split("\t", $strLine);
				$strType			= trim_b($strType);

			#	print "type: $strType\tlines: $intReadLine\n";

				# 继续读取后 3 行
				my @arrFewLines		= readFile(FH_STAT, $intReadLine);

			#	array_dump(\@arrFewLines);

				my %hashFewLines;
				for(my $j = 0; $j < @arrFewLines; ++$j) {

					# 每行拆成 2 个字段，地区代码 和 Count
					my ($strCode, $intCount)	= split("\t", trim($arrFewLines[$j]));
					$hashTotal{$strType}{$strCode}	= $intCount;
				}
			}

		#	hash_dump_r(\%hashTotal);
			if ($strWord eq '126') {
				print	"===========\n";
				hash_dump_r(\%hashTotal);
			}

			close(FH_STAT);
			unlink	$strWordStatFile;

		} else {
			# 创建目录
			touchFile($strWordStatFile, ".");
		}

		open(FH_STAT, ">$strWordStatFile") or die "Failed to write stat file! [$strWordStatFile]";

		# 分析每一个 IP 的位置，写入 %hashTotal

		foreach $strIPAddr (keys %{$hashObj{$strWord}}) {

			my %resFind	= findIPLocation(\%hashSearhMap, $strIPAddr);
			if ($resFind{"p"}) {
				$hashTotal{"province"}{$resFind{"p"}}	+= $hashObj{$strWord}{$strIPAddr};
			}
			if ($resFind{"c"}) {
				$hashTotal{"city"}{$resFind{"c"}}	+= $hashObj{$strWord}{$strIPAddr};
			}
		#	print	"----$strIPAddr\n";
		#	hash_dump(\%resFind);
		#	print	"\n";
		}

#		print $strWord . " : \n";
#		hash_dump_r(\%hashTotal);


		my $strProvinceContent	= "";
		my $strCityContent	= "";

		my $intProvinceCount	= 0;
		my $intCityCount	= 0;

		foreach my $keyProvince (sort {$hashTotal{"province"}{$b} <=> $hashTotal{"province"}{$a}} keys %{$hashTotal{"province"}}) {
			$strProvinceContent	.= $keyProvince . "\t" . $hashTotal{"province"}{$keyProvince} . "\n";
			$intProvinceCount++;
		}

		foreach my $keyCity (sort {$hashTotal{"city"}{$b} <=> $hashTotal{"city"}{$a}} keys %{$hashTotal{"city"}}) {
			$strCityContent	.= $keyCity . "\t" . $hashTotal{"city"}{$keyCity} . "\n";
			$intCityCount++;
		}

		my $strFileContent	= "$strWord\n";
		$strFileContent		.= "[province]\t$intProvinceCount\n$strProvinceContent";
		$strFileContent		.= "[city]\t$intCityCount\n$strCityContent";

		print	FH_STAT $strFileContent;

		close(FH_STAT);

		if ($strWord eq '126') {
		#	print	"===========\n";
		#	hash_dump_r(\%hashTotal);
		}


#		print	"$strWord [$strWordStatFile]\n\n\n";


	}

#	my $finishAt	= date("H:i:s");


	return	1;

}
