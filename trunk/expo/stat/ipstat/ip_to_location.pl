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
	if ($arrLogDirsTmp[$i] =~ m/^aaword_to_ip_.*/) {
		push(@arrLogDirs, $arrLogDirsTmp[$i]);
	}
}
#array_dump(\@arrLogDirs);exit;

`rm -rf ip_data/20070920`;

#my %hashWordIP;
my %hashWordLocation;	# 最终数组
my %hashFewLines;
for(my $i = 0; $i < @arrLogDirs; $i++) {

	# 处理每个文件	word_to_ip_0.txt, word_to_ip_1.txt, ...
	my $strWordIPFile	= $strLogPath . "/" . $arrLogDirs[$i];

	print date("H:i:s") . "\t" . $strWordIPFile . "\n";

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

		my @arrWordLine		= split("\t", $strLine);
		my $strWord		= $arrWordLine[0];	# 关键词是 abc
		$strWord		= trim_b($strWord);
		if (!$strWord) {next;}

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

	close(FH_WORDFILE);
}

#hash_dump_r($hashWordLocation{"263"});
#hash_dump_r(\%hashWordLocation);
saveWordLocations();

# 生成地区信息表
sub statWordIPHash {

	my %hashObj	= %{shift(@_)};
	my $strDat	= date("Ymd", time - 86400);
	my $strPath	= "ip_data/";

	my $intOrder	= shift(@_);

#	my $intWordCount	= 0;

#	hash_dump_r(\%hashObj);exit;

	foreach my $strWord (keys %hashObj) {

#		$intWordCount++;
#		if (($intWordCount % 100) == 0) {
#			print date("H:i:s") . "\t" . $intOrder . ":\t" . $intWordCount . "\n";
#		}

		# 分析每一个 IP 的位置，写入 %hashWordLocation
		foreach $strIPAddr (keys %{$hashObj{$strWord}}) {

			# 查 IP
			my %resFind	= findIPLocation(\%hashSearhMap, $strIPAddr);
			if ($resFind{"p"}) {
				$hashWordLocation{$strWord}{"province"}{$resFind{"p"}}	+= $hashObj{$strWord}{$strIPAddr};
			}
			if ($resFind{"c"}) {
				$hashWordLocation{$strWord}{"city"}{$resFind{"c"}}	+= $hashObj{$strWord}{$strIPAddr};
			}
		}

	#	hash_dump_r(\%hashWordLocation);

	}

	return	1;
}

# 把每个词的位置信息存入相应的文件
sub saveWordLocations {

	print "\nWrite result to files!\n";

	my $strDat	= date("Ymd", time - 86400);
	my $strPath	= "ip_data/";

	foreach my $strWord (keys %hashWordLocation) {

		# 文件名
		my $strWordStatFile	= $strPath . $strDat . "/" . getWordStatFile($strWord);

		#	文件格式
		#	HelloWorld
		#	[Province]	2
		#	3	19
		#	4	14
		#	[City]	3
		#	7	18
		#	23	15
		#	17	13

		my $strProvinceContent	= "";
		my $strCityContent	= "";

		my $intProvinceCount	= 0;
		my $intCityCount	= 0;

		my $intProvinceTotal	= 0;
		my $intCityTotal	= 0;

		foreach my $keyProvince (sort {$hashWordLocation{$strWord}{"province"}{$b} <=> $hashWordLocation{$strWord}{"province"}{$a}} keys %{$hashWordLocation{$strWord}{"province"}}) {
			$strProvinceContent	.= $keyProvince . "\t" . $hashWordLocation{$strWord}{"province"}{$keyProvince} . "\n";
			$intProvinceTotal	+= $hashWordLocation{$strWord}{"province"}{$keyProvince};
			$intProvinceCount++;
		}

		foreach my $keyCity (sort {$hashWordLocation{$strWord}{"city"}{$b} <=> $hashWordLocation{$strWord}{"city"}{$a}} keys %{$hashWordLocation{$strWord}{"city"}}) {
			$strCityContent	.= $keyCity . "\t" . $hashWordLocation{$strWord}{"city"}{$keyCity} . "\n";
			$intCityTotal	+= $hashWordLocation{$strWord}{"city"}{$keyCity};
			$intCityCount++;
		}

		my $strFileContent	= "$strWord\n";
		$strFileContent		.= "[province]\t$intProvinceTotal\t$intProvinceCount\n$strProvinceContent";
		$strFileContent		.= "[city]\t$intCityTotal\t$intCityCount\n$strCityContent";

		if (!(-e $strWordStatFile)) {
			touchFile($strWordStatFile, ".");
		}
		open(FH_STAT, ">$strWordStatFile") or die "Failed to write stat file! [$strWordStatFile]";
		print	FH_STAT $strFileContent;
		close(FH_STAT);

#		print	"$strWord [$strWordStatFile]\n\n\n";


	}

	return	1;
}



