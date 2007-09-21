# Expo ר�ú�����

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

# �õ� expo �ʱ�
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


	my $strDate		= date("Ymd", time - 86400);	# ���������

	my $strArgDate		= shift(@_);
	if ($strArgDate) {
		$strDate	= $strArgDate;
	}

	my $strLogPath		= getConfig("UI_LOG_PATH");	# ��־��Ŀ¼
	my $strLogDirPatterns	= getConfig("UI_LOG_DIR");	# ��־Ŀ¼��������ʽ		se.*
	my $strLogFile		= getConfig("UI_LOG_FILE");	# ��־�ļ�����������ʽ	pb_log\.{DATE}.*

	my @arrReturn;
	# ��־Ŀ¼����������ʽ����	( 0 => 'se.*', 1 => 'kk.*', ...)
	my @arrLogDirPatterns	= split(";", $strLogDirPatterns);

	# ��ȡ��־��Ŀ¼�µ�����Ŀ¼ se00, se01, ...
	opendir(FP_LOG_PATH, $strLogPath);
	my @arrLogDirs		= readdir(FP_LOG_PATH);
	close(FP_LOG_PATH);

	my $intIndex		= 0;

	# ������־��Ŀ¼�µ�ÿһ��Ŀ¼
	# $strLogDirName ������־Ŀ¼��
	foreach my $strLogDirName (@arrLogDirs){

		# ��������ƥ��Ŀ¼���ļ�
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
	my $intReturn	= $arrIP[$intSize-1];	# ��ĩλֱ�����

	for(my $i = 0; $i < ($intSize - 1); ++$i) {
		my $intPower	= $intSize - $i - 1;
		$intReturn	+= (256 ** $intPower) * $arrIP[$i];
	}
	return	$intReturn;
}

# �����Ż����� Map_Range.txt�����ɽṹ���� IP ��ѯ Hash Table
sub buildSearchMap {

	my %hashMapping;
	my ($strOptimizedRangeFile) = @_;
	open(FH_ORF, "<$strOptimizedRangeFile") or die "Failed to open Optimized Range File ! $strOptimizedRangeFile";

	my %hashLine;

	while (!(eof FH_ORF)) {
		my $strLine		= <FH_ORF>;
		%hashLine		= parseLineToHash($strLine);

		my $strIPBegin		= $hashLine{"ip"};	# ��ʼ
		my $strIPEnd		= $hashLine{"end"};	# ����
		my $intIPBegin		= ipStrToInt($strIPBegin);
		my $intIPEnd		= ipStrToInt($strIPEnd);
		my $intIPLength		= $intIPEnd - $intIPBegin;	# ��ֵ
		my @arrIPBegin		= split('\.', $strIPBegin);

		my %hashNode	= (
			"begin"		=> $intIPBegin,
			"end"		=> $intIPEnd,
			"ip"		=> $strIPBegin,
		#	"to"		=> $strIPEnd,
			"length"	=> $intIPLength,
			"p"		=> $hashLine{"p"},
			"c"		=> $hashLine{"c"}
		);

#		if ('61.177.0.0' eq $strIPBegin) {
#			print $strLine . "\n";
#			hash_dump(\%hashNode);
#		}

		if ($intIPLength >= 16777216) {
			# ��Ч����
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

# ���ݽṹ���� IP Hash Table ��ѯλ����Ϣ����һ�������ǹ�ϣ������ã��ڶ������ַ�����ʽ�� IP ��ַ
sub findIPLocation {

	my $refer		= shift(@_);
	my %hashRefer		= %$refer;


	my $strIP		= trim(shift(@_));
	my $intIP		= ipStrToInt($strIP);
	my @arrIP		= split('\.', $strIP);

	my $intCompareCount	= 0;

	# �� 4 �β���
	if ($hashRefer{@arrIP[0]}{@arrIP[1]}{@arrIP[2]}{"lineNodes"}) {

		my %hashFound	= findFromLineNodes(\%{$hashRefer{@arrIP[0]}{@arrIP[1]}{@arrIP[2]}{"lineNodes"}}, $intIP, $intCompareCount);
		if ($hashFound{"p"}) {
			return	%hashFound;
		}
	}

	# �� 3 �β���
	if ($hashRefer{@arrIP[0]}{@arrIP[1]}{"lineNodes"}) {

		my %hashFound	= findFromLineNodes(\%{$hashRefer{@arrIP[0]}{@arrIP[1]}{"lineNodes"}}, $intIP, $intCompareCount);
		if ($hashFound{"p"}) {
			return	%hashFound;
		}
	}

	# �� 2 �β���
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

		$intCompareCount++;	# �Ƚϼ���

		# �� IP ����ĳ��������ʱ�����ؽ��
		if ($hashObjRefer{$nodesKey}{"begin"} <= $intIP && $intIP <= $hashObjRefer{$nodesKey}{"end"}) {

			$hashReturn{"x"}	= $intCompareCount;
			$hashReturn{"p"}	= $hashObjRefer{$nodesKey}{"p"};
			$hashReturn{"c"}	= $hashObjRefer{$nodesKey}{"c"};

			return	%hashReturn;
		}
	}
	# û���ҵ�
	return	%hashReturn;
}


# �ҵ� IP ������ͬ��ʼ IP �ļ�¼
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
			# �� 1 ���ҵ���ͬ�$hashSame{$strBeginIP} ������ͬ����к�

			# ������ͬ��
			$hashOut{$hashSame{$strBeginIP}}	= $arrLine[$hashSame{$strBeginIP}];
			# ���汾��
			$hashOut{$i}				= $arrLine[$i];
			# ����ͬ����к���Ϊ 0
			$hashSame{$strBeginIP} = -1;

		} elsif ($hashSame{$strBeginIP} == -1) {
			# �� 2+ ���ҵ���ͬ�$hashSame{$strBeginIP} ������ͬ����к�

			# ���汾��
			$hashOut{$i}				= $arrLine[$i];

		} else {

			# �����к�
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


# ���� �ؼ��� ȷ������·��
sub getWordStatFile {

	my $strWord		= trim(shift(@_));
	my $strMD5		= md5_hex($strWord);

	my $strLevelFirst	= substr($strMD5, 0, 2);
	my $strLevelSecond	= substr($strMD5, 2, 2);

	my $intLevelFirst	= hex($strLevelFirst);
	my $intLevelSecond	= hex($strLevelSecond);

	# ��ʱ���ԣ���Ҫ̫ɢ
	$intLevelFirst	= '0';
#	$intLevelSecond	= $intLevelSecond % 100;
#	$intLevelSecond	= '0';

	my $strIPDataFile	= $intLevelFirst . "/" . $intLevelSecond . "/" .$strMD5 . ".txt";

#	print	$strWord . "\t=> " . $strMD5 . "\t" . $strIPDataFile . "\n";

	return	$strIPDataFile;
}



# ���������������ݣ��Ѳ���ʹ��

sub statWordIPHashxxxx {

	my %hashObj	= %{shift(@_)};
	my $strDat	= date("Ymd", time - 86400);
	my $strPath	= "ip_data/";

	my $intOrder	= shift(@_);

	my $intWordCount	= 0;

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


		#	�ļ���ʽ
		#	[Province]	2
		#	3	19
		#	4	14
		#	[City]	3
		#	7	18
		#	23	15
		#	17	13

		if (0 && -e $strWordStatFile) {
			# ����ļ��Ѿ����ڣ���ҪԤ��װ���ļ��������

			open(FH_STAT, "<$strWordStatFile") or die "Failed to read stat file! [$strWordStatFile]";

			# ��һ���ǹؼ���
			my $strWordOfFile	= <FH_STAT>;
			$strWordOfFile		= trim($strWordOfFile);
			if (!($strWordOfFile eq $strWord)) {
			#	print "[$strWordOfFile :: $strWord] \n";
				# �ؼ��ʲ�ƥ�䣬����
				next;
			}


			# �ӵڶ��е����һ����λ����Ϣ

			while(!(eof FH_STAT)) {

				my $strLine		= <FH_STAT>;
				$strLine		= trim($strLine);


			#	print "line:\t$strLine \n";
				print "merge file:\t$strWord\t$strWordStatFile\n";

				my ($strType, $intReadLine)	= split("\t", $strLine);
				$strType			= trim_b($strType);

			#	print "type: $strType\tlines: $intReadLine\n";

				# ������ȡ�� 3 ��
				my @arrFewLines		= readFile(FH_STAT, $intReadLine);

			#	array_dump(\@arrFewLines);

				my %hashFewLines;
				for(my $j = 0; $j < @arrFewLines; ++$j) {

					# ÿ�в�� 2 ���ֶΣ��������� �� Count
					my ($strCode, $intTotal, $intCount)	= split("\t", trim($arrFewLines[$j]));
					$hashTotal{$strType}{$strCode}	= $intCount;
				}
			}

		#	hash_dump_r(\%hashTotal);
			close(FH_STAT);
			unlink	$strWordStatFile;

		} else {
			# ����Ŀ¼
#			touchFile($strWordStatFile, ".");
		}

#		open(FH_STAT, ">$strWordStatFile") or die "Failed to write stat file! [$strWordStatFile]";

		# ����ÿһ�� IP ��λ�ã�д�� %hashTotal
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

		my $intProvinceTotal	= 0;
		my $intCityTotal	= 0;

		foreach my $keyProvince (sort {$hashTotal{"province"}{$b} <=> $hashTotal{"province"}{$a}} keys %{$hashTotal{"province"}}) {
			$strProvinceContent	.= $keyProvince . "\t" . $hashTotal{"province"}{$keyProvince} . "\n";
			$intProvinceTotal	+= $hashTotal{"province"}{$keyProvince};
			$intProvinceCount++;
		}

		foreach my $keyCity (sort {$hashTotal{"city"}{$b} <=> $hashTotal{"city"}{$a}} keys %{$hashTotal{"city"}}) {
			$strCityContent	.= $keyCity . "\t" . $hashTotal{"city"}{$keyCity} . "\n";
			$intCityTotal	+= $hashTotal{"city"}{$keyCity};
			$intCityCount++;
		}

		my $strFileContent	= "$strWord\n";
		$strFileContent		.= "[province]\t$intProvinceTotal\t$intProvinceCount\n$strProvinceContent";
		$strFileContent		.= "[city]\t$intCityTotal\t$intCityCount\n$strCityContent";

#		print	FH_STAT $strFileContent;
#		close(FH_STAT);

#		print	"$strWord [$strWordStatFile]\n\n\n";


	}

	return	1;
}

1;