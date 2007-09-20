require 'require.pl';

my %hashWordToIP;	# $hashWordToIP['xbox'] = { '60.223.27.193' => 10, '218.24.148.101' => 26, ... }
my %hashWordToCount;	# $hashWordToCount = { 'xbox' => 80, 'ps2' => 18, ... }

my $intConcurrency	= getConfig("CONCURRENCY");
my $strStatLog		= getConfig("STAT_LOG");

# 得到 Expo 词表
my %hashExpoWordList	= getExpoWordList();

# 得到原始 UI 日志
#my $strLogFile		= getConfig("UI_LOG");

my @arrLogFiles		= getUILogFile("20070916");

for(my $intProcess = 0; $intProcess < $intConcurrency; ++$intProcess) {

	print "Round [$intProcess]\n";

	# free memory
	%hashWordToIP		= undef;
	%hashWordToCount	= undef;

	for(my $i = 0, $len = @arrLogFiles; $i < $len; ++$i) {
		if ($intProcess == ($i % $intConcurrency)) {
			print date("H:i:s") . " processing " . $arrLogFiles[$i] . "\n";
			parseLogToWrodIP($arrLogFiles[$i]);
		}
	}

	my $strFName	= "$strStatLog/word_to_ip_" . $intProcess . ".txt";
	dumpWordToIP(\%hashWordToIP, \%hashWordToCount, $strFName);
}
exit;



sub parseLogToWrodIP {

	my $strLogFile	= shift(@_);
	open(FH_UI_LOG, "<$strLogFile") or die "Failed to open log file! [$strLogFile]";

	while (my $line = <FH_UI_LOG>) {

		if ($line =~ m/.* \[(.*)\] .* ip=(.*) sz=.*/) {

			my $word	= $1;
			my $ip		= $2;

			# 只处理现有 Expo 词表中的关键词
			if (1 == $hashExpoWordList{$word} && $word) {
				$hashWordToCount{$word}		+= 1;
				$hashWordToIP{$word}{$ip}	+= 1;
			}
		}
	}
	close(FH_UI_LOG);
}

# 输出到文件
sub dumpWordToIP {
	my $refer		= shift(@_);
	my %hashWordToIPObj	= %$refer;

	my $refer		= shift(@_);
	my %hashWordToCountObj	= %$refer;

	my $strOutputFile	= shift(@_);

	my $strOutput		= '';
	# 对关键词排序，以便后续归并
	foreach my $word (sort keys %hashWordToIPObj) {

		if (!$word) {
			next;
		}

		my $referWord	= $hashWordToIPObj{$word};
		my %hashWord	= %$referWord;

		my $strIPCount	= '';
		my $intIPCount	= 0;
		foreach my $ip (keys %hashWord) {
			$intIPCount++;
			$strIPCount	.= $ip . "\t" . $hashWordToIPObj{$word}{$ip} . "\n";
		}

		$strOutput	.= "[$word]\t" . $hashWordToCountObj{$word} . "\t" . $intIPCount . "\n";
		$strOutput	.= $strIPCount;
	}

	open (FH_LOG, ">$strOutputFile") or die "Failed to open log file! [$strOutputFile]";
	print FH_LOG $strOutput;
	return	1;
}


