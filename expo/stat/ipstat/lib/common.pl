# 公共函数库

sub trim {
	my $string	= shift(@_);
	$string		=~ s/^\s*//;
	$string		=~ s/\s*$//;
	return		$string;
}

sub parseConfigLine {
	my $line	= shift(@_);
	$line		=~ s/#.*$//;
	if ($line) {
		my @arrKeyValue	= split("=", $line);
		$arrKeyValue[0]	= trim($arrKeyValue[0]);
		$arrKeyValue[1]	= trim($arrKeyValue[1]);
		return		@arrKeyValue;
	} else {
		return		0;
	}
}

# 类似于 PHP 中的 date 函数，不过目前只支持有限的格式 Y-m-d H:i:s
sub date {

	my %hashDate;
	my $strReturn;
	my $strFormat	= shift(@_);	# 日期格式	Y-m-d H:i:s
	my $intTime	= shift(@_);	# 时间戳	1180630098

	if (!$strFormat) {
		$strFormat	= "Ymd";
	}

	if (!$intTime) {
		$intTime	= time;
	}

	my @arrLocaltime	= localtime($intTime);

#	my($sec, $min, $hour, $day, $mon, $year, $wday, $yday, $isdst)	= @arrLocaltime;

	$hashDate{"Y"}		= 1900 + @arrLocaltime[5];
	$hashDate{"m"}		= sprintf("%02d", @arrLocaltime[4] + 1);
	$hashDate{"d"}		= sprintf("%02d", @arrLocaltime[3]);
	$hashDate{"H"}		= sprintf("%02d", @arrLocaltime[2]);
	$hashDate{"i"}		= sprintf("%02d", @arrLocaltime[1]);
	$hashDate{"s"}		= sprintf("%02d", @arrLocaltime[0]);

	$strReturn		= $strFormat;
	foreach my $strLetter (keys %hashDate) {
		$strReturn	=~ s/$strLetter/$hashDate{$strLetter}/;
	}

	return $strReturn;
}

# 读取文件的 N 行
sub readFile {
	my $fileHandle	= shift(@_);
	my $intCount	= shift(@_);
	my @arrFileContent;
	if (!$intCount) {
		$intCount	= 1;
	}

	for(my $i = 0; $i < $intCount && $fileHandle; ++$i) {
		$arrFileContent[$i]	= <$fileHandle>;
	}

	return	@arrFileContent;
}

# helper function
sub key_value {
	my $key		= shift(@_);
	my $value	= shift(@_);
	print $key, "\t=> ", $value, "\n";
	return 1;
}

sub array_dump {
	my $refer	= shift(@_);
	my @arrayObj	= @$refer;
	for (my $i = 0; $i < @arrayObj; $i++) {
		print $i, "\t=> ", $arrayObj[$i], "\n";
	}
	print "\n";
	return 1;
}

sub hash_dump {
	my $refer	= shift(@_);
	my %hashObj	= %$refer;
	foreach my $key (keys %hashObj) {
		print $key, "\t=> ", $hashObj{$key}, "\n";
	}
	return 1;
}

# 递归打印 Hash Table
sub hash_dump_r {

	my %hashObj	= %{shift(@_)};
	my $strIndent	= shift(@_);

	foreach my $key (keys %hashObj) {

		if (%{$hashObj{$key}}) {

			my %hashSub	= %{$hashObj{$key}};
			my $subIndent	= $strIndent . "\t";

			print $strIndent . "\%" . $key . "\t=>\n";
			hash_dump_r(\%hashSub, $subIndent);
		} else {
			print $strIndent . "\$" . $key, "\t= " . $hashObj{$key} . "\n";
		}

	}
	return 1;
}

sub hash_dump_by_key {
	my $refer	= shift(@_);
	my %hashObj	= %$refer;
	foreach my $key (sort keys %hashObj) {
		print $key, "\t=> ", $hashObj{$key}, "\n";
	}
	return 1;
}

sub hash_dump_by_value {
	my $refer	= shift(@_);
	my %hashObj	= %$refer;
	foreach my $key (sort {$hashObj{$a} <=> $hashObj{$b}} keys %hashObj) {
		print $key, "\t=> ", $hashObj{$key}, "\n";
	}
	return 1;
}

sub hash_to_file {

	my $strFileName		= shift(@_);
	my $refer		= shift(@_);
	my %hashObj		= %$refer;
	my $withoutKey		= shift(@_);
	my $strFileContent	= '';

#	hash_dump_by_value(\%hashObj);

	if ($withoutKey) {
		# 不输出 key
		foreach my $key (sort keys %hashObj) {
			$strFileContent	.= $hashObj{$key} . "\n";
		}
	} else {
		foreach my $key (sort keys %hashObj) {
			$strFileContent	.= $key . "\t" . $hashObj{$key} . "\n";
		}
	}

	open (FH_OBJ, ">$strFileName") or die "Failed to open file!";
	print FH_OBJ $strFileContent;
	close (FH_OBJ);
	return 1;
}


1;