require 'require.pl';

=begin comment

202.100.36.128	202.100.36.135	5	5
202.100.36.136	202.100.36.143	5	5
202.100.36.144	202.100.36.159	5	5

IP Struct = {
	ip:	202.100.36.128	# primary key
	end:	202.100.36.135
	next:	202.100.36.136	# 136 = 135 + 1
	p:	5
	c:	5
}

=end comment
=cut


# 优化 IP 范围 opt_range.pl

my $strRange		= 'map_range';
#$strRange		= 'map_test';

my $strFileRange	= 'ip_map/' . $strRange . '.txt';
my $strFileRangeOut	= 'ip_map/' . $strRange . '_out.txt';
my $strFileRangeOut1	= 'ip_map/' . $strRange . '_out1.txt';
my $strFileRangeOut2	= 'ip_map/' . $strRange . '_out2.txt';

open(FH_MAP, "<$strFileRange");
open(FH_MAP_OUT, ">$strFileRangeOut");

unlink($strFileRangeOut1);
unlink($strFileRangeOut2);
#open(FH_MAP_OUT1, ">$strFileRangeOut1");
#open(FH_MAP_OUT2, ">$strFileRangeOut2");

my $strKey;
my $strLine;
my $strFileContent;
my %hashIPMap;
my %hashIPStruct;

# 生成 %hashIPMap 结构体 hash 表
while(!(eof FH_MAP)) {

	$strLine		= <FH_MAP>;
	my @arrIPStruct		= split("\t", $strLine);

	my %hashIPStruct;
	$hashIPStruct{"ip"}	= trim($arrIPStruct[0]);
	$hashIPStruct{"end"}	= trim($arrIPStruct[1]);
	$hashIPStruct{"p"}	= trim($arrIPStruct[2]);
	$hashIPStruct{"c"}	= trim($arrIPStruct[3]);

	# 得到下一个 IP 记录的指针(key)
	$hashIPStruct{"next"}	= getNextIP($hashIPStruct{"end"});

#	hash_dump(\%hashIPStruct);
	# 隐含的问题，如果有 2 条记录的起始 IP 相同，那么只能保存其中 1 条
	#$hashIPMap{$arrIPStruct[0]}	= \%hashIPStruct;

	# 这个 IP 已经存在
	if ($hashIPMap{$arrIPStruct[0]}) {

		my $intExistedEnd	= ipStrToInt($hashIPMap{$arrIPStruct[0]}{"end"});
		my $intCurrentEnd	= ipStrToInt($hashIPStruct{"end"});

		if ($intCurrentEnd > $intExistedEnd) {
			# 当前的比已经存在的范围更大，那么进行更新操作
		} else {
			# 否而，进行下一次循环
			next;
		}
	}

	$hashIPMap{$arrIPStruct[0]}	= \%hashIPStruct;
}


#hash_dump($hashIPMap{"202.100.36.128"});
#exit;

# 反复 IP 连接
# From
# 202.100.36.128	202.100.36.135	5	5
# 202.100.36.136	202.100.36.143	5	5
# To
# 202.100.36.128	202.100.36.143	5	5

my $intFount		= 1;
my $intJoinCount	= 0;	# 连接计数
my $intLoopCount	= 0;
my $strJoin;

my $stop		= 6;


my @arrDeletedIP;
$arrDeletedIP[0]	= 0;

while($intFount) {

	$intLoopCount++;

	# 如果没有找到可以连接的 IP，则设定 0 以退出循环
	$intFount	= 0;


	$strJoin	= '';
	foreach my $strKey (sort keys %hashIPMap) {
		if (%{$hashIPMap{$strKey}}) {
#			print	"\n\n::::::\n";
#			hash_dump(\%{$hashIPMap{$strKey}});
		}
		$strJoin	.= $strKey . "\t" . $hashIPMap{$strKey}{"end"} . "\t" . $hashIPMap{$strKey}{"next"} . "\n";
	}
#	print	"\n\n---------$intLoopCount-------------\n\n";
	if ($intLoopCount == ($stop - 1)) {
#		print	FH_MAP_OUT1 $strJoin;
	}
	if ($intLoopCount == $stop) {
#		print	FH_MAP_OUT2 $strJoin;
	}


	foreach my $strKey (keys %hashIPMap) {

		if (!%{$hashIPMap{$strKey}}) {
			next;
		}

		# 当前 Struct
		my %hashStruct	= %{$hashIPMap{$strKey}};

		# 根据 next 指针查询 hashtable
		my $strNextIP	= $hashStruct{"next"};
		my @arrEndIP	= split('\.', $strNextIP);

		# 如果存在可连接的 IP，则直接命中索引，只有 IP 的最后一段小于 255，才有必要进入连接逻辑
		if ($hashIPMap{$strNextIP} && $arrEndIP[3] < 255) {

			# 命中 IP 的位置信息
			$strFoundAreaInfo	= $hashIPMap{$strNextIP}{"p"} . "_" . $hashIPMap{$strNextIP}{"c"};
			# 当前 IP 的位置信息
			$strStructAreaInfo	= $hashStruct{"p"} . "_" . $hashStruct{"c"};

			# 调试信息，当两次连接的结果一样时，说明程序有问题
			if ($arrDeletedIP[$intLoopCount-1] == $arrDeletedIP[$intLoopCount-2] && $arrDeletedIP[$intLoopCount-1]) {

				print	"\n\n----------$intLoopCount------------\n\n";
				print	"Struct: $strFoundAreaInfo \n";
				hash_dump(\%hashStruct);

				print	"\n";
				print	"Hash: $strStructAreaInfo \n";
				hash_dump(\%{$hashIPMap{$strNextIP}});
			}


			# 地区匹配
			if ($strStructAreaInfo eq $strFoundAreaInfo) {

				# 隐藏的问题，尽管 IP 匹配了，但地区不匹配，仍然不能作为合并的条件
				$intFount	= 1;

				dumpPrint("From\t" . $strStructAreaInfo . "\t" . $strFoundAreaInfo . "\n");
				dumpPrint("From\t" . $hashStruct{"ip"} . "\t" . $hashStruct{"end"} . "\n");
				dumpPrint("And\t" . $hashIPMap{$strNextIP}{"ip"} . "\t" . $hashIPMap{$strNextIP}{"end"} . "\n");

				# 用命中的 end 更新 本记录的 end
				$hashStruct{"end"}	= $hashIPMap{$strNextIP}{"end"};
				# 更新 next 指针
				$hashStruct{"next"}	= getNextIP($hashStruct{"end"});

				$hashIPMap{$strKey}	= \%hashStruct;

				# 清除命中的记录
				$hashIPMap{$strNextIP}	= 0;

				$intJoinCount++;

				dumpPrint("To\t" . $hashStruct{"ip"} . "\t" . $hashStruct{"end"} . "\t" . "\n====\t===============\t===============\n");

			}
		}

	}

	$arrDeletedIP[$intLoopCount]	= $intJoinCount;


#	if ($intLoopCount == $stop) {
#		print	"Force to breakout!\n";
#		print	$intLoopCount;
#		exit;
#	}
#	print	$intLoopCount, "\n";
	print	"[$intLoopCount]\t$intJoinCount\n";


}

print	"Finished to join IP!\n";



# 可以输出文件了
$strFileContent	= '';
foreach my $strKey (sort keys %hashIPMap) {

	if (!%{$hashIPMap{$strKey}}) {
		next;
	}

	# 注意参考 map_range.txt 文件的格式
	$strFileContent	.= join "\t", $hashIPMap{$strKey}{"ip"}, $hashIPMap{$strKey}{"end"},
			$hashIPMap{$strKey}{"p"}, $hashIPMap{$strKey}{"c"} . "\n";

}
print FH_MAP_OUT $strFileContent;
print	"Finished to output New Map_Range!\n";



# 以 IP 地址的最后一位是否小于 255 为依据，返回 +1 的结果
sub getNextIP {
	my $strReturn;
	my $strEndIP		= shift(@_);
	my @arrEndIP		= split('\.', $strEndIP);

	$arrEndIP[3]		+= 1;
	# 最后一位要小于 255
	if ($arrEndIP[3] > 255) {
		$arrEndIP[3]	= 255;
	}

	$strReturn	= join(".", @arrEndIP);

	return	$strReturn;
}


sub dumpPrint {
	my $strLog	= shift(@_);
#	print		$strLog;
}
