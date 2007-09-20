require 'require.pl';

my $strFileRaw		= getConfig("IP_MAP_RAW");
my $strFileProvince	= getConfig("IP_MAP_PROVINCE");
my $strFileCity		= getConfig("IP_MAP_CITY");
my $strFileRange	= getConfig("IP_MAP_RANGE");

my $intProvince		= 1;
my $intCity		= 1;

my %hashRange;
my %hashProvinceCode;
my %hashCityCode;

my $countKK	= 0;
# 输入原始 IP 库文件
open (FH_RAW, "<$strFileRaw") or die "Failed to open raw file!";
while (my $line = <FH_RAW>) {

	# 原始格式:   125  . 031  . 000  . 000        125  . 031  . 063  . 255 	      澳门 	  澳门
	$line	=~ m/(\d+)\.(\d+)\.(\d+)\.(\d+)\s\t\s(\d+)\.(\d+)\.(\d+)\.(\d+)\s\t\s([^\t]*)\t\s([^\t]*)/;


	# 转换成整数 031 => 31
	my $strBeginIP	= join '.', int $1, int $2, int $3, int $4;	# 125.31.0.0
	my $strEndIP	= join '.', int $5, int $6, int $7, int $8;	# 125.31.63.255
	my $strProvince	= trim($9);					# 澳门
	my $strCity	= trim($10);					# 澳门


	# begin of [assign area code]
	# 地区号码分配，每新增一个地区，分配一个自增的整数

	# 为每个 Province 分配一个数字
	if (!$hashProvinceCode{$strProvince} && $strProvince) {
		$hashProvinceCode{$strProvince}		= $intProvince++;
	}

	# 为每个 City 分配一个数字
	if (!$hashCityCode{$strCity} && $strCity) {
		$hashCityCode{$strCity}			= $intCity++;
	}

	# end of [assign area code]


	# 输出文件消重，同样的起始、结束 IP 的记录只应出现一次，而原始记录中有重复的现象
	my $strIndexIPRange		= $strBeginIP . " " . $strEndIP;


	# 输出新格式
	$hashRange{$strIndexIPRange}	= join "\t", $strBeginIP, $strEndIP, $hashProvinceCode{$strProvince}, $hashCityCode{$strCity};

}

# 输出到外部文件
hash_to_file($strFileProvince, \%hashProvinceCode);	# 省份代码
hash_to_file($strFileCity, \%hashCityCode);		# 城市代码
hash_to_file($strFileRange, \%hashRange, 1);		# IP 范围



# 优化 IP 范围 opt_range.pl