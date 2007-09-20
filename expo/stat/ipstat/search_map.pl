require 'require.pl';



my $strRange		= 'map_range';
#$strRange		= 'map_test';

my $strFileRangeOut	= 'ip_map/' . $strRange . '_out.txt';

my $strRangeFile	= $strFileRangeOut;

# µ√µΩ IP ”≥…‰±Ì
my %hashSearhMap	= buildSearchMap($strRangeFile);

#hash_dump_r(\%hashSearhMap);

#hash_dump_r($hashSearhMap{"202"}{"100"}{"200"});
hash_dump_r($hashSearhMap{"61"}{"177"}{"lineNodes"});

my $strTestIP		= "61.177.202.210";
my %resFind		= findIPLocation(\%hashSearhMap, $strTestIP);

hash_dump(\%resFind);
#exit;



my $strOutContent	= "";
my $strFileIPFound	= "ip_map/ip_found.txt";
my $strFileIPAddress	= "ip_map/ip_100k.txt";


print	"Start\t" . date("H:i:s") . "\n";

open(FH_IPADDR, "<$strFileIPAddress");
open(FH_IPLOC, ">$strFileIPFound");

while(!(eof FH_IPADDR)) {

	my $strIP	= <FH_IPADDR>;
	$strIP		= trim($strIP);
#	print	$strIP;

	my %resFind	= findIPLocation(\%hashSearhMap, $strIP);

	my $strLocation	= $resFind{"p"} . "_" . $resFind{"c"};


	$strOutContent	.= $strIP . "\t" . $strLocation . "\n";

}

print	FH_IPLOC $strOutContent;


print	"Stop\t" . date("H:i:s") . "\n";


