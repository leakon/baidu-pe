<?php

$fileProvince	= "map_province.txt";
$fileCity	= "map_city.txt";

function fileToPHP($file, $varName) {

	$string		= file_get_contents($file);
	$string		= str_replace("\r\n", "\n", $string);

	$tmp_array	= split("\n", $string);

	$array		= array();

	foreach($tmp_array as $line) {
		$tmp		= split("\t", $line);
		if ($tmp[1]) {
			$array[$tmp[1]]	= $tmp[0];
		}
	}

	ksort($array, SORT_NUMERIC);

	$loop		= '';
	foreach($array as $key => $val) {

		$loop	.= "\t$key	=> '$val',\n";

	}

	$string		= "

\$$varName	= array(
$loop
);
";

#	echo		$string;

	return		$string;
#	print_r($array);

}


$province	= fileToPHP($fileProvince, "global_map_province");
$city		= fileToPHP($fileCity, "global_map_city");

$string		= '<?php
'.$province.'
'.$city.'
?>';

#echo	$string;

$fp	= fopen("code_mapping.inc.php", "w+");
echo	fwrite($fp, $string);