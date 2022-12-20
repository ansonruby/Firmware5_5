
<?php
/*
define('WP_USE_THEMES', false);
require('../wp-blog-header.php');
header("HTTP/1.1 200 OK");
header("Status: 200 All rosy");
*/
/*
$DATO_re = $_GET['Dato'];
	$fh = fopen('Dato_get.txt', 'a');
	fwrite($fh,$DATO_re."\n");
	echo 'OK';
	$fclose($fh);

echo 'anderson';
*/



///---- resepcion por get un dato
/*
if (isset($_GET["Dato"])) {
    http_response_code(200);
    #header('Content-type: text/html');

    echo 'La URI solicitada es: ';
    echo 'El valor del parámetro "foo" es: ';

    return ;
}


{"data":["g2ytm.6ebe76c9fb411be97b3b0d48b791a7c9","g2yt1asd1234356755.6ebe76c9fb411be97b3b0d48b791a7c9"]}

*/

///---- resepcion por post


$dato = json_decode(file_get_contents('php://input'), true);

#print json_last_error()."\n";

if (json_last_error() == 0)
{
	$N = count($dato["data"]);
	$fh = fopen('Dato_get.txt', 'a');
	for($i = 0; $i < $N;$i++)
	{
		#echo $dato["data"][$i]."\n";
		fwrite($fh,$dato["data"][$i]."\n");
	}
	echo 'OK';

}
else{
	http_response_code(500);
}
#print_r($dato);

#echo '-----------';
#echo $dato["data"];
#echo $dato["data"][0];
#echo $dato["data"][1];
#$N = count($dato["data"]);
#echo 'Numero: '.$N ; #count($dato["data"]);

#$fh = fopen('Dato_get.txt', 'a');
#for($i = 0; $i < $N;$i++)
#{
#	#echo $dato["data"][$i]."\n";
#	fwrite($fh,$dato["data"][$i]."\n");
#}
#$fclose($fh);

#http_response_code(200);







?>
