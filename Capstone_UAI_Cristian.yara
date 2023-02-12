rule Capstone_UAI_Cristian.yara
{
meta:
	description= "Regla Simple YARA para la deteccion de IPs Rusas del binario Pony Stealer"

strings:
	$a = "http://leftthenhispar.ru/zapoy/gate.php"
	$b = "http://reninparwil.com/zapoy/gate.php"
	$c = "http://reptertinrom.ru/zapoy/gate.php"
   

condition:
	($a or $b or $c)
}
