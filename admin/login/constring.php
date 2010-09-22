<?php
# FileName="Connection_php_mysql.htm"
# Type="MYSQL"
# HTTP="true"
$hostname_constring = "localhost"; //Server Host
$database_constring = "radius"; //Database Name
$username_constring = "radius"; //Database Username
$password_constring = "radpass"; //Database password
$constring = mysql_pconnect($hostname_constring, $username_constring, $password_constring) or trigger_error(mysql_error(),E_USER_ERROR); 
?>
