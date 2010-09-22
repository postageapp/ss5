<?php
$q=$_GET["q"];

if ($q != "") {
$con = mysql_connect('localhost', 'radius', 'radpass');
//$con = mysql_connect('89.188.136.53', 'm3312d1', 'rjumo8wqb9na656n');
if (!$con)
  {
  die('Could not connect: ' . mysql_error());
  }

//mysql_select_db("m3312d1", $con);
mysql_select_db("radius", $con);

$sql="SELECT srcaddr FROM ss5_method WHERE srcaddr like '%".$q."%' limit 10 ";

$result = mysql_query($sql);

if(mysql_num_rows($result) == 0) //no result found   
 {   
 echo "No result found!";   
 }   
else //result 
{
 echo " <select onkeydown='CursorKeyDown(event)' class='mytest' name=siti size=10  onclick='testl(this)' onchange='test(this)' >  ";
 while($row = mysql_fetch_array($result))
  {
  echo " <option value=" . $row['answer'] . ">" . $row['answer'] . " </option>";
  }
 echo " </select>";


}

mysql_close($con);
}
?> 
