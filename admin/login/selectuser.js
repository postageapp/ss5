var xmlhttp;

function showUser(str)
{
xmlhttp=GetXmlHttpObject();
if (xmlhttp==null)
  {
  alert ("Browser does not support HTTP Request");
  return;
  }
var url="getuser.php";
url=url+"?q="+str;
url=url+"&sid="+Math.random();
xmlhttp.onreadystatechange=stateChanged;
xmlhttp.open("GET",url,true);
xmlhttp.send(null);

}

function stateChanged()
{
if (xmlhttp.readyState==4)
{
document.getElementById("txtHint").innerHTML=xmlhttp.responseText;
}
}

function GetXmlHttpObject()
{
if (window.XMLHttpRequest)
  {
  // code for IE7+, Firefox, Chrome, Opera, Safari
  return new XMLHttpRequest();
  }
if (window.ActiveXObject)
  {
  // code for IE6, IE5
  return new ActiveXObject("Microsoft.XMLHTTP");
  }
return null;
}

function test(value) {
  var idx = value.selectedIndex;
  var sel = document.getElementById('users'); 
  sel.value=value.options[idx].text; 
  //sel.focus();
}

function testl(value) {
  //var idx = value.selectedIndex;
  var sel = document.getElementById('users'); 
  //sel.value=value.options[idx].text; 
  sel.focus();
}

function CursorKeyDown(e) {
  if (!e) e=window.event;
  var selectName;
  switch(e.keyCode)
  {
  case 40:
    // Key down.
    var controls = document.getElementsByName('siti');
    if (!controls) return;
    if (controls.length != 1) return;
    controls[0].focus();
  break;
  case 13:
    // Key enter
    var controls = document.getElementsByName('button');
    if (!controls) return;
    if (controls.length != 1) return;
    controls[0].focus();
  break;
  }
}
