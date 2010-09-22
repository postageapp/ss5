<?php require_once('constring.php'); ?>
<?php
if (!function_exists("GetSQLValueString")) {
function GetSQLValueString($theValue, $theType, $theDefinedValue = "", $theNotDefinedValue = "") 
{
  $theValue = get_magic_quotes_gpc() ? stripslashes($theValue) : $theValue;

  $theValue = function_exists("mysql_real_escape_string") ? mysql_real_escape_string($theValue) : mysql_escape_string($theValue);

  switch ($theType) {
    case "text":
      $theValue = ($theValue != "") ? "'" . $theValue . "'" : "NULL";
      break;    
    case "long":
    case "int":
      $theValue = ($theValue != "") ? intval($theValue) : "NULL";
      break;
    case "double":
      $theValue = ($theValue != "") ? "'" . doubleval($theValue) . "'" : "NULL";
      break;
    case "date":
      $theValue = ($theValue != "") ? "'" . $theValue . "'" : "NULL";
      break;
    case "defined":
      $theValue = ($theValue != "") ? $theDefinedValue : $theNotDefinedValue;
      break;
  }
  return $theValue;
}
}
?>
<?php
// *** Validate request to login to this site.
if (!isset($_SESSION)) {
  session_start();
}

$loginFormAction = $_SERVER['PHP_SELF'];
if (isset($_GET['accesscheck'])) {
  $_SESSION['PrevUrl'] = $_GET['accesscheck'];
}

if (isset($_POST['user'])) {
  $loginUsername=$_POST['user'];
  $password=$_POST['password'];
  $MM_fldUserAuthorization = "";
  $MM_redirectLoginSuccess = "index.php";
  $MM_redirectLoginFailed = "loginerror.php";
  $MM_redirecttoReferrer = false;
  mysql_select_db($database_constring, $constring);
  
  $LoginRS__query=sprintf("SELECT username, password FROM login WHERE username=%s AND password=%s",
    GetSQLValueString($loginUsername, "text"), GetSQLValueString($password, "text")); 
   
  $LoginRS = mysql_query($LoginRS__query, $constring) or die(mysql_error());
  $loginFoundUser = mysql_num_rows($LoginRS);
  if ($loginFoundUser) {
     $loginStrGroup = "";
    
    //declare two session variables and assign them
    $_SESSION['MM_Username'] = $loginUsername;
    $_SESSION['MM_UserGroup'] = $loginStrGroup;	      

    if (isset($_SESSION['PrevUrl']) && false) {
      $MM_redirectLoginSuccess = $_SESSION['PrevUrl'];	
    }
    header("Location: " . $MM_redirectLoginSuccess );
  }
  else {
    header("Location: ". $MM_redirectLoginFailed );
  }
}
?>


<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
  <meta http-equiv="content-type" content="text/html; charset=UTF-8" />

  <title>Area riservata | Accesso utente business</title>

  <!--[if lte IE 6]>
  <script type="text/javascript" charset="utf-8">
    if (window.location.pathname != "/ie6") window.location = "/ie6";
  </script>
  <![endif]-->

        <link href="login_new.css" media="screen" rel="Stylesheet" type="text/css" />
        </head>




<body >
  
    <div class="header">
    </div>
      
      

    <div class="content">
    
        <form class="login_block" name="login" method="post" action="<?php echo $loginFormAction; ?>">

        <fieldset> 
          <legend>
            Accesso utenti
          </legend>
        <br>

  <div class="explanation subtext">
    Usa questa pagina per accedere all'area riservata per gli utenti business.
  </div>

<div align="right" class="style1">Password non corretta.</div>
  
  <div class="line">
    <label for="login" id="login_label" class="graphic_text">Username:</label>
    <span class="  input_text" id="login_wrap"><span><input id="login" name="user" type="text" /></span></span>  
  </div>
  
  <div class="line">
    <label for="password" id="password_label" class="graphic_text">Password:</label>
    <span class="input_text" id="password_wrap"><span><input id="password" name="password" type="password" /></span></span>  
  </div>
  
  <div class="line">
   <input type="image" id="login_button" src="bottone.png" border="0" name="button"/ >
  </div>

   <a href="#" title="Aiuto" id="forgot_your_password">Problemi di accesso?</a>

 
</div>
</fieldset> 


</form>


<div id="txtHint"></div>

</body>
</html>



