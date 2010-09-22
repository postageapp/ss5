<?php include('whoyou.php'); ?>

<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
  <meta http-equiv="content-type" content="text/html; charset=UTF-8" />

  <title>Area riservata | Supporto utenti business</title>

  <!--[if lte IE 6]>
  <script type="text/javascript" charset="utf-8">
    if (window.location.pathname != "/ie6") window.location = "/ie6";
  </script>
  <![endif]-->

        <link href="login_new.css" media="screen" rel="Stylesheet" type="text/css" />
        <script type="text/javascript" src="selectuser.js"></script>
        </head>




<body >
  
    <div class="header">
    </div>
      
      

    <div class="content">
    
        <form class="login_block" name="ricerca" method="get" action="answer.php" >

        <fieldset> 
          <legend>
            Richiedi supporto
          </legend>
        <br>

  <div class="explanation subtext">
    Usa questa pagina per richiedere supporto.
  </div>
  
  <div class="line">
    <label for="login" id="login_label" class="graphic_text">Username:</label>
    <span class="input_text" id="login_wrap"><span>
    <input  onkeydown="CursorKeyDown(event)" onkeyup="showUser(this.value)" type="text" value="" size="40" maxlength="200" id="login" name="users" type="text" /></span></span> 

  <input type="image" id="login_button" src="bottone2.png" border="0" name="button"/ >
  </div>
  
  

 
</div>
</fieldset> 


</form>


<div id="txtHint"></div>

</body>
</html>



