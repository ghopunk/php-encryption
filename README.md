# encrypte n decrypte string PHP
$enc = new Encryption();<br>
$enc->setUniquecode( 'my_unique' );<br>
$encode = $enc->encode( 'my_text' );<br>
$decode = $enc->decode( $encode );<br>
echo $decode;