<?php
namespace ghopunk\Helpers;

class Encryption {
	
	protected $uniqueCode = "bgp";
	
	public function __construct( $uniqueCode=null ){
		if(!empty($uniqueCode))
			$this->setUniquecode($uniqueCode);
	}
	
	public function setUniquecode( $uniqueCode ){
		$this->uniqueCode = $uniqueCode;
	}
	
	public function getUniquecode(){
		return $this->uniqueCode;
	}
	
	private function safe_b64encode($string) {
		$data = base64_encode($string);
		$data = str_replace(array('+','/','='),array('-','_',''),$data);
		return $data;
	}
	
	private function safe_b64decode($string) {
		$data = str_replace(array('-','_'),array('+','/'),$string);
		$mod4 = strlen($data) % 4;
		if ($mod4) {
			$data .= substr('====', $mod4);
		}
		return base64_decode($data);
	}
	
	public function encode($value){
		if(!$value){return false;}
		$text = $value;
		if(version_compare( PHP_VERSION, '5.6', '<' ) && !extension_loaded('openssl')){
			$iv_size 		= mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB);
			$iv 			= mcrypt_create_iv($iv_size, MCRYPT_RAND);
			$crypttext 		= mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $this->getUniquecode(), $text, MCRYPT_MODE_ECB, $iv);
		} else {
			$cipher 		= "AES-128-CBC";
			$iv_size 		= openssl_cipher_iv_length($cipher);
			$iv 			= openssl_random_pseudo_bytes($iv_size);
			$ciphertext_raw = openssl_encrypt($text, $cipher, $this->getUniquecode(), OPENSSL_RAW_DATA, $iv);
			$hmac 			= hash_hmac('sha256', $ciphertext_raw, $this->getUniquecode(), true);
			$crypttext 		= $iv.$hmac.$ciphertext_raw;
		}
		return trim($this->safe_b64encode($crypttext));
	}
	
	public function decode($value){
		if(!$value){return false;}
		$crypttext 			= $this->safe_b64decode($value);
		if(version_compare( PHP_VERSION, '5.6', '<' ) && !extension_loaded('openssl')){
			$iv_size 		= mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB);
			$iv 			= mcrypt_create_iv($iv_size, MCRYPT_RAND);
			$decrypttext 	= mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $this->getUniquecode(), $crypttext, MCRYPT_MODE_ECB, $iv);
		} else {
			$cipher			= "AES-128-CBC";
			$sha2len		= 32;
			$iv_size 		= openssl_cipher_iv_length($cipher);
			$iv 			= substr($crypttext, 0, $iv_size);
			$hmac 			= substr($crypttext, $iv_size, $sha2len);
			$ciphertext_raw = substr($crypttext, $iv_size + $sha2len);
			$decrypttext 	= openssl_decrypt($ciphertext_raw, $cipher, $this->getUniquecode(), OPENSSL_RAW_DATA, $iv);
		}
		return trim($decrypttext);
	}
}

?>