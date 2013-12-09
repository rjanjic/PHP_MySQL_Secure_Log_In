<?php
/******************************************************************
 * 
 * Projectname:   PHP User Validation Class 
 * Version:       1.0
 * PHP Version:   4 >= 4.0.2, 5
 * Author:        Radovan Janjic <rade@it-radionica.com>
 * Last modified: 15 08 2013
 * Copyright (C): 2013 IT-radionica.com, All Rights Reserved
 * 
 * GNU General Public License (Version 2, June 1991)
 *
 * This program is free software; you can redistribute
 * it and/or modify it under the terms of the GNU
 * General Public License as published by the Free
 * Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will
 * be useful, but WITHOUT ANY WARRANTY; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 * 
 ******************************************************************
 * Description:
 *
 * Foo Bar
 *
 ******************************************************************/

// Log in errors
define('USER_LOGIN_ERR_WRONG_PASSWORD', -1);
define('USER_LOGIN_ERR_NO_SUCH_USER', -2);
define('USER_LOGIN_ERR_INVALID_EMAIL', -3);
 
// Password strength errors
define('USER_ERR_PASS_TOO_SHORT', -1);
define('USER_ERR_PASS_TOO_LONG', -2);
define('USER_ERR_PASS_NUMBERS_MISSING', -3);
define('USER_ERR_PASS_LETTERS_MISSING', -4);
define('USER_ERR_PASS_CAPS_MISSING', -5);
define('USER_ERR_PASS_SYMBOLS_MISSING', -6);


define('USER_REG_ERR_USER_EXISTS', -7);
define('USER_REG_ERR_INVALID_EMAIL', -8);



class User_Validation {
	
	/** Class version 
	 * @var float 
	 */
	var $version = '1.0';
	
	/** Database object
	 * @var object
	 */
	var $db = NULL;
	
	/** Hash algorithm
	 * @var string 
	 */
	var $hashAlgorithm = 'sha256';
	
	/** Number of internal iterations to perform for the derivation
	 * @var integer 
	 */
	var $iterations = 1500;
	
	/** Salt in bytes
	 * @var integer 
	 */
	var $saltBytes = 24;
	
	/** Hash in bytes
	 * @var integer 
	 */
	var $hashBytes = 48;
	
	/** Password strength safety 
	 * @var array 
	 */
	var $passStrength = array('minStrLen' => 8, 'maxStrLen' => 20, 'numbers' => TRUE, 'letters' => TRUE, 'caps' => TRUE, 'symbols' => TRUE);
	
	/** Hash function
	 * @param 	string	$password	- Password to be hashed
	 * @return 	string	- Hashed string
	 */
	function hash($password) {
		// format: salt:hash
		$salt = base64_encode(mcrypt_create_iv($this->saltBytes, MCRYPT_DEV_URANDOM));
		return $salt . ":" . base64_encode($this->pbkdf2($password, $salt, $this->hashBytes, TRUE));
	}
	
	/** Validate password
	 * @param	string	$password	- Password
	 * @param	string	$hash		- Hash
	 * @return	boolean
	 */
	function validatePassword($password, $hash) {
		$params = explode(":", $hash);
		if(count($params) !== 2) return FALSE;
		$pbkdf2 = base64_decode($params[1]);
		return $this->timeStrCmp($pbkdf2, $this->pbkdf2($password, $params[0], strlen($pbkdf2), TRUE));
	}
	
	/** Constant time string comparison
	 * @param 	string	$str1	- First string
	 * @param 	string	$str2	- First string
	 * @retrun 	boolean
	 */
	function timeStrCmp($str1, $str2) { // time_strcmp
		$result = strlen($str1) ^ strlen($str2);
		$i = min(strlen($str1), strlen($str2));
		while ($i--) {
			$result |= ord($str1[$i]) ^ ord($str2[$i]);
		}
		return 0 === $result; 
	}
	
	/** hash_pbkdf2 - Password-Based Key Derivation Function 2
	 * @param 	string 	$password 	- Password to use for the derivation
	 * @param 	string 	$salt 		- Salt to use for the derivation
	 * @param 	string 	$length 	- Length of the derived key to output
	 * @param 	string 	$raw_output	- When set to TRUE, outputs raw binary data. FALSE outputs lowercase hexits
	 * @return 	string 	- String containing the derived key as lowercase hexits unless raw_output is set to true in which case the raw binary representation of the derived key is returned.
	 */
	function pbkdf2($password, $salt, $length, $raw_output = FALSE) {
		$hashLen = strlen(hash($this->hashAlgorithm, NULL, TRUE));
		$return = NULL;
		$i = ceil($length / $hashLen);
		while ($i--) {
			$last = $salt . pack("N", $i);
			$last = $xorsum = hash_hmac($this->hashAlgorithm, $last, $password, TRUE);
			for ($j = 1; $j < $this->iterations; $j++) {
				$xorsum ^= ($last = hash_hmac($this->hashAlgorithm, $last, $password, TRUE));
			}
			$return .= $xorsum;
		}
		return ($raw_output) ? substr($return, 0, $length) : bin2hex(substr($return, 0, $length));
	}
	
	/** Generate token
	 * @param	void
	 * @return  string
	 */
	function generateToken() {
		mt_srand((double) microtime() * 10000);
		$charid = strtoupper(md5(uniqid(rand(), TRUE)));
		return substr($charid, 0, 8) . substr($charid, 8, 4) . substr($charid, 12, 4) . substr($charid, 16, 4) . substr($charid, 20, 12);
	}
	
	/** Update token in table
	 * @param	string		- E-mail
	 * @return 	- Inserted token
	 */
	function updateToken($email) {
		$token = $this->generateToken();
		$this->db->arrayToUpdate(MYSQL_TABLE_USERS, array('token' => $token), "`email` LIKE '{$this->db->escape($email)}'", 1);
		return $token;
	}
	
	/** Check password strength
	 * @param 	string	$password	- Password
	 * @return 	integer	- Error number or TRUE
	 */
	function checkPassStrength($password) {
		switch (TRUE) {
            case strlen($password) < $this->passStrength['minStrLen'] :
				return USER_ERR_PASS_TOO_SHORT;
				break;
			case strlen($password) > $this->passStrength['maxStrLen'] :
				return USER_ERR_PASS_TOO_LONG;
				break;
			case !preg_match('/[0-9]+/', $password) && $this->passStrength['numbers'] :
				return USER_ERR_PASS_NUMBERS_MISSING;
				break;
			case !preg_match('/[a-z]+/i', $password) && $this->passStrength['letters'] :
				return USER_ERR_PASS_LETTERS_MISSING;
				break;
			case !preg_match('/[A-Z]+/', $password) && $this->passStrength['caps'] :
				return USER_ERR_PASS_CAPS_MISSING;
				break;
			case !preg_match('/\W+/', $password) && $this->passStrength['symbols'] :
				return USER_ERR_PASS_SYMBOLS_MISSING;
				break;
			default:
				return TRUE;
			break;
		}
	}
	
	/** Check email
	 * @param 	string 	$email 		- E-mail address to validate
	 * @return 	boolean
	 */
	function checkEmail($email) {
		$isValid = TRUE;
		$atIndex = strrpos($email, "@");
		if (is_bool($atIndex) && !$atIndex) {
			$isValid = FALSE;
		} else {
			$domain = substr($email, $atIndex + 1);
			$local = substr($email, 0, $atIndex);
			$localLen = strlen($local);
			$domainLen = strlen($domain);
			if ($localLen < 1 || $localLen > 64) {
				$isValid = FALSE;
			} elseif ($domainLen < 1 || $domainLen > 255) {
				$isValid = FALSE;
			} elseif ($local[0] == '.' || $local[$localLen - 1] == '.') {
				$isValid = FALSE;
			} elseif (preg_match('/\\.\\./', $local)) {
				$isValid = FALSE;
			} elseif (!preg_match('/^[A-Za-z0-9\\-\\.]+$/', $domain)) {
				$isValid = FALSE;
			} elseif (preg_match('/\\.\\./', $domain)) {
				$isValid = FALSE;
			} elseif (!preg_match('/^(\\\\.|[A-Za-z0-9!#%&`_=\\/$\'*+?^{}|~.-])+$/', str_replace("\\\\", NULL, $local))) {
				if (!preg_match('/^"(\\\\"|[^"])+"$/', str_replace("\\\\", NULL, $local))) {
					$isValid = FALSE;
				}
			}
			if ($isValid && !(checkdnsrr($domain, "MX") || checkdnsrr($domain, "A"))) {
				$isValid = FALSE;
			}
		}
		return $isValid;
	}
	
	/** Check if user exists
	 * @param 	string 	$email 		- E-mail address of user
	 * @return 	boolean
	 */
	function userExists($email) {
		$this->db->query("SELECT 1 FROM `" . MYSQL_TABLE_USERS . "` WHERE `email` LIKE '{$this->db->escape($email)}' LIMIT 1;");
		return ($this->db->affected > 0) ? TRUE : FALSE;
	}
}
