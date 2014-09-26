<?php
/******************************************************************
 * 
 * Projectname:   PHP User Log In Class 
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

class User_Log_In extends User_Validation {

	/** Class version 
	 * @var float 
	 */
	var $version = '1.0';
	
	/** Auto log out after (in seconds)
	 * @var integer
	 */
	var $logOutAfter = 1440;
	
	/** Database object
	 * @var object
	 */
	var $db = NULL;
	
	/** Session var
	 * @var
	 */
	var $sessionVarName = 'USER';
	
	/** Check credentials
	 * @param	string	$email		- User E-mail
	 * @param	string	$password	- User password
	 * @return	bool or error status code
	 */
	function checkCredentials($email, $password) {
		if ($this->checkEmail($email) && !empty($password)) {
			$this->db->query("SELECT `userid`, `password` FROM `" . MYSQL_TABLE_USERS . "` WHERE `email` LIKE '{$this->db->escape($email)}' LIMIT 1;");
			if ($this->db->affected > 0) {
				$row = $this->db->fetchArray();
				if ($this->validatePassword($password, $row['password'])) {
					$_SESSION[$this->sessionVarName]['USERID'] = $row['userid'];
					return TRUE;
				} else {
					return USER_LOGIN_ERR_WRONG_PASSWORD;
				}
			} else {
				return USER_LOGIN_ERR_NO_SUCH_USER;
			}
		} else {
			return USER_LOGIN_ERR_INVALID_EMAIL;
		}
	}
	
	/** Log in user
	 * @param	string	$email		- E-mail
	 * @param	string	$password	- Password
	 * @return	boolean
	 */
	function logInUser($email, &$password) {
		if ($this->checkCredentials($email, $password) === TRUE) {
			$_SESSION[$this->sessionVarName]['EMAIL'] = $email;
			$_SESSION[$this->sessionVarName]['TOKEN'] = $this->updateToken($email);
			unset($password);
			return TRUE;
		} 
		return FALSE;
	}
	
	/** Log out procedure
	 * @param	string	$redirectTo	- Redirect location after logging out
	 */
	function logOut($redirectTo = NULL) {
		$this->updateToken($_SESSION[$this->sessionVarName]['EMAIL']);
		session_destroy();
		if (!empty($redirectTo)) {
			header("Location: {$redirectTo}");
			exit;
		}
	}
	
	/** Check log in status
	 * @param	string	$email		- E-mail
	 * @param	string	$token		- Token
	 * @return	boolean	- Status
	 */
	function loggedIn($email = NULL, &$token = NULL) {
		if ($email === NULL && $token === NULL) {
			if (isset($_SESSION[$this->sessionVarName]['EMAIL']) && isset($_SESSION[$this->sessionVarName]['TOKEN'])) {
				$email = $_SESSION[$this->sessionVarName]['EMAIL'];
				$token = &$_SESSION[$this->sessionVarName]['TOKEN'];
			} else {
				return FALSE;
			}
		}
		$logged = FALSE;
		$this->db->query("SELECT * FROM `" . MYSQL_TABLE_USERS . "` WHERE `email` LIKE '{$this->db->escape($email)}' AND `token` LIKE '{$this->db->escape($token)}' AND `last_activity` > CURRENT_TIMESTAMP - {$this->logOutAfter} LIMIT 1;");
		if ($this->db->affected > 0) {
			$logged = TRUE;
			$token = $this->updateToken($email);
		} else {
			$this->updateToken($email);
		}
		return $logged;
	}
}