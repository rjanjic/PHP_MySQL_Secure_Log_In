<?php
/******************************************************************
 * 
 * Projectname:   PHP User Register Class 
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

class User_Register extends User_Validation {

	/** Class version 
	 * @var float 
	 */
	var $version = '1.0';
	
	/** Database object
	 * @var object
	 */
	var $db = NULL;
	
	function User_Register(&$db) {
		$this->db = &$db;
	}
	
	function register($email, $password) {
		if (!$this->checkEmail($email)) return USER_REG_ERR_INVALID_EMAIL;
		if ($this->userExists($email)) return USER_REG_ERR_USER_EXISTS;
		$pass = $this->checkPassStrength($password);
		if ($pass !== TRUE) return $pass;
		
		$data = array();
		$data['email'] = $this->db->escape($email);
		$data['password'] = $this->hash($password);
		$data['token'] = $this->generateToken();
		return $this->db->arrayToInsert(MYSQL_TABLE_USERS, $data);
	}
}
