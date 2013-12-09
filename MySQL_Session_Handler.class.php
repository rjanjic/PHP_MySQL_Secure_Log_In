<?php 
/******************************************************************
 * 
 * Projectname:   PHP MySQL Session Handler Class 
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
 * This class contains everything needed to store PHP session into 
 * MySQL database. 
 *
 * Stored data can be encrypted.
 *
 * To use PHP MySQL Session Handler simply call mysql_session_start()
 * function.
 *
 ******************************************************************/
 
/** MySQL database stored session
 * @param string 	$server 	- MySQL Host name or ( host:port )
 * @param string 	$username 	- MySQL User
 * @param string 	$password 	- MySQL Password
 * @param string 	$db		 	- MySQL Database
 * @param string 	$table 		- MySQL Table
 * @param integer 	$lifeTime 	- Session lifetime
 * @param bool	 	$encrypt 	- Encrypt session data 
 */
function mysql_session_start($host, $username, $password, $db, $table = NULL, $lifeTime = 0, $encrypt = TRUE) {
	// Create object
	$GLOBALS['MYSQL_SESSION'] = new MySQL_Session_Handler( new MySQL_wrapper($host, $username, $password, $db), $table, $lifeTime, $encrypt);
}

class MySQL_Session_Handler {

	/** Class version 
	 * @var float 
	 */
	var $version = '1.0';
	
	/** Session lifetime 
	 * @var integer 
	 */
	var $lifeTime = 1440;
	
	/** Session name 
	 * @var string 
	 */
	var $name = 'PHP_MYSQL_SESSION';
	
	/** Session storage table name 
	 * @var string 
	 */
	var $table = 'sessions';
	
	/** Encrypt session data 
	 * @var bool 
	 */
	var $encrypt = TRUE;
	
	/** Key with which the data will be encrypted 
	 * @var string 
	 */
	var $key = '19f84f108bf8897ff7b6e7ea5fdb876c';
	
	/** Database object
	 * @var object
	 */
	var $db = NULL;
	
	/** Constructor
	 * @param string 	$server 	- MySQL Host name or ( host:port )
	 * @param string 	$username 	- MySQL User
	 * @param string 	$password 	- MySQL Password
	 * @param string 	$db		 	- MySQL Database
	 * @param string 	$table 		- MySQL Table
	 * @param integer 	$lifeTime 	- Session lifetime
	 * @param bool	 	$encrypt 	- Encrypt session data 
	 */
	function MySQL_Session_Handler(&$db, $table = NULL, $lifeTime = 0, $encrypt = TRUE) {
		$this->db = &$db;
		if (is_object($this->db) && !$this->db->link) {
			// Connect to DB
			$this->db->connect();
		}
		
		// If not setted value from php.ini is used
		$this->lifeTime = ($lifeTime === 0) ? ini_get('session.gc_maxlifetime') : $lifeTime;
		
		// Session storage table
		$this->table = ($table == NULL) ? $this->table : $table;
		
		// Encrypt session data
		$this->encrypt = $encrypt;
		
		// Hook up handler
		session_set_save_handler(
			array(&$this, '_Open'),
			array(&$this, '_Close'),
			array(&$this, '_Read'),
			array(&$this, '_Write'),
			array(&$this, '_Destroy'),
			array(&$this, '_GC')
		);
		
		// Start session
		session_start();
	}
	
	/** Create table for session storage
	 * @param void
	 */	
	function createStorageTable() {
		return $this->db->query("CREATE TABLE IF NOT EXISTS `{$this->table}` ( `session_id` varchar(50) NOT NULL, `name` varchar(50) NOT NULL, `expires` int(10) unsigned NOT NULL DEFAULT '0', `data` text, `fingerprint` varchar(32) NOT NULL, PRIMARY KEY (`session_id`, `name`) ) ENGINE=InnoDB;");
	}
	
	/** Initialize session
	 * @param string 	$save_path 	- Session save path (not in use!)
	 * @param string 	$name 		- Session name
	 */
	function _Open($save_path = NULL, $name) {
		// Session name
		$this->name = $name;
		// Is connection OK
		return ($this->db->link !== FALSE);
	}
	
	/** Close the session
	 * @param void
	 * @return bool
	 */
	function _Close() {
		// Run the garbage collector in 15% of f. calls
		if (rand(1, 100) <= 15) $this->_GC();
		// Close connection
		return $this->db->close();
	}
	
	/** Read session data
	 * @param string	$session_id - Session identifier]
	 * @return string
	 */
	function _Read($session_id) {
		// Read entry
		if ($this->db->query("SELECT `data` FROM `{$this->table}` WHERE `session_id` = '{$this->db->escape($session_id)}' AND `name` = '{$this->db->escape($this->name)}' AND `fingerprint` LIKE '{$this->fingerprint()}' AND `expires` > " . time() . " ORDER BY `expires` DESC LIMIT 1;") === FALSE) {
			if ($this->db->errorNo == 1146) {
				// Create table if not exists
				if ($this->createStorageTable())
					return $this->_Read($session_id);
			}
		}
		// Return data or null
		return ($this->db->affected > 0 && ($row = $this->db->fetchArray())) ? $this->encrypt ?  $this->decrypt($row['data']) : $row['data'] : NULL;
	}
	
	/** Initialize session
	 * @param string 	$session_id	- Session identifier
	 * @param string 	$data 		- Session data
	 */
	function _Write($session_id, $data) {
		$r = $this->db->arrayToInsert($this->table, array('session_id' => $session_id, 'name' => $this->name, 'expires' => time() + $this->lifeTime, 'data' => $this->encrypt ? $this->encrypt($data) : $data, 'fingerprint' => $this->fingerprint()), FALSE, '`expires` = VALUES(`expires`), `data` = VALUES(`data`)');
		if ($r === FALSE) {
			if ($this->db->errorNo == 1146) {
				// Create table if not exists
				if ($this->createStorageTable())
					return $this->_Write($session_id, $data);
			}
		}
		return $r;
	}

	/** Destroy session
	 * @param 	string 	$session_id	- Session identifier
	 * @return 	bool
	 */
	function _Destroy($session_id) {
		// Remove $session_id session
		$this->db->query("DELETE FROM `{$this->table}` WHERE `session_id` = '{$this->db->escape($session_id)}' AND `name` = '{$this->db->escape($this->name)}';");
		return ($this->db->affected) ? TRUE : FALSE;
	}
	
	/** Garbage collector
	 * @param 	string 	$maxlifetime - Session max lifetime
	 * @return 	integer	- Affected rows
	 */
	function _GC($maxlifetime = 0) {
		// Remove expired sessions 
		$this->db->query("DELETE FROM `{$this->table}` WHERE `expires` < " . time() . ";");
		return $this->db->affected;
	}
	
	/** Encrypt session data
     * @param 	string 	$data 	- Data to encrypt
     * @return 	string 	- Encrypted data
     */
    function encrypt($data) {
        return rtrim(base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $this->key, $data, MCRYPT_MODE_ECB, mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB), MCRYPT_RAND))), "\0");
    }
	
	/** Decrypt session data
     * @param 	string 	$data 	- Data to decrypt
     * @return 	string 	- Decrypted data
     */
    function decrypt($data) {
        return rtrim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $this->key, base64_decode($data), MCRYPT_MODE_ECB, mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB), MCRYPT_RAND)), "\0");
    }
	
	/** Returns "digital fingerprint" of user
     * @param 	void
     * @return 	string 	- MD5 hashed data
     */
	function fingerprint() {
		return md5(implode('|', array($_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_USER_AGENT'], $_SERVER['HTTP_ACCEPT'], $_SERVER['HTTP_ACCEPT_ENCODING'], $_SERVER['HTTP_ACCEPT_LANGUAGE'])));
	}
}