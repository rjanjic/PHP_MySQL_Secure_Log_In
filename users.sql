-- phpMyAdmin SQL Dump
-- version 3.4.5
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Generation Time: Dec 09, 2013 at 08:52 PM
-- Server version: 5.5.16
-- PHP Version: 5.3.8

SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

--
-- Database: `users`
--

-- --------------------------------------------------------

--
-- Table structure for table `sessions`
--

CREATE TABLE IF NOT EXISTS `sessions` (
  `session_id` varchar(50) NOT NULL,
  `name` varchar(50) NOT NULL,
  `expires` int(10) unsigned NOT NULL DEFAULT '0',
  `data` text,
  `fingerprint` varchar(32) NOT NULL,
  PRIMARY KEY (`session_id`,`name`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `sessions`
--

INSERT INTO `sessions` (`session_id`, `name`, `expires`, `data`, `fingerprint`) VALUES
('ftkm3egfr3nhborsa6prfn7tn2', 'PHPSESSID', 1386620156, 'cDRnsXnfVkzX/fHwQO5FLXDLdAhsUfZnK7g6g02ZLSHPKy0pBW+8YOyzthPf03hQxJ68QuDMae32TTLef8byTKjAUeD4PqEH0+0gGPjidt/3+bUA3N2AITt3gaE3PkJAVn/F6xFGBm/X4Qj+2xQm+xxEQfRmTPYTcLtdTE5tND0=', 'c6203bb7370e62ac92e0f5cf766a66c6');

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE IF NOT EXISTS `users` (
  `userid` int(11) NOT NULL AUTO_INCREMENT,
  `email` varchar(254) NOT NULL,
  `password` text NOT NULL,
  `token` varchar(32) NOT NULL,
  `last_activity` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`userid`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=4 ;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`userid`, `email`, `password`, `token`, `last_activity`) VALUES
(3, 'rade@it-radionica.com', '0LvcUkNoOfqaVZ55nOUmxmoUW90rcGgE:3sXC2j2TTPLm4DkkMkNIp4wyd8ZDIjS+dPV5bu8SNwOiEiglpBxwDAvVasMg9jnS', 'C8E49A43EC752FFA4B7DD126CD27F93A', '2013-12-09 19:51:56');

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
