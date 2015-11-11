CREATE TABLE IF NOT EXISTS `presta16_fail2ban` (
  `id_fail2ban` int(11) NOT NULL,
  `email` varchar(64) NOT NULL,
  `access_time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `banned` int(1) NOT NULL DEFAULT '0'
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

ALTER TABLE `presta16_fail2ban`
  ADD PRIMARY KEY (`id_fail2ban`);

ALTER TABLE `presta16_fail2ban`
  MODIFY `id_fail2ban` int(11) NOT NULL AUTO_INCREMENT;