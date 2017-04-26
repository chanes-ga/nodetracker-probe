-- MySQL dump 9.11
--
-- Host: localhost    Database: nt_icnet
-- ------------------------------------------------------
-- Server version	4.0.21

--
-- Table structure for table `CanopyCustomers`
--

CREATE TABLE CanopyCustomers (
  customer varchar(50) NOT NULL default '',
  ipblock int(4) unsigned NOT NULL default '0',
  mask int(4) unsigned NOT NULL default '0',
  dlspeed int(4) unsigned NOT NULL default '0',
  ulspeed int(4) unsigned NOT NULL default '0',
  linuxgw varchar(30) NOT NULL default '',
  classID int(4) NOT NULL default '0',
  id int(4) NOT NULL auto_increment,
  PRIMARY KEY  (id)
) TYPE=MyISAM;

--
-- Table structure for table `CanopyQOSClasses`
--

CREATE TABLE CanopyQOSClasses (
  pid int(4) NOT NULL default '0',
  ClassID int(4) NOT NULL default '0',
  BWPercentage int(1) unsigned default NULL,
  id int(4) unsigned NOT NULL auto_increment,
  description varchar(50) default NULL,
  BWCeiling int(1) unsigned NOT NULL default '100',
  BWPercentageU int(1) unsigned default NULL,
  BWCeilingU int(1) unsigned NOT NULL default '100',
  isdefault int(1) unsigned NOT NULL default '0',
  PRIMARY KEY  (id)
) TYPE=MyISAM;

--
-- Table structure for table `CanopyQOSFilters`
--

CREATE TABLE CanopyQOSFilters (
  classID int(4) NOT NULL default '0',
  PortList varchar(255) default NULL,
  protocol varchar(10) NOT NULL default 'tcp',
  id int(4) unsigned NOT NULL auto_increment,
  pid int(4) default NULL,
  direction int(1) unsigned NOT NULL default '1',
  layer7 varchar(255) default NULL,
  PRIMARY KEY  (id)
) TYPE=MyISAM;

--
-- Table structure for table `CanopyQOSRouters`
--

CREATE TABLE CanopyQOSRouters (
  name varchar(50) NOT NULL default '',
  ip varchar(20) NOT NULL default '',
  upIF varchar(10) NOT NULL default '',
  downIF varchar(10) NOT NULL default '',
  remoteadmin int(1) unsigned NOT NULL default '0',
  PRIMARY KEY  (ip)
) TYPE=MyISAM;

--
-- Table structure for table `Crossovers`
--

CREATE TABLE Crossovers (
  Switch varchar(25) NOT NULL default '',
  ifnum int(4) NOT NULL default '0',
  detail varchar(100) default NULL,
  lastupdated int(4) NOT NULL default '0',
  PRIMARY KEY  (Switch,ifnum)
) TYPE=MyISAM;

--
-- Table structure for table `CryptSpecs`
--

CREATE TABLE CryptSpecs (
  tablename varchar(30) NOT NULL default '',
  fieldname varchar(30) NOT NULL default '',
  fieldtype int(1) unsigned NOT NULL default '0',
  iskey int(1) unsigned NOT NULL default '0',
  crypt int(1) unsigned NOT NULL default '1',
  PRIMARY KEY  (tablename,fieldname)
) TYPE=MyISAM;

--
-- Table structure for table `Devices`
--

CREATE TABLE Devices (
  MAC varchar(32) NOT NULL default '',
  Description varchar(64) NOT NULL default 'unknown',
  active int(1) unsigned NOT NULL default '0',
  RunNMAP int(1) unsigned NOT NULL default '0',
  PrimaryIP varchar(25) NOT NULL default '',
  IPAutoFill int(1) NOT NULL default '1',
  tcpsequence varchar(32) default NULL,
  osguess varchar(254) NOT NULL default '',
  rating int(4) default NULL,
  ratingcomment varchar(32) NOT NULL default '',
  public varchar(64) NOT NULL default '',
  type int(1) unsigned NOT NULL default '0',
  lastnmap int(4) unsigned NOT NULL default '0',
  lastactive int(4) unsigned NOT NULL default '0',
  ifDescShortOID int(4) unsigned NOT NULL default '0',
  nodeID int(4) unsigned NOT NULL auto_increment,
  snmpver int(1) unsigned NOT NULL default '1',
  groupid int(4) default '0',
  icmpscan int(1) unsigned NOT NULL default '1',
  ownerid int(4) unsigned NOT NULL default '1',
  PRIMARY KEY  (nodeID)
) TYPE=MyISAM;

--
-- Table structure for table `EncryptionStatus`
--

CREATE TABLE EncryptionStatus (
  state int(1) unsigned default NULL,
  secret varchar(254) default NULL,
  scheduleWalk int(1) unsigned NOT NULL default '0',
  scheduleDiscovery int(1) unsigned NOT NULL default '0',
  lastWalk int(4) unsigned NOT NULL default '0',
  lastDiscovery int(4) unsigned NOT NULL default '0'
) TYPE=MyISAM;

--
-- Table structure for table `EthernetCodes`
--

CREATE TABLE EthernetCodes (
  Code varchar(6) NOT NULL default '',
  Vendor varchar(255) default NULL,
  PRIMARY KEY  (Code)
) TYPE=MyISAM;

--
-- Table structure for table `GraphData`
--

CREATE TABLE GraphData (
  vertex int(4) NOT NULL default '0',
  edge int(4) NOT NULL default '0',
  candidate int(4) NOT NULL default '0',
  selected int(1) unsigned NOT NULL default '0',
  available int(1) unsigned NOT NULL default '1'
) TYPE=MyISAM;

--
-- Table structure for table `Groups`
--

CREATE TABLE Groups (
  id int(4) NOT NULL default '0',
  name varchar(255) NOT NULL default '',
  PRIMARY KEY  (id)
) TYPE=MyISAM;

--
-- Table structure for table `HourlyValues`
--

CREATE TABLE HourlyValues (
  refid int(4) unsigned NOT NULL default '0',
  ifnum int(4) unsigned NOT NULL default '0',
  timeinterval int(1) unsigned NOT NULL default '0',
  value int(4) unsigned default NULL,
  PRIMARY KEY  (refid,ifnum,timeinterval)
) TYPE=MyISAM;

--
-- Table structure for table `ICMPData`
--

CREATE TABLE ICMPData (
  ip int(4) unsigned NOT NULL default '0',
  timeblock int(4) unsigned NOT NULL default '0',
  loss int(1) unsigned NOT NULL default '0',
  min int(2) unsigned NOT NULL default '0',
  mean int(2) unsigned NOT NULL default '0',
  max int(2) unsigned NOT NULL default '0',
  PRIMARY KEY  (ip,timeblock),
  KEY ICMPDataIdx1 (ip,timeblock),
  KEY ICMPDataIdx2 (timeblock,ip)
) TYPE=MyISAM;

--
-- Table structure for table `IFDescriptions`
--

CREATE TABLE IFDescriptions (
  IP varchar(25) NOT NULL default '',
  ifnum int(1) NOT NULL default '0',
  description varchar(128) NOT NULL default '',
  speed int(4) NOT NULL default '0',
  opStatus tinyint(1) unsigned NOT NULL default '0',
  physAddress varchar(64) default NULL,
  lastupdated int(4) unsigned NOT NULL default '0',
  PRIMARY KEY  (IP,ifnum)
) TYPE=MyISAM;

--
-- Table structure for table `IP`
--

CREATE TABLE IP (
  IP varchar(25) NOT NULL default '',
  MAC varchar(32) default NULL,
  DNS varchar(64) default NULL,
  routerif int(1) NOT NULL default '0',
  address int(4) unsigned default NULL,
  sourceType int(1) unsigned NOT NULL default '0',
  sourceIP varchar(25) default NULL,
  PRIMARY KEY  (IP),
  KEY IPIdx1 (MAC,IP)
) TYPE=MyISAM;

--
-- Table structure for table `IPAllocations`
--

CREATE TABLE IPAllocations (
  network int(4) unsigned NOT NULL default '0',
  mask int(4) unsigned NOT NULL default '0',
  description varchar(128) NOT NULL default 'Unassigned',
  notes text,
  ownerid int(1) unsigned NOT NULL default '1',
  PRIMARY KEY  (network,mask)
) TYPE=MyISAM;

--
-- Table structure for table `IPBlocks`
--

CREATE TABLE IPBlocks (
  network int(4) unsigned NOT NULL default '0',
  mask int(4) unsigned NOT NULL default '0',
  icmp_scan int(1) unsigned NOT NULL default '1',
  PRIMARY KEY  (network)
) TYPE=MyISAM;

--
-- Table structure for table `Links`
--

CREATE TABLE Links (
  nodeID int(4) NOT NULL default '0',
  MAC varchar(50) NOT NULL default '',
  PRIMARY KEY  (nodeID,MAC)
) TYPE=MyISAM;

--
-- Table structure for table `MACData`
--

CREATE TABLE MACData (
  MAC varchar(32) NOT NULL default '',
  Switch varchar(25) NOT NULL default '',
  ifnum int(1) unsigned default NULL,
  lastupdated int(4) unsigned NOT NULL default '0',
  macOwner varchar(25) default NULL,
  SwitchID int(4) unsigned default NULL,
  macOwnerID int(4) unsigned default NULL
) TYPE=MyISAM;

--
-- Table structure for table `Notifications`
--

CREATE TABLE Notifications (
  id int(4) unsigned NOT NULL auto_increment,
  timestamp int(4) unsigned NOT NULL default '0',
  subject varchar(255) default NULL,
  body varchar(255) default NULL,
  PRIMARY KEY  (id)
) TYPE=MyISAM;

--
-- Table structure for table `OID_Instance_D`
--

CREATE TABLE OID_Instance_D (
  refid int(4) unsigned NOT NULL default '0',
  ifnum int(4) unsigned NOT NULL default '0',
  ifdescr varchar(64) default NULL,
  avg double(10,3) default NULL,
  std double(10,3) default NULL,
  PRIMARY KEY  (refid,ifnum)
) TYPE=MyISAM;

--
-- Table structure for table `OID_Instances`
--

CREATE TABLE OID_Instances (
  refid int(4) unsigned NOT NULL auto_increment,
  MAC varchar(32) NOT NULL default '',
  status int(4) NOT NULL default '0',
  lasttime int(4) unsigned NOT NULL default '0',
  shortoid int(4) unsigned NOT NULL default '0',
  lasterror varchar(128) default NULL,
  lastrrdupdate int(4) unsigned NOT NULL default '0',
  nodeID int(4) unsigned default NULL,
  PRIMARY KEY  (refid)
) TYPE=MyISAM;

--
-- Table structure for table `Owners`
--

CREATE TABLE Owners (
  id int(10) unsigned NOT NULL auto_increment,
  name varchar(70) default NULL,
  contact varchar(80) default NULL,
  phone varchar(40) default NULL,
  email varchar(100) default NULL,
  notes text,
  lastupdated int(4) unsigned NOT NULL default '0',
  PRIMARY KEY  (id)
) TYPE=MyISAM;

--
-- Table structure for table `Port`
--

CREATE TABLE Port (
  MAC varchar(32) NOT NULL default '',
  Switch varchar(25) NOT NULL default '',
  ifnum int(1) unsigned default NULL,
  uplink int(1) unsigned NOT NULL default '0',
  lastupdated int(4) unsigned NOT NULL default '0',
  KEY PortIdx1 (MAC),
  KEY PortIdx2 (Switch,MAC),
  KEY PortIdx3 (Switch,ifnum)
) TYPE=MyISAM;

--
-- Table structure for table `RawSNMP`
--

CREATE TABLE RawSNMP (
  refid int(3) unsigned NOT NULL default '0',
  timestamp int(4) unsigned NOT NULL default '0',
  ifnum int(3) unsigned NOT NULL default '0',
  value int(4) unsigned default NULL,
  shortoid int(2) unsigned NOT NULL default '0',
  PRIMARY KEY  (refid,timestamp,ifnum)
) TYPE=MyISAM;

--
-- Table structure for table `RouterIFs`
--

CREATE TABLE RouterIFs (
  ip varchar(25) NOT NULL default '',
  ifnum int(4) NOT NULL default '0',
  description varchar(128) default NULL,
  PRIMARY KEY  (ip,ifnum)
) TYPE=MyISAM;

--
-- Table structure for table `RouterIPs`
--

CREATE TABLE RouterIPs (
  ip varchar(25) NOT NULL default '',
  address int(4) unsigned NOT NULL default '0',
  mask int(4) unsigned default NULL,
  network int(4) unsigned NOT NULL default '0',
  ifnum int(4) NOT NULL default '0',
  lastupdated int(4) unsigned NOT NULL default '0',
  PRIMARY KEY  (ip,address,network)
) TYPE=MyISAM;

--
-- Table structure for table `SNMP_MIB`
--

CREATE TABLE SNMP_MIB (
  filename varchar(50) NOT NULL default '',
  baseoid varchar(200) NOT NULL default '',
  lastupdated int(4) unsigned default NULL,
  PRIMARY KEY  (filename)
) TYPE=MyISAM;

--
-- Table structure for table `SNMP_OID`
--

CREATE TABLE SNMP_OID (
  shortoid int(4) unsigned NOT NULL auto_increment,
  oid varchar(200) NOT NULL default '',
  description varchar(50) default NULL,
  rrd_graphType varchar(10) default NULL,
  rrd_stacked int(1) unsigned default '1',
  rrd_dataType varchar(10) default 'GAUGE',
  plotType int(1) unsigned NOT NULL default '0',
  descriptionoid varchar(200) default NULL,
  monitorSTD int(1) NOT NULL default '0',
  IgnoredValue int(4) unsigned default NULL,
  PRIMARY KEY  (shortoid)
) TYPE=MyISAM;

--
-- Table structure for table `SNMP_Value_D`
--

CREATE TABLE SNMP_Value_D (
  oid varchar(200) NOT NULL default '',
  value int(4) unsigned NOT NULL default '0',
  description varchar(50) NOT NULL default '',
  PRIMARY KEY  (oid,value)
) TYPE=MyISAM;

--
-- Table structure for table `nmap`
--

CREATE TABLE nmap (
  Service varchar(33) default NULL,
  State varchar(10) NOT NULL default '',
  Owner varchar(20) default NULL,
  Port int(4) unsigned NOT NULL default '0',
  nodeID int(4) unsigned NOT NULL default '0'
) TYPE=MyISAM;

--
-- Table structure for table `nmap_changelog`
--

CREATE TABLE nmap_changelog (
  MAC varchar(33) NOT NULL default '',
  timestamp int(4) unsigned NOT NULL default '0',
  changedescription varchar(254) default NULL,
  PRIMARY KEY  (MAC,timestamp)
) TYPE=MyISAM;

