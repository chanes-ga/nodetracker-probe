##########################################################################################################################################
# Program: common.pl
# Author:  Christopher Hanes
# Revision: v0.1.2
# Changelog:
# 10/31/01: v0.1.0 this script consolidates functionality common to other scripts; basic function is to read config
#	    data and setup some global variables
# 11/07/01: v0.1.1 changes to improve ease of startup
# 12/11/01: v0.1.2 explanatory comments
##########################################################################################################################################
#    Copyright (C) 2001  Christopher A. Hanes
#    
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or   
#    (at your option) any later version.
#    
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of 
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the 
#    GNU General Public License for more details.
#    
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#    
#########################################################################################################################################

use DBI;
use Getopt::Std;



# -d database
# -u user
# -p password
# -e email list
# -f config file
# -k encryption key
# -x cipher direction
# -a autodiscovery for nmap
getopts('d:u:p:e:f:k:x:a');

$utilsPackage=$path."utils.pm";
require $utilsPackage;


if ($opt_f){
	$configfile=$opt_f."nodetracker.conf";
}else{	
	$configfile=$path."nodetracker.conf";
}
	
#read settings from config file
open (CONFIG,$configfile) or die ("Unable to open $configfile\n");
while (<CONFIG>) {
    chomp;                  # no newline
    s/#.*//;                # no comments
    s/^\s+//;               # no leading white
    s/\s+$//;               # no trailing white
    next unless length;     # anything left?
    my ($var, $value) = split(/\s*=\s*/, $_, 2);
    $globals::conf{$var} = $value;
    print "Read $var\t=\t$value\n";
} 
close(CONFIG);


#Database settings
$driver="mysql";
$hostname=$conf{"nodetrackerserver"};
$database=$opt_d;       #as specified on the command line
$user=$opt_u;
$password=$opt_p;
$emails=$opt_e;
$mailserver=$conf{"mailserver"};
$dsn="DBI:$driver:database=$database;host=$hostname;mysql_client_found_rows=true";
$nmap=$conf{"nmap"}." -I -O -v ";
$globals::key=$opt_k;
$direction=$opt_x;

$logfile=$conf{"logpath"}.$program.".log";
print "Logging to $logfile\n";
open(LOG,">".$logfile) or die "Unable to open $logfile\n";

