##########################################################################################################################################
# Program: globals.pm
# Author:  Christopher Hanes
# Revision: v0.2.0
# Changelog:
# 01/24/02: v0.1.0
# 02/01/02: v0.1.1 minor corrections to code
# 03/13/02: v0.2.0 added support for previosly command-line only option to be specified in conf file
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

package globals;

use DBI;
use Getopt::Std;
use Mail::Sendmail;
use Date::Format qw(time2str);

use Exporter;
@ISA = ('Exporter');
@EXPORT = ('Log','SendEmail');



#configuration hash from nodetracker.conf
%conf=();

#path to all modules
$path;

$program;

$user;
$password;
$dsn;

#encryption key
$key;

#encryption key validity and db encryption state 
$keyvalid;

#key is valid and data is encrypted
$stateEncrypted=3;

$typeRouter=3;
$typeSwitch=2;
$routerOID=".1.3.6.1.2.1.4.22.1.2";
$routerIPOID=".1.3.6.1.2.1.4.20.1.1";
$routerIPIfnumOID="1.3.6.1.2.1.4.20.1.2";
$routerIPMaskOID="1.3.6.1.2.1.4.20.1.3";
$IFDescriptionOID=".1.3.6.1.2.1.2.2.1.2";
$IFSpeedOID=".1.3.6.1.2.1.2.2.1.5";
$IFOpStatusOID=".1.3.6.1.2.1.2.2.1.8";
$IFPhysAddressOID=".1.3.6.1.2.1.2.2.1.6";
$switchPortTableOID=".1.3.6.1.2.1.17.4.3.1.2";
$switchPortTypeTableOID=".1.3.6.1.2.1.17.4.3.1.3";
$switchPortIFIndex=".1.3.6.1.2.1.17.1.4.1.2";

sub Initialize($$){
	$path=shift;
	$program=shift;
	#print "$path|$program\n";
	# -d database
	# -u user
	# -p password
	# -e email list
	# -f config file
	# -k encryption key
	# -x cipher direction
	# -a autodiscovery for nmap
	getopts('d:u:p:e:f:k:x:a');

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
	    $conf{$var} = $value;
	    #print "Read $var\t=\t$value\n";
	} 
	close(CONFIG);


	#Database settings
	$driver="mysql";
	$hostname=$conf{"nodetrackerserver"};
	if ($opt_d){
		$database=$opt_d;       #as specified on the command line
	}else{
		$database=$conf{db};
	}
	if ($opt_u){
		$user=$opt_u;
	}else{
		$user=$conf{username};
	}
	if ($opt_p){
		$password=$opt_p;
	}else{
		$password=$conf{password};
	}

	if ($opt_e){
		$emails=$opt_e;
	}else{
		$emails=$conf{emails};
	}
	$mailserver=$conf{"mailserver"};
	$dsn="DBI:$driver:database=$database;host=$hostname;mysql_client_found_rows=true;mysql_ssl=0";
	$nmap=$conf{"nmap"}." -I -O -v ";

	if ($opt_k){
		$key=$opt_k;
	}else{
		$key=$conf{key};
	}
	$direction=$opt_x;
	
	$logfile=$conf{"logpath"}.$program.".log";
	print "Logging to $logfile\n";
	open(LOG,">".$logfile) or die "Unable to open $logfile\n";
}

sub SendEmail($$){
        my $subject=shift;
        my $body=shift;

        Log("Sending alert to $emails\n");
        %mail = ( To      => $emails,
                From    => 'alert@nodetracker.net',
                Message => $body,
                Subject => $subject,
                smtp =>$conf{mailserver}
        );
        
        if (!sendmail(%mail)){  
		print $Mail::Sendmail::error."\n";
	}
}
sub Log($){
        my $message=shift;
	if (length($message)>2){
		$message=time2str("%c",time()).":  ".$message;
	}
	print $message;
        print LOG $message;
}
sub Shutdown(){
	close(LOG);
	exit;
}
1;
