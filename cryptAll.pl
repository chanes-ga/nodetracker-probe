#!/usr/bin/perl
##########################################################################################################################################
# Program: cryptAll.pl
# Author:  Christopher Hanes
# Revision: v0.2.0
# Changelog:
# 11/07/01: v0.1.0 encrypts all significant data in all tables in the user's database 
#		(base64 coded TripleDES for text and 4 byte xor for IP addresses)		
# 02/19/01: v0.2.0 supprot for new mycrypt package
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

use Digest::MD5  qw(md5 md5_hex md5_base64);
use Crypt::TripleDES;
use MIME::Base64; 

### this section common to all code
($path,$program)=getPathInfo();


#this must loaded first in order for other packages to work correctly
require globals;
require mycrypt;

globals::Initialize($path,$program);
$dbh = DBI->connect($globals::dsn,$globals::user,$globals::password);

mycrypt::Initialize($dbh);

$r=mycrypt::verifyKey($globals::key);

if ($r>0){
	mycrypt::cryptAll($globals::direction,$globals::key);
}else{
	print "Invalid encryption key\n";
}

$dbh->disconnect();

sub getPathInfo(){
        #include this routing in all modules
        #determine path program was executed from so we know where to include nodetracker packages from
        $path=$0;
        if (index($path,"/")>=0){
                $separator="/";
        }elsif(index($path,"\\")>=0){
                $separator="\\";
        }       
        $pos=0; 
        while( ($pos=index($path,$separator,$pos))>=0){
                $lastpos=$pos;
                $pos++;
        }       
        $program=substr($path,$lastpos+1);
        $path=substr($path,0,$lastpos+1);
        #important!!
        push(@INC,$path);

        return ($path,$program);
}       

