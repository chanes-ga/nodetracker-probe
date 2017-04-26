##########################################################################################################################################
# Program: mycrypt.pm
# Author:  Christopher Hanes
# Revision: v0.3.0
# Changelog:
# 11/08/01: v0.1.0
# 11/07/01: v0.1.1 table encryption specs are now pulled from the shared table CryptSpecs instead of being hard coded for each table
# 12/12/01: v0.1.2 mcrypt 3DES implementation incompatible with Crypt::TripleDES; therefore php and perl could not communicate 
#		   so I am now using Blowfish
# 01/24/02: v0.2.0 converted into a package
# 03/06/02: v0.3.0 fixed warnings output by perl -w
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
package mycrypt;

use Digest::MD5  qw(md5 md5_hex md5_base64);
use Crypt::Blowfish;
use MIME::Base64; 


$dbh;

sub Initialize($){
	print "Initializing package crypt\n";
	$dbh=shift;
}
  
sub escape($){
	my $v=shift;
	$v=~s/\\/\\\\/g;
	$v=~s/\'/\\\'/g;

	return $v;
}

sub cryptAll($$){
	my $direction=shift;
	my $key=shift;
	my ($sth,$sth2);
	my ($r,$r2);
	my ($fieldList,$fieldTypeList);
	my ($keyfieldList,$keyfieldTypeList);
	my $table;
        $startTime=time();
	$sql="select distinct tablename from CryptSpecs order by tablename";
	$sth=$dbh->prepare($sql);
	$sth->execute();

	$r=$sth->fetchrow_hashref();
	while($r){
		$sql="select * from CryptSpecs where tablename='$r->{tablename}'";
		$table=$r->{tablename};
		$sth2=$dbh->prepare($sql);
		$sth2->execute();
		$r2=$sth2->fetchrow_hashref();
		$fieldList="";
		$fieldTypeList="";
		$keyfieldList="";
		$keyfieldTypeList="";
		while($r2){
			if ($r2->{crypt}==1){
				$fieldList=$fieldList."$r2->{fieldname},";
				$fieldTypeList=$fieldTypeList."$r2->{fieldtype},";
			}
			if ($r2->{iskey}==1){
				$keyfieldList=$keyfieldList."$r2->{fieldname},";
				$keyfieldTypeList=$keyfieldTypeList."$r2->{fieldtype},";
			}
			$r2=$sth2->fetchrow_hashref();
		}
		chop($fieldList);
		chop($fieldTypeList);
		chop($keyfieldList);
		chop($keyfieldTypeList);
		print "\tKeys: $keyfieldList\n\tFields: $fieldList\n";
	        cryptTable($direction,$table,$keyfieldList, $keyfieldTypeList, $fieldList, $fieldTypeList, $key);	
		#print "$table\n\t$fieldList\n\t$fieldTypeList\n\t$keyfieldList\n\t$keyfieldTypeList\n";
		$r=$sth->fetchrow_hashref();
	}

        $totalTime=time()-$startTime;
        print "\nAction took $totalTime seconds.\n";

        $sql="update EncryptionStatus set state=$direction";
	$sth=$dbh->prepare($sql);
	$sth->execute();

	$sth->finish();	

}



sub cryptTable($$$$$$$){
	my ($sth,$sth2,$r,$r2,$i);
	my $direction=shift;
	my $table=shift;
	my $keyfieldList=shift;
	my $keyfieldTypeList=shift;
	my $fieldList=shift;
	my $fieldTypeList=shift;
	my $key=shift;
        print "Working on $table $direction\n";
        #get the numerical key used for ciphering numerical data
        $nkey=GetNKey($key);
        my @keyfields=split(",",$keyfieldList);
        my @keyfieldtypes=split(",",$keyfieldTypeList);
        my @fields=split(",",$fieldList);
        my @fieldtypes=split(",",$fieldTypeList);

        $sql="select $keyfieldList,$fieldList from $table";
        $sth=$dbh->prepare($sql);
	$sth->execute();
        $r=$sth->fetchrow_hashref();

        while($r){ 
                #first build update part of sql statement
                $sql="update $table set ";
                $i=0;
                foreach $f(@fields){
                        $delimiter=getDelimiter($fieldtypes[$i]);
                        if ($fieldtypes[$i]==0){
                                #then need to cipher a numerical value; direction doesn't matter here
                                $v=$r->{$f};
                                $e=doxor($nkey,$v);
                        }else{
                                #need to cipher text data here
				#print "$f\t".$r->{$f}."\n";
                                $e=cryptText($direction,$r->{$f},$key);
                                if ($direction==0){
                                        #when decrypting trim off whitespace and escape any 's
					$e=escape($e);
                                        chomp($e);
                                }
                        }
                        $sql=$sql."$f=".$delimiter.$e.$delimiter.",";
                        $i++;
                }
                $sql=substr($sql,0,length($sql)-1);

                #secondly build the where condition part of the sql statement
                my $where=" where ";
                $i=0;
                foreach $kf(@keyfields){
                        $delimiter=getDelimiter($keyfieldtypes[$i]);
                        #need this I think
                        $keyfield=$r->{$kf};
                        $where=$where."$kf=".$delimiter.$keyfield.$delimiter." and ";
                        $i++;
                }
                $where=substr($where,0,length($where)-5);       #trim off last " and "
                $sql=$sql.$where;

		#Log($sql."\n");
		$sth2=$dbh->prepare($sql);
		$sth2->execute();
		if ($sth2->err){
			Log("\n$sql\n");
		}

                $r=$sth->fetchrow_hashref();
        } 

}
sub getDelimiter($){
	my $type=shift;
        if ($type=="1"){
                return "'";
        }else{
                return "";
        }
}


sub verifyKey($){
	my $key=shift;
	my ($sth,$r,$hash,$ret);
        $hash=md5_hex($key);
	#print $hash."\n";
        $sql="select state from EncryptionStatus where secret='$hash'";
	$sth=$dbh->prepare($sql);
	$sth->execute();
	
        $ret=$sth->rows;
        if ($sth->rows>0){
		$r=$sth->fetchrow_hashref();
                $ret=$ret+2*$r->{state};
        }
        return $ret;
}


sub GetNKey($){
	my $key=shift;
        my $nkey=0;
	my ($i,$t);
        for ($i=0;$i<4;$i++){
                $t=ord(substr($key,$i,1))*2**($i*8);
                $nkey=$nkey+$t;
                #print "$t\t$nkey\n";
        }
        return $nkey;
}

sub doxor($$){
	my $key=shift;
	my $value=shift;
        return $key^$value;                
}

sub cryptText($$$){
	my $direction=shift;
	my $text=shift;
	my $key=shift;
	#print "D:$direction\tText: $text\tKey:$key|\n";

	#my $des = new Crypt::TripleDES; 
	my $cipher = new Crypt::Blowfish $key; 
        if ($direction==1){
		#$rtext = $des->encrypt3 ( $text, $key );
		$rtext = cifer($direction,$text,$key);
		#now base64 encode the encrypted text
		$rtext=encode_base64($rtext);
		chop($rtext);
                #print "Encrypting $text len ".length($text)." to $rtext len ".length($rtext)."\n";

        }else{
		#now decode the base64 then decrypt
		$rtext = decode_base64($text);
		#print "Decodes to $rtext\n";
		$rtext  = cifer($direction,$rtext,$key);
                #print "Decrypting $text length ".length($text)." to $rtext length ".length($rtext)."\n";
        }
        return $rtext;
}

sub cifer($$$){
	#need this procedure for 8 byte block ciphers in order to cipher an arbitrary length string;

        my $direction=shift;
        my $text=shift;
        my $key=shift;
        my $rtext="";
        my $i;
        my $blocksize=8;
        my $cipher = new Crypt::Blowfish $key;

        $i=0;
        my $iterations=sprintf("%d",length($text)/$blocksize);

        while($i<$iterations){
                $block=substr($text,$i*$blocksize,$blocksize);
                if ($direction==1){
                        $rtext=$rtext.$cipher->encrypt($block);
                }else{
                        $rtext=$rtext.$cipher->decrypt($block);
                }
                #print "$i\t$block\n";
                $i++;
        }

        #now on last piece of plaintext
        $block=substr($text,$i*$blocksize,$blocksize);
        $padding=$blocksize-length($block);
        #print "P:$padding\nL:".length($block)."\n";
        if ($direction==1){
                for($i=0;$i<$padding;$i++){
                        $block=$block."\0";
                }
                $rtext=$rtext.$cipher->encrypt($block);
        }else{
                if ($block ne ""){
                        $rtext=$rtext.$cipher->decrypt($block);
                }
                $rtext =~ s/\0*$//;

        }
        return $rtext;
}


1;
