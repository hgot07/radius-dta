#!/usr/bin/perl
#
# Disruption-Tolerant Authentication (DTA) demo
#   Hideaki Goto
#
# PoC implementation of the method presented in
# "Disruption-tolerant Local Authentication Method for
#  Network Roaming Systems"
# https://doi.org/10.2197/ipsjjip.32.407
#
# 20240525	Initial release
# 20260605	Add note about Android's limitation
# 20260628	Modernize. Include the realm into HMAC and signature.
#

# Realm (lower-case only)
my $realm = 'dta.example.com';

# HMAC shared key - Generate your own key and use it!
my $key = 'izivz7Km2kHW0rF4wc0UXuAlV8PFNNgNYN9WarKw';


# To see supported curves,
#  openssl ecparam -list_curves
#
# To create an EC key pair,
#  openssl ecparam -genkey -name secp128r1 -out eckey-pair.pem
#  openssl ec -in eckey-pair.pem -outform PEM -pubout -out eckey-pub.pem
#  openssl ec -in eckey-pair.pem -outform PEM -out eckey-priv.pem
#
# Note: secp128r1 has been dropped in recent versions of openssl.
#   Android needs this small curve since it limits User-Name up to 62b.
#
# To view the EC key pair content,
#  openssl ec -text -noout -in eckey-priv.pem

use strict;
use warnings;
use DateTime;
use MIME::Base64;
use Digest::SHA qw(hmac_sha256_base64);
use File::Basename;

use Crypt::PK::ECC;

use Cwd 'realpath';
my $SCRIPTDIR = realpath(dirname($0));

# delimiter (See RFC 7542 as well as 4282 for usable characters.)
my $dlm = '|';

# Encoding scheme selector (one letter)
my $EncScheme = 'C';

# Not before
my $sdate = DateTime->now();
$sdate->set( hour => 0, minute => 0, second => 0);

# Valid days (0:no limit, 1-4095)
my $days = 90;

my $edate = $sdate->clone->add(days => $days);


sub val2c {
	my $v = $_[0];
	if ( $v < 0 || $v > 61 ){ return ''; }
	if ( $v < 26 ){ return chr($v + 0x41); }
	if ( $v < 52 ){ return chr($v + 0x61 - 26); }
	return chr($v + 0x30 - 52);
}

sub c2val {
	my $v = ord($_[0]);
	if ( $v >= 0x30 && $v <= 0x39 ){ return $v - 0x30 + 52; }
	if ( $v >= 0x41 && $v <= 0x5a ){ return $v - 0x41; }
	if ( $v >= 0x61 && $v <= 0x7a ){ return $v - 0x61 + 26; }
	return(-1);
}

sub random_b64_string {
	my ($len) = @_;
	my @b64 = ('A'..'Z', 'a'..'z', '0'..'9', '+', '/');
	return join '', map { $b64[int rand @b64] } 1..$len;
}

my $rstr = random_b64_string(3);

# Compose User-Name and derive Password
# SYMDLLrrr
my $datecode = sprintf("%s%s%s%s%s",
  val2c($sdate->year - 2000), val2c($sdate->month), 
  val2c($sdate->day), val2c(int($days /64)), val2c($days %64));
my $userID = $EncScheme.$datecode.$rstr;
$realm = lc $realm;	# enforce lower-case
my $username = $userID.'@'.$realm;

# SHA256 always produces 43 chars. Padding is of no use in this app.
my $hmac64 = hmac_sha256_base64($username, $key).'=';
my $password = substr($hmac64, 0, 12);

print "Not before:  ".$sdate."Z\n";
print "Valid until: ".$edate."Z\n";
print "User-Name: ".$username."\n";
print "Password: ".$password."\n";
print "HMAC: ".$hmac64."\n";

# https://manpages.ubuntu.com/manpages/bionic/man3/Crypt::PK::ECC.3pm.html

my $priv = Crypt::PK::ECC->new("$SCRIPTDIR/eckey-priv.pem");
my $sig = $priv->sign_message($username, 'SHA256');
my $sig64 = encode_base64($sig, "");
chomp($sig64);

my $UN = $userID.$dlm.$sig64;
my $RadUserName = $UN.'@'.$realm;

print "Signed User-Name: ".$RadUserName."\n";
print "User-Name Length: ".length($RadUserName)."\n";
print "User ID Length: ".length($UN)."\n";

print "\n----------------\n";


#-----------------
# AAA server side
#-----------------

$username = $RadUserName;
$EncScheme = substr($username, 0, 1);

my $validYear = 2000 + c2val(substr($username, 1, 1));
my $validMonth = c2val(substr($username, 2, 1));
my $validDay = c2val(substr($username, 3, 1));
$days = c2val(substr($username, 4, 1)) * 64;
$days += c2val(substr($username, 5, 1));

print "Received User-Name: ",$RadUserName."\n";
print "Encoding scheme: ".$EncScheme."\n";

if ( $validYear < 2000 || $validMonth < 0 || $validMonth > 12 
  || $validDay < 0 || $validDay > 31 || $days < 0 || $days > 4095 ){
	print "Error: Received malformed User-Name.\n";
	exit(1);
}

$sdate = DateTime->new(
 year => $validYear, month => $validMonth, day => $validDay, 
 hour => 0, minute => 0, second => 0
);

$edate = $sdate->clone->add(days => $days);

print "Not before:  ".$sdate."Z\n";
print "Valid until: ".$edate."Z\n";

my $ct = DateTime->now();
$ct->set( hour => 0, minute => 0, second => 0);

if ( DateTime->compare($sdate, $ct) > 0
  || DateTime->compare($edate, $ct) < 0 ){
	print "Warning: Not valid.\n";
}


$userID = $realm = $username;
$realm =~ s/^.*@//;
$realm = lc $realm;	# enforce lower-case
$userID =~ s/@.*$//;

if ( $username !~ /@/ ){	# no realm?
	$realm = '';
}

$sig64 = $userID;
if ( $userID =~ /\Q$dlm/ ){	# contains delimiter?
	$userID =~ s/\Q$dlm\E.*//;
	$sig64 =~ s/.*\Q$dlm\E//;
}
else{
	$sig64 = '';
}

print "Extracted Signature: ".$sig64."\n";

$username = $userID;	# canonicalize username
if ( $realm ne '' ){
	$username .= '@'.$realm;
}

print "Signature check: ";
if ( $sig64 eq '' ){
	print "N/A\n";
}
else {
	$sig = decode_base64($sig64);
	my $pub = Crypt::PK::ECC->new("$SCRIPTDIR/eckey-pub.pem");
	if ( $pub->verify_message($sig, $username, 'SHA256') ){
		print "OK\n";
	}
	else{	print "NG\n";
	}
}


$hmac64 = hmac_sha256_base64($username, $key).'=';
$password = substr($hmac64, 0, 12);

print "Extracted User-Name: ",$username."\n";
print "Extracted UserID: ",$userID."\n";
print "Extracted Realm: ".$realm."\n";
print "Decoded password: ".$password."\n";
print "HMAC: ".$hmac64."\n";

1;
