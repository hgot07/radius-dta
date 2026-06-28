#!/usr/bin/perl

use strict;
use warnings;
use Crypt::PK::ECC;

my $pk = Crypt::PK::ECC->new();
$pk->generate_key('secp128r1');

my $priv_pem = $pk->export_key_pem('private');
my $pub_pem  = $pk->export_key_pem('public');

my $priv_file = 'eckey-priv.pem';
my $pub_file  = 'eckey-pub.pem';

open my $priv_fh, '>', $priv_file or die "Cannot open $priv_file: $!";
print {$priv_fh} $priv_pem;
close $priv_fh or die "Cannot close $priv_file: $!";

open my $pub_fh, '>', $pub_file or die "Cannot open $pub_file: $!";
print {$pub_fh} $pub_pem;
close $pub_fh or die "Cannot close $pub_file: $!";

print "Private key written to $priv_file\n";
print "Public key written to $pub_file\n";
