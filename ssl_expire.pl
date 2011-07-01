#!/usr/bin/perl -w

# Check peer certificate validity, Returns the days left to the expiry date
# from the cerificate
# If connection fails, 0 is returned
# Require perl module : IO::Socket, Net::SSLeay, Date::Parse;
# Require unix programs : openssl
# Usage: ssl_expire <HOST> <PORT>, Port is optinal, 443 is default

# Based on the Script from Emmanuel Lacour
# http://sslexpire.home-dn.net/src/sslexpire-0.6.2/

use strict;
use IO::Socket;
use Net::SSLeay;
use Getopt::Long;
use Date::Parse;

Net::SSLeay::SSLeay_add_ssl_algorithms();
Net::SSLeay::randomize();

my $opensslpath = "/usr/bin/openssl";

my $host = $ARGV[0];
my $expdate = 0;
my $port = 443;
my $days_left = 0;
my $expiry_timestamp = 0;
if($ARGV[1])
{
    $port = $ARGV[1];
}

# Connect to $host:$port
my $socket = IO::Socket::INET->new(Proto => "tcp",PeerAddr => $host,PeerPort => $port);
# If we connected successfully
if ($socket)
{
    # Intiate ssl
    my $ctx = Net::SSLeay::CTX_new();
    my $ssl = Net::SSLeay::new($ctx);
    Net::SSLeay::set_fd($ssl, fileno($socket));
    my $res = Net::SSLeay::connect($ssl);
    # Get peer certificate
    my $x509 = Net::SSLeay::get_peer_certificate($ssl);
    if ($x509)
    {
        my $string = Net::SSLeay::PEM_get_string_X509($x509);
        # Get the expiration date, using openssl
	($expdate) = split(/\n/, `echo "$string" | $opensslpath x509 -enddate -subject -noout 2>&1`);
        $expdate =~ s/.*=//;
        chomp($expdate);
    }
    # Close and cleanup
    Net::SSLeay::free($ssl);
    Net::SSLeay::CTX_free($ctx);
    close $socket;
}
$expiry_timestamp = str2time($expdate)."\n";
$days_left        = ($expiry_timestamp-time())/86400;
print int($days_left)."\n";