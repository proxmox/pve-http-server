#!/usr/bin/perl

package DemoServer;

use strict;
use warnings;
use HTTP::Status qw(:constants);
use URI::Escape;

use PVE::APIServer::AnyEvent;
use PVE::Exception qw(raise_param_exc);

use base('PVE::APIServer::AnyEvent');

use Digest::MD5;

my $secret = Digest::MD5::md5_base64($$ . time());

sub create_ticket {
    my ($username) = @_;

    return "$username:$secret";
}

sub auth_handler {
    my ($self, $method, $rel_uri, $ticket, $token, $peer_host) = @_;

    # explicitly allow some calls without authentication
    if ($rel_uri eq '/access/ticket' && 
	($method eq 'POST' || $method eq 'GET')) {
	return; # allow call to create ticket
    }

    die "no ticket" if !defined($ticket);

    my ($userid, $rest) = split(/:/, $ticket, 2);
    die "invalid unsername" if $userid ne 'demo';
    die "invalid ticket" if $rest ne $secret;
    
    return {
	ticket => $ticket,
	userid => $userid,
    };    
}

sub rest_handler {
    my ($self, $clientip, $method, $rel_uri, $auth, $params) = @_;

    my $resp = {
	status => HTTP_NOT_IMPLEMENTED,
	message => "Method '$method $rel_uri' not implemented",
    };
    if ($rel_uri eq '/access/ticket') {
	if ($method eq 'POST') {
	    if ($params->{username} && $params->{username} eq 'demo' &&
		$params->{password} && $params->{password} eq 'demo') {
		return {
		    status => HTTP_OK,
		    data => {
			ticket => create_ticket($params->{username}),
		    },
		};
	    }
	    return $resp;
	} elsif ($method eq 'GET') {
	    # this is allowed to display the login form
	    return { status => HTTP_OK, data => {} };
	} else {
	    return $resp;
	}
    }
    
    $resp = {
	data => {
	    method => $method,
	    clientip => $clientip,
	    rel_uri =>  $rel_uri,
	    auth => $auth,
	    params => $params,
	},
	info => { description => "You called API method '$method $rel_uri'" },
	status => HTTP_OK,
    };

    return $resp;
}


package main;

use strict;
use warnings;

use Socket qw(IPPROTO_TCP TCP_NODELAY SOMAXCONN);
use IO::Socket::IP;
use HTTP::Headers;
use HTTP::Response;

use PVE::Tools qw(run_command);
use PVE::INotify;
use PVE::APIServer::Formatter::Standard;
use PVE::APIServer::Formatter::HTML;

my $nodename = PVE::INotify::nodename();
my $port = 9999;

my $cert_file = "simple-demo.pem";

if (! -f $cert_file) {
    print "generating demo server certificate\n";
    my $cmd = ['openssl', 'req', '-batch', '-x509', '-newkey', 'rsa:4096',
	       '-nodes', '-keyout', $cert_file, '-out', $cert_file,
	       '-subj', "/CN=Simple Demo Server/OU=$nodename/",
	       '-days', '3650'];
    run_command($cmd);
}

my $socket = IO::Socket::IP->new(
    LocalAddr => $nodename,
    LocalPort => $port,
    Listen => SOMAXCONN,
    Proto  => 'tcp',
    GetAddrInfoFlags => 0,
    ReuseAddr => 1) ||
    die "unable to create socket - $@\n";

# we often observe delays when using Nagle algorithm,
# so we disable that to maximize performance
setsockopt($socket, IPPROTO_TCP, TCP_NODELAY, 1);

my $accept_lock_fn = "simple-demo.lck";
my $lockfh = IO::File->new(">>${accept_lock_fn}") ||
    die "unable to open lock file '${accept_lock_fn}' - $!\n";

my $server = DemoServer->new(
    socket => $socket,
    lockfile => $accept_lock_fn,
    lockfh => $lockfh,
    title => 'Simple Demo API',
    logfh => \*STDOUT,
    tls_ctx  => { verify => 0, cert_file => $cert_file },
    pages => {
	'/' => sub { get_index($nodename, @_) },
    },
);

# NOTE: Requests to non-API pages are not authenticated
# so you must be very careful here

my $root_page = <<__EOD__;
<!DOCTYPE html>
<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
    <title>Simple Demo Server</title>
  </head>
  <body>
    <h1>Simple Demo Server ($nodename)</h1>

    You can browse the API <a href='/api2/html' >here</a>. Please sign
    in with usrename <b>demo</b> and passwort <b>demo</b>.

  </body>
</html>
__EOD__
    
sub get_index {
    my ($nodename, $server, $r, $args) = @_;

    my $headers = HTTP::Headers->new(Content_Type => "text/html; charset=utf-8");
    my $resp = HTTP::Response->new(200, "OK", $headers, $root_page);

}

print "demo server listens at: https://$nodename:$port/\n";

$server->run();
