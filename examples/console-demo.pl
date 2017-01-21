#!/usr/bin/perl

# This demo requires some other packages: novnc-pve and
# pve-manager (for PVE::NoVncIndex)


# First, we need some helpers to create authentication Tickets

package Ticket;

use strict;
use warnings;
use Net::SSLeay;

use PVE::Ticket;

use Crypt::OpenSSL::RSA;

my $min_ticket_lifetime = -60*5; # allow 5 minutes time drift
my $max_ticket_lifetime = 60*60*2; # 2 hours

my $rsa = Crypt::OpenSSL::RSA->generate_key(2048);

sub create_ticket {
    my ($username) = @_;

    return PVE::Ticket::assemble_rsa_ticket($rsa, 'DEMO', $username);
}

sub verify_ticket {
    my ($ticket, $noerr) = @_;

    return PVE::Ticket::verify_rsa_ticket(
	$rsa, 'DEMO', $ticket, undef,
	$min_ticket_lifetime, $max_ticket_lifetime, $noerr);
}

# VNC tickets
# - they do not contain the username in plain text
# - they are restricted to a specific resource path (example: '/vms/100')
sub assemble_vnc_ticket {
    my ($username, $path) = @_;

    my $secret_data = "$username:$path";

    return PVE::Ticket::assemble_rsa_ticket(
	$rsa, 'DEMOVNC', undef, $secret_data);
}

sub verify_vnc_ticket {
    my ($ticket, $username, $path, $noerr) = @_;

    my $secret_data = "$username:$path";

    return PVE::Ticket::verify_rsa_ticket(
	$rsa, 'DEMOVNC', $ticket, $secret_data, -20, 40, $noerr);
}

# We stack several PVE::RESTHandler classes to create
# the API for the novnc-pve console.

package NodeInfoAPI;

use strict;
use warnings;

use PVE::RESTHandler;
use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTEnvironment;
use PVE::SafeSyslog;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    permissions => { user => 'all' },
    description => "Node index.",
    parameters => {
    	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {},
	},
	links => [ { rel => 'child', href => "{name}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $result = [
	    { name => 'vncshell' },
	];

	return $result;
    }});

__PACKAGE__->register_method ({
    name => 'vncshell',
    path => 'vncshell',
    method => 'POST',
    description => "Creates a VNC Shell proxy.",
    parameters => {
    	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    websocket => {
		optional => 1,
		type => 'boolean',
		description => "use websocket instead of standard vnc.",
		default => 1,
	    },
	},
    },
    returns => {
    	additionalProperties => 0,
	properties => {
	    user => { type => 'string' },
	    ticket => { type => 'string' },
	    port => { type => 'integer' },
	    upid => { type => 'string' },
	},
    },
    code => sub {
	my ($param) = @_;

	my $node = $param->{node};

	# we only implement the websocket based VNC here
	my $websocket = $param->{websocket} // 1;
	die "standard VNC not implemented" if !$websocket;

	my $authpath = "/nodes/$node";

	my $restenv = PVE::RESTEnvironment->get();
	my $user = $restenv->get_user();

	my $ticket = Ticket::assemble_vnc_ticket($user, $authpath);

	my $family = PVE::Tools::get_host_address_family($node);
	my $port = PVE::Tools::next_vnc_port($family);

	my $cmd = ['/usr/bin/vncterm', '-rfbport', $port,
		   '-timeout', 10, '-notls', '-listen', 'localhost',
		   '-c', '/usr/bin/top'];

	my $realcmd = sub {
	    my $upid = shift;

	    syslog ('info', "starting vnc proxy $upid\n");

	    my $cmdstr = join (' ', @$cmd);
	    syslog ('info', "launch command: $cmdstr");

	    eval {
		foreach my $k (keys %ENV) {
		    next if $k eq 'PATH' || $k eq 'TERM' || $k eq 'USER' || $k eq 'HOME';
		    delete $ENV{$k};
		}
		$ENV{PWD} = '/';

		$ENV{PVE_VNC_TICKET} = $ticket; # pass ticket to vncterm

		PVE::Tools::run_command($cmd, errmsg => "vncterm failed");
	    };
	    if (my $err = $@) {
		syslog('err', $err);
	    }

	    return;
	};

	my $upid = $restenv->fork_worker('vncshell', "", $user, $realcmd);

	PVE::Tools::wait_for_vnc_port($port);

	return {
	    user => $user,
	    ticket => $ticket,
	    port => $port,
	    upid => $upid,
	};
    }});

__PACKAGE__->register_method({
    name => 'vncwebsocket',
    path => 'vncwebsocket',
    method => 'GET',
    description => "Opens a weksocket for VNC traffic.",
    parameters => {
    	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vncticket => {
		description => "Ticket from previous call to vncproxy.",
		type => 'string',
		maxLength => 512,
	    },
	    port => {
		description => "Port number returned by previous vncproxy call.",
		type => 'integer',
		minimum => 5900,
		maximum => 5999,
	    },
	},
    },
    returns => {
	type => "object",
	properties => {
	    port => { type => 'string' },
	},
    },
    code => sub {
	my ($param) = @_;

	my $authpath = "/nodes/$param->{node}";

	my $restenv = PVE::RESTEnvironment->get();
	my $user = $restenv->get_user();

	Ticket::verify_vnc_ticket($param->{vncticket}, $user, $authpath);

	my $port = $param->{port};

	return { port => $port };
    }});


package NodeAPI;

use strict;
use warnings;

use PVE::RESTHandler;
use PVE::JSONSchema qw(get_standard_option);

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    subclass => "NodeInfoAPI",
    path => '{node}',
});

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    permissions => { user => 'all' },
    description => "Cluster node index.",
    parameters => {
    	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {},
	},
	links => [ { rel => 'child', href => "{node}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $res = [
	   { node => 'elsa' },
	];

	return $res;
    }});


package YourAPI;

use strict;
use warnings;

use PVE::RESTHandler;
use PVE::JSONSchema;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    subclass => "NodeAPI",
    path => 'nodes',
});

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    permissions => { user => 'all' },
    description => "Directory index.",
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		subdir => { type => 'string' },
	    },
	},
	links => [ { rel => 'child', href => "{subdir}" } ],
    },
    code => sub {
	my ($resp, $param) = @_;

	my $res = [ { subdir => 'nodes' } ];

	return $res;
    }});


# This is the REST/HTTPS Server
package DemoServer;

use strict;
use warnings;
use HTTP::Status qw(:constants);
use URI::Escape;

use PVE::APIServer::AnyEvent;
use PVE::Exception qw(raise_param_exc);
use PVE::RESTEnvironment;

use base('PVE::APIServer::AnyEvent');

sub new {
    my ($this, %args) = @_;

    my $class = ref($this) || $this;

    my $self = $class->SUPER::new(%args);

    PVE::RESTEnvironment->init('pub');

    return $self;
}

sub auth_handler {
    my ($self, $method, $rel_uri, $ticket, $token, $peer_host) = @_;

    my $restenv = PVE::RESTEnvironment::get();
    $restenv->set_user(undef);

    # explicitly allow some calls without authentication
    if ($rel_uri eq '/access/ticket' &&
	($method eq 'POST' || $method eq 'GET')) {
	return; # allow call to create ticket
    }

    my $userid = Ticket::verify_ticket($ticket);
    $restenv->set_user($userid);

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
			ticket => Ticket::create_ticket($params->{username}),
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

    my ($handler, $info);

    eval {
	my $uri_param = {};
	($handler, $info) = YourAPI->find_handler($method, $rel_uri, $uri_param);
	return if !$handler || !$info;

	foreach my $p (keys %{$params}) {
	    if (defined($uri_param->{$p})) {
		raise_param_exc({$p =>  "duplicate parameter (already defined in URI)"});
	    }
	    $uri_param->{$p} = $params->{$p};
	}

	$resp = {
	    data => $handler->handle($info, $uri_param),
	    info => $info, # useful to format output
	    status => HTTP_OK,
	};
    };
    if (my $err = $@) {
	$resp = { info => $info };
	if (ref($err) eq "PVE::Exception") {
	    $resp->{status} = $err->{code} || HTTP_INTERNAL_SERVER_ERROR;
	    $resp->{errors} = $err->{errors} if $err->{errors};
	    $resp->{message} = $err->{msg};
	} else {
	    $resp->{status} =  HTTP_INTERNAL_SERVER_ERROR;
	    $resp->{message} = $err;
	}
    }

    return $resp;
}


# The main package creates the socket and runs the server
package main;

use strict;
use warnings;

use Socket qw(IPPROTO_TCP TCP_NODELAY SOMAXCONN);
use IO::Socket::IP;
use HTTP::Headers;
use HTTP::Response;
use Data::Dumper;

use PVE::Tools qw(run_command);
use PVE::INotify;
use PVE::APIServer::Formatter::Standard;
use PVE::APIServer::Formatter::HTML;
use PVE::NoVncIndex;

my $nodename = PVE::INotify::nodename();
my $port = 9999;

my $cert_file = "simple-demo.pem";

if (! -f $cert_file) {
    print "generating demo server certificate\n";
    my $cmd = ['openssl', 'req', '-batch', '-x509', '-newkey', 'rsa:4096',
	       '-nodes', '-keyout', $cert_file, '-out', $cert_file,
	       '-subj', "/CN=$nodename/",
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

my $dirs = {};
PVE::APIServer::AnyEvent::add_dirs(
    $dirs, '/novnc/' => '/usr/share/novnc-pve/');

my $server = DemoServer->new(
    debug => 1,
    socket => $socket,
    lockfile => $accept_lock_fn,
    lockfh => $lockfh,
    title => 'Simple Demo API',
    cookie_name => 'DEMO',
    logfh => \*STDOUT,
    tls_ctx  => { verify => 0, cert_file => $cert_file },
    dirs => $dirs,
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

    <p>You can browse the API <a href='/api2/html' >here</a>. Please sign
    in with usrename <b>demo</b> and passwort <b>demo</b>.</p>

    <p>Server console is here: <a href="?console=shell&novnc=1&node=$nodename">Console</a>

  </body>
</html>
__EOD__

sub get_index {
    my ($nodename, $server, $r, $args) = @_;

    my $token = '';

    my ($ticket, $userid);
    if (my $cookie = $r->header('Cookie')) {
	#$ticket = PVE::APIServer::Formatter::extract_auth_cookie($cookie, $server->{cookie_name});
#	$userid = Ticket::verify_ticket($ticket, 1);
    }

    my $page = $root_page;

    if (defined($args->{console}) && $args->{novnc}) {
	$page = PVE::NoVncIndex::get_index('en', $userid, $token,
						      $args->{console}, $nodename);
    }

    my $headers = HTTP::Headers->new(Content_Type => "text/html; charset=utf-8");
    my $resp = HTTP::Response->new(200, "OK", $headers, $page);

    return $resp;
}

print "demo server listens at: https://$nodename:$port/\n";

$server->run();
