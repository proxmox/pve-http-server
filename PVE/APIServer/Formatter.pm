package PVE::APIServer::Formatter;

use strict;
use warnings;

use URI::Escape;

# generic formatter support
# PVE::APIServer::Formatter::* classes should register themselves here

my $formatter_hash = {};
my $page_formatter_hash = {};

sub register_formatter {
    my ($format, $code) = @_;

    die "formatter '$format' already defined"
	if defined($formatter_hash->{$format});

    $formatter_hash->{$format} = $code;
}

sub register_page_formatter {
    my (%config) = @_;

    my $format = $config{format} ||
	die "missing format";

    my $path = $config{path} ||
	die "missing path";

    my $method = $config{method} ||
	die "missing method";

    my $code = $config{code} ||
	die "missing formatter code";

    die "duplicate page formatter for '$method: $path'"
	if defined($page_formatter_hash->{$format}->{$method}->{$path});

    $page_formatter_hash->{$format}->{$method}->{$path} = $code;
}

sub get_formatter {
    my ($format, $method, $path) = @_;

    return undef if !defined($format);

    if (defined($method) && defined($path)) {
	my $code = $page_formatter_hash->{$format}->{$method}->{$path};
	return $code if defined($code);
    }

    return $formatter_hash->{$format};
}

my $login_formatter_hash = {};

sub register_login_formatter {
    my ($format, $code) = @_;

    die "login formatter '$format' already defined"
	if defined($login_formatter_hash->{$format});

    $login_formatter_hash->{$format} = $code;
}

sub get_login_formatter {
    my ($format) = @_;

    return undef if !defined($format);

    return $login_formatter_hash->{$format};
}

# some helper functions

sub extract_auth_cookie {
    my ($cookie, $cookie_name) = @_;

    return undef if !$cookie;

    my $ticket = ($cookie =~ /(?:^|\s)\Q$cookie_name\E=([^;]*)/)[0];

    $ticket = uri_unescape($ticket) if $ticket;

    return $ticket;
}

sub create_auth_cookie {
    my ($ticket, $cookie_name) = @_;

    my $encticket = uri_escape($ticket);

    return "${cookie_name}=$encticket; path=/; secure;";
}

1;
