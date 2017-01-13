package PVE::APIServer::Formatter;

use strict;
use warnings;

# generic formatter support
# PVE::APIServer::Formatter::* classes should register themselves here

my $formatter_hash = {};

sub register_formatter {
    my ($format, $func) = @_;

    die "formatter '$format' already defined" if $formatter_hash->{$format};

    $formatter_hash->{$format} = {
	func => $func,
    };
}

sub get_formatter {
    my ($format) = @_;

     return undef if !$format;

    my $info = $formatter_hash->{$format};
    return undef if !$info;

    return $info->{func};
}

my $login_formatter_hash = {};

sub register_login_formatter {
    my ($format, $func) = @_;

    die "login formatter '$format' already defined" if $login_formatter_hash->{$format};

    $login_formatter_hash->{$format} = {
	func => $func,
    };
}

sub get_login_formatter {
    my ($format) = @_;

    return undef if !$format;

    my $info = $login_formatter_hash->{$format};
    return undef if !$info;

    return $info->{func};
}

# some helper functions

sub extract_auth_cookie {
    my ($cookie, $cookie_name) = @_;

    return undef if !$cookie;

    my $ticket = ($cookie =~ /(?:^|\s)\Q$cookie_name\E=([^;]*)/)[0];

    if ($ticket && $ticket =~ m/^PVE%3A/) {
	$ticket = uri_unescape($ticket);
    }

    return $ticket;
}

sub create_auth_cookie {
    my ($ticket, $cookie_name) = @_;

    my $encticket = uri_escape($ticket);

    return "${cookie_name}=$encticket; path=/; secure;";
}

1;
