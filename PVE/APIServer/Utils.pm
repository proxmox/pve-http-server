package PVE::APIServer::Utils;

use strict;
use warnings;

use Net::IP;

sub read_proxy_config {
    my ($proxy_name) = @_;

    my $conffile = "/etc/default/$proxy_name";

    # Note: evaluate with bash
    my $shcmd = ". $conffile;\n";
    $shcmd .= 'echo \"ALLOW_FROM:\$ALLOW_FROM\";';
    $shcmd .= 'echo \"DENY_FROM:\$DENY_FROM\";';
    $shcmd .= 'echo \"POLICY:\$POLICY\";';
    $shcmd .= 'echo \"CIPHERS:\$CIPHERS\";';
    $shcmd .= 'echo \"DHPARAMS:\$DHPARAMS\";';
    $shcmd .= 'echo \"HONOR_CIPHER_ORDER:\$HONOR_CIPHER_ORDER\";';
    $shcmd .= 'echo \"COMPRESSION:\$COMPRESSION\";';

    my $data = -f $conffile ? `bash -c "$shcmd"` : '';

    my $res = {};

    while ($data =~ s/^(.*)\n//) {
	my ($key, $value) = split(/:/, $1, 2);
	next if !defined($value) || $value eq '';
	if ($key eq 'ALLOW_FROM' || $key eq 'DENY_FROM') {
	    my $ips = [];
	    foreach my $ip (split(/,/, $value)) {
		$ip = "0/0" if $ip eq 'all';
		push @$ips, Net::IP->new($ip) || die Net::IP::Error() . "\n";
	    }
	    $res->{$key} = $ips;
	} elsif ($key eq 'POLICY') {
	    die "unknown policy '$value'\n" if $value !~ m/^(allow|deny)$/;
	    $res->{$key} = $value;
	} elsif ($key eq 'CIPHERS') {
	    $res->{$key} = $value;
	} elsif ($key eq 'DHPARAMS') {
	    $res->{$key} = $value;
	} elsif ($key eq 'HONOR_CIPHER_ORDER' || $key eq 'COMPRESSION') {
	    die "unknown value '$value' - use 0 or 1\n" if $value !~ m/^(0|1)$/;
	    $res->{$key} = $value;
	} else {
	    # silently skip everythin else?
	}
    }

    return $res;
}

1;
