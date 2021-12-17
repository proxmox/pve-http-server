package PVE::APIServer::Utils;

use strict;
use warnings;

use Net::IP;

# all settings are used for pveproxy and pmgproxy
# the ALLOW/DENY/POLICY is also used by spiceproxy
sub read_proxy_config {
    my ($proxy_name) = @_;

    my $conffile = "/etc/default/$proxy_name";

    # Note: evaluate with bash
    my $shcmd = ". $conffile;\n";
    $shcmd .= 'echo \"LISTEN_IP:\$LISTEN_IP\";';
    $shcmd .= 'echo \"ALLOW_FROM:\$ALLOW_FROM\";';
    $shcmd .= 'echo \"DENY_FROM:\$DENY_FROM\";';
    $shcmd .= 'echo \"POLICY:\$POLICY\";';
    $shcmd .= 'echo \"CIPHERS:\$CIPHERS\";';
    $shcmd .= 'echo \"CIPHERSUITES:\$CIPHERSUITES\";';
    $shcmd .= 'echo \"DHPARAMS:\$DHPARAMS\";';
    $shcmd .= 'echo \"TLS_KEY_FILE:\$TLS_KEY_FILE\";';
    $shcmd .= 'echo \"HONOR_CIPHER_ORDER:\$HONOR_CIPHER_ORDER\";';
    $shcmd .= 'echo \"COMPRESSION:\$COMPRESSION\";';
    $shcmd .= 'echo \"DISABLE_TLS_1_2:\$DISABLE_TLS_1_2\";';
    $shcmd .= 'echo \"DISABLE_TLS_1_3:\$DISABLE_TLS_1_3\";';

    my $data = -f $conffile ? `bash -c "$shcmd"` : '';

    my $res = {};

    my $boolean_options = [
	'HONOR_CIPHER_ORDER',
	'COMPRESSION',
	'DISABLE_TLS_1_2',
	'DISABLE_TLS_1_3',
    ];

    while ($data =~ s/^(.*)\n//) {
	my ($key, $value) = split(/:/, $1, 2);
	next if !defined($value) || $value eq '';
	if ($key eq 'ALLOW_FROM' || $key eq 'DENY_FROM') {
	    my $ips = [];
	    foreach my $ip (split(/,/, $value)) {
		if ($ip eq 'all') {
		    push @$ips, Net::IP->new('0/0') || die Net::IP::Error() . "\n";
		    push @$ips, Net::IP->new('::/0') || die Net::IP::Error() . "\n";
		    next;
		}
		push @$ips, Net::IP->new(normalize_v4_in_v6($ip)) || die Net::IP::Error() . "\n";
	    }
	    $res->{$key} = $ips;
	} elsif ($key eq 'LISTEN_IP') {
	    $res->{$key} = $value;
	} elsif ($key eq 'POLICY') {
	    die "unknown policy '$value'\n" if $value !~ m/^(allow|deny)$/;
	    $res->{$key} = $value;
	} elsif ($key eq 'CIPHERS') {
	    $res->{$key} = $value;
	} elsif ($key eq 'CIPHERSUITES') {
	    $res->{$key} = $value;
	} elsif ($key eq 'DHPARAMS') {
	    $res->{$key} = $value;
	} elsif ($key eq 'TLS_KEY_FILE') {
	    $res->{$key} = $value;
	} elsif (grep { $key eq $_ } @$boolean_options) {
	    die "unknown value '$value' - use 0 or 1\n" if $value !~ m/^(0|1)$/;
	    $res->{$key} = $value;
	} else {
	    # silently skip everythin else?
	}
    }

    return $res;
}

sub normalize_v4_in_v6 {
    my ($ip_text) = @_;

    my $ip = Net::IP->new($ip_text) || die Net::IP::Error() . "\n";
    my $v4_mapped_v6_prefix = Net::IP->new('::ffff:0:0/96');
    if ($v4_mapped_v6_prefix->overlaps($ip)) {
	return Net::IP::ip_get_embedded_ipv4($ip_text);
    }
    return $ip_text;
}

1;
