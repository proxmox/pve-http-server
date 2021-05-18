package PVE::APIServer::AnyEvent;

# Note 1: interactions with Crypt::OpenSSL::RSA
#
# Some handlers (auth_handler) use Crypt::OpenSSL::RSA, which seems to
# set the openssl error variable. We need to clear that here, else
# AnyEvent::TLS aborts the connection.
# Net::SSLeay::ERR_clear_error();

use strict;
use warnings;
use Time::HiRes qw(usleep ualarm gettimeofday tv_interval);
use Socket qw(IPPROTO_TCP TCP_NODELAY SOMAXCONN);
use POSIX qw(strftime EINTR EAGAIN);
use Fcntl;
use IO::File;
use File::stat qw();
use File::Find;
use MIME::Base64;
use Digest::MD5;
use Digest::SHA;
# use AnyEvent::Strict; # only use this for debugging
use AnyEvent::Util qw(guard fh_nonblocking WSAEWOULDBLOCK WSAEINPROGRESS);
use AnyEvent::Socket;
use AnyEvent::Handle;
use Net::SSLeay;
use AnyEvent::TLS;
use AnyEvent::IO;
use AnyEvent::HTTP;
use Fcntl ();
use Compress::Zlib;
use Encode;
use PVE::SafeSyslog;
use PVE::INotify;
use PVE::Tools;
use PVE::APIServer::Formatter;
use PVE::APIServer::Utils;

use Net::IP;
use URI;
use URI::Escape;
use HTTP::Status qw(:constants);
use HTTP::Date;
use HTTP::Headers;
use HTTP::Request;
use HTTP::Response;
use Data::Dumper;
use JSON;

my $limit_max_headers = 64;
my $limit_max_header_size = 8*1024;
my $limit_max_post = 64*1024;

my $known_methods = {
    GET => 1,
    POST => 1,
    PUT => 1,
    DELETE => 1,
};

my $split_abs_uri = sub {
    my ($abs_uri, $base_uri) = @_;

    my ($format, $rel_uri) = $abs_uri =~ m/^\Q$base_uri\E\/+([a-z][a-z0-9]+)(\/.*)?$/;
    $rel_uri = '/' if !$rel_uri;

    return wantarray ? ($rel_uri, $format) : $rel_uri;
};

sub dprint {
    my ($self, $message) = @_;

    return if !$self->{debug};

    my ($pkg, $pkgfile, $line, $sub) = caller(1);
    $sub =~ s/^(?:.+::)+//;
    print "worker[$$]: $pkg +$line: $sub: $message\n";
}

sub log_request {
    my ($self, $reqstate) = @_;

    my $loginfo = $reqstate->{log};

    # like apache2 common log format
    # LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\""

    return if $loginfo->{written}; # avoid duplicate logs
    $loginfo->{written} = 1;

    my $peerip = $reqstate->{peer_host} || '-';
    my $userid = $loginfo->{userid} || '-';
    my $content_length = defined($loginfo->{content_length}) ? $loginfo->{content_length} : '-';
    my $code =  $loginfo->{code} || 500;
    my $requestline = $loginfo->{requestline} || '-';
    my $timestr = strftime("%d/%m/%Y:%H:%M:%S %z", localtime());

    my $msg = "$peerip - $userid [$timestr] \"$requestline\" $code $content_length\n";

    $self->write_log($msg);
}

sub log_aborted_request {
    my ($self, $reqstate, $error) = @_;

    my $r = $reqstate->{request};
    return if !$r; # no active request

    if ($error) {
	syslog("err", "problem with client $reqstate->{peer_host}; $error");
    }

    $self->log_request($reqstate);
}

sub cleanup_reqstate {
    my ($reqstate) = @_;

    delete $reqstate->{log};
    delete $reqstate->{request};
    delete $reqstate->{proto};
    delete $reqstate->{accept_gzip};
    delete $reqstate->{starttime};

    if ($reqstate->{tmpfilename}) {
	unlink $reqstate->{tmpfilename};
	delete $reqstate->{tmpfilename};
    }
}

sub client_do_disconnect {
    my ($self, $reqstate) = @_;

    cleanup_reqstate($reqstate);

    my $shutdown_hdl = sub {
	my $hdl = shift;

	shutdown($hdl->{fh}, 1);
	# clear all handlers
	$hdl->on_drain(undef);
	$hdl->on_read(undef);
	$hdl->on_eof(undef);
    };

    if (my $proxyhdl = delete $reqstate->{proxyhdl}) {
	&$shutdown_hdl($proxyhdl);
    }

    my $hdl = delete $reqstate->{hdl};

    if (!$hdl) {
	syslog('err', "detected empty handle");
	return;
    }

    $self->dprint("close connection $hdl");

    &$shutdown_hdl($hdl);

    warn "connection count <= 0!\n" if $self->{conn_count} <= 0;

    $self->{conn_count}--;

    $self->dprint("CLOSE FH" .  $hdl->{fh}->fileno() . " CONN$self->{conn_count}");
}

sub finish_response {
    my ($self, $reqstate) = @_;

    cleanup_reqstate($reqstate);

    my $hdl = $reqstate->{hdl};
    return if !$hdl; # already disconnected

    if (!$self->{end_loop} && $reqstate->{keep_alive} > 0) {
	# print "KEEPALIVE $reqstate->{keep_alive}\n" if $self->{debug};
	$hdl->on_read(sub {
	    eval { $self->push_request_header($reqstate); };
	    warn $@ if $@;
	});
    } else {
	$hdl->on_drain (sub {
	    eval {
		$self->client_do_disconnect($reqstate);
	    };
	    warn $@ if $@;
	});
    }
}

sub response_stream {
    my ($self, $reqstate, $stream_fh) = @_;

    # disable timeout, we don't know how big the data is
    $reqstate->{hdl}->timeout(0);

    my $buf_size = 4*1024*1024;

    my $on_read;
    $on_read = sub {
	my ($hdl) = @_;
	my $reqhdl = $reqstate->{hdl};
	return if !$reqhdl;

	my $wbuf_len = length($reqhdl->{wbuf});
	my $rbuf_len = length($hdl->{rbuf});
	# TODO: Take into account $reqhdl->{wbuf_max} ? Right now
	# that's unbounded, so just assume $buf_size
	my $to_read = $buf_size - $wbuf_len;
	$to_read = $rbuf_len if $rbuf_len < $to_read;
	if ($to_read > 0) {
	    my $data = substr($hdl->{rbuf}, 0, $to_read, '');
	    $reqhdl->push_write($data);
	    $rbuf_len -= $to_read;
	} elsif ($hdl->{_eof}) {
	    # workaround: AnyEvent gives us a fake EPIPE if we don't consume
	    # any data when called at EOF, so unregister ourselves - data is
	    # flushed by on_eof anyway
	    # see: https://sources.debian.org/src/libanyevent-perl/7.170-2/lib/AnyEvent/Handle.pm/#L1329
	    $hdl->on_read();
	    return;
	}

	# apply backpressure so we don't accept any more data into
	# buffer if the client isn't downloading fast enough
	# note: read_size can double upon read, and we also need to
	# account for one more read after start_read, so *4
	if ($rbuf_len + $hdl->{read_size}*4 > $buf_size) {
	    # stop reading until write buffer is empty
	    $hdl->on_read();
	    my $prev_on_drain = $reqhdl->{on_drain};
	    $reqhdl->on_drain(sub {
		my ($wrhdl) = @_;
		# on_drain called because write buffer is empty, continue reading
		$hdl->on_read($on_read);
		if ($prev_on_drain) {
		    $wrhdl->on_drain($prev_on_drain);
		    $prev_on_drain->($wrhdl);
		}
	    });
	}
    };

    $reqstate->{proxyhdl} = AnyEvent::Handle->new(
	fh => $stream_fh,
	rbuf_max => $buf_size,
	timeout => 0,
	on_read => $on_read,
	on_eof => sub {
	    my ($hdl) = @_;
	    eval {
		if (my $reqhdl = $reqstate->{hdl}) {
		    $self->log_aborted_request($reqstate);
		    # write out any remaining data
		    $reqhdl->push_write($hdl->{rbuf}) if length($hdl->{rbuf}) > 0;
		    $hdl->{rbuf} = "";
		    $reqhdl->push_shutdown();
		    $self->finish_response($reqstate);
		}
	    };
	    if (my $err = $@) { syslog('err', "$err"); }
	    $on_read = undef;
	},
	on_error => sub {
	    my ($hdl, $fatal, $message) = @_;
	    eval {
		$self->log_aborted_request($reqstate, $message);
		$self->client_do_disconnect($reqstate);
	    };
	    if (my $err = $@) { syslog('err', "$err"); }
	    $on_read = undef;
	},
    );
}

sub response {
    my ($self, $reqstate, $resp, $mtime, $nocomp, $delay, $stream_fh) = @_;

    #print "$$: send response: " . Dumper($resp);

    # activate timeout
    $reqstate->{hdl}->timeout_reset();
    $reqstate->{hdl}->timeout($self->{timeout});

    $nocomp = 1 if !$self->{compression};
    $nocomp = 1 if !$reqstate->{accept_gzip};

    my $code = $resp->code;
    my $msg = $resp->message || HTTP::Status::status_message($code);
    ($msg) = $msg =~m/^(.*)$/m;
    my $content = $resp->content;

    if ($code =~ /^(1\d\d|[23]04)$/) {
	# make sure content we have no content
	$content = "";
    }

    $reqstate->{keep_alive} = 0 if ($code >= 400) || $self->{end_loop};

    $reqstate->{log}->{code} = $code;

    my $proto = $reqstate->{proto} ? $reqstate->{proto}->{str} : 'HTTP/1.0';
    my $res = "$proto $code $msg\015\012";

    my $ctime = time();
    my $date = HTTP::Date::time2str($ctime);
    $resp->header('Date' => $date);
    if ($mtime) {
	$resp->header('Last-Modified' => HTTP::Date::time2str($mtime));
    } else {
	$resp->header('Expires' => $date);
	$resp->header('Cache-Control' => "max-age=0");
	$resp->header("Pragma", "no-cache");
    }

    $resp->header('Server' => "pve-api-daemon/3.0");

    my $content_length;
    if ($content && !$stream_fh) {

	$content_length = length($content);

	if (!$nocomp && ($content_length > 1024)) {
	    my $comp = Compress::Zlib::memGzip($content);
	    $resp->header('Content-Encoding', 'gzip');
	    $content = $comp;
	    $content_length = length($content);
	}
	$resp->header("Content-Length" => $content_length);
	$reqstate->{log}->{content_length} = $content_length;

    } else {
	$resp->remove_header("Content-Length");
    }

    if ($reqstate->{keep_alive} > 0) {
	$resp->push_header('Connection' => 'Keep-Alive');
    } else {
	$resp->header('Connection' => 'close');
    }

    $res .= $resp->headers_as_string("\015\012");
    #print "SEND(without content) $res\n" if $self->{debug};

    $res .= "\015\012";
    $res .= $content if $content && !$stream_fh;

    $self->log_request($reqstate, $reqstate->{request});

    if ($stream_fh) {
	# write headers and preamble...
	$reqstate->{hdl}->push_write($res);
	# ...then stream data via an AnyEvent::Handle
	$self->response_stream($reqstate, $stream_fh);
    } elsif ($delay && $delay > 0) {
	my $w; $w = AnyEvent->timer(after => $delay, cb => sub {
	    undef $w; # delete reference
	    $reqstate->{hdl}->push_write($res);
	    $self->finish_response($reqstate);
	});
    } else {
	$reqstate->{hdl}->push_write($res);
	$self->finish_response($reqstate);
    }
}

sub error {
    my ($self, $reqstate, $code, $msg, $hdr, $content) = @_;

    eval {
	my $resp = HTTP::Response->new($code, $msg, $hdr, $content);
	$self->response($reqstate, $resp);
    };
    warn $@ if $@;
}

my $file_extension_info = {
    css   => { ct => 'text/css' },
    html  => { ct => 'text/html' },
    js    => { ct => 'application/javascript' },
    json  => { ct => 'application/json' },
    map   => { ct => 'application/json' },
    png   => { ct => 'image/png' , nocomp => 1 },
    ico   => { ct => 'image/x-icon', nocomp => 1},
    gif   => { ct => 'image/gif', nocomp => 1},
    svg   => { ct => 'image/svg+xml' },
    jar   => { ct => 'application/java-archive', nocomp => 1},
    woff  => { ct => 'application/font-woff', nocomp => 1},
    woff2 => { ct => 'application/font-woff2', nocomp => 1},
    ttf   => { ct => 'application/font-snft', nocomp => 1},
    pdf   => { ct => 'application/pdf', nocomp => 1},
    epub  => { ct => 'application/epub+zip', nocomp => 1},
    mp3   => { ct => 'audio/mpeg', nocomp => 1},
    oga   => { ct => 'audio/ogg', nocomp => 1},
    tgz   => { ct => 'application/x-compressed-tar', nocomp => 1},
};

sub send_file_start {
    my ($self, $reqstate, $download) = @_;

    eval {
	# print "SEND FILE $filename\n";
	# Note: aio_load() this is not really async unless we use IO::AIO!
	eval {

	    my $r = $reqstate->{request};

	    my $fh;
	    my $nocomp;
	    my $mime;

	    if (ref($download) eq 'HASH') {
		$mime = $download->{'content-type'};

		if ($download->{path} && $download->{stream} &&
		    $reqstate->{request}->header('PVEDisableProxy'))
		{
		    # avoid double stream from a file, let the proxy handle it
		    die "internal error: file proxy streaming only available for pvedaemon\n"
			if !$self->{trusted_env};
		    my $header = HTTP::Headers->new(
			pvestreamfile => $download->{path},
			Content_Type => $mime,
		    );
		    # we need some data so Content-Length gets set correctly and
		    # the proxy doesn't wait for more data - place a canary
		    my $resp = HTTP::Response->new(200, "OK", $header, "error canary");
		    $self->response($reqstate, $resp);
		    return;
		}

		if (!($fh = $download->{fh})) {
		    my $path = $download->{path};
		    die "internal error: {download} returned but neither fh not path given\n"
			if !$path;
		    sysopen($fh, "$path", O_NONBLOCK | O_RDONLY)
			or die "open stream path '$path' for reading failed: $!\n";
		}

		if ($download->{stream}) {
		    my $header = HTTP::Headers->new(Content_Type => $mime);
		    my $resp = HTTP::Response->new(200, "OK", $header);
		    $self->response($reqstate, $resp, undef, 1, 0, $fh);
		    return;
		}
	    } else {
		my $filename = $download;
		$fh = IO::File->new($filename, '<') ||
		    die "unable to open file '$filename' - $!\n";

		my ($ext) = $filename =~ m/\.([^.]*)$/;
		my $ext_info = $file_extension_info->{$ext};

		die "unable to detect content type" if !$ext_info;
		$mime = $ext_info->{ct};
		$nocomp = $ext_info->{nocomp};
	    }

	    my $stat = File::stat::stat($fh) ||
		die "$!\n";

	    my $mtime = $stat->mtime;

	    if (my $ifmod = $r->header('if-modified-since')) {
		my $iftime = HTTP::Date::str2time($ifmod);
		if ($mtime <= $iftime) {
		    my $resp = HTTP::Response->new(304, "NOT MODIFIED");
		    $self->response($reqstate, $resp, $mtime);
		    return;
		}
	    }

	    my $data;
	    my $len = sysread($fh, $data,  $stat->size);
	    die "got short file\n" if !defined($len) || $len != $stat->size;

	    my $header = HTTP::Headers->new(Content_Type => $mime);
	    my $resp = HTTP::Response->new(200, "OK", $header, $data);
	    $self->response($reqstate, $resp, $mtime, $nocomp);
	};
	if (my $err = $@) {
	    $self->error($reqstate, 501, $err);
	}
    };

    warn $@ if $@;
}

sub websocket_proxy {
    my ($self, $reqstate, $wsaccept, $wsproto, $param) = @_;

    eval {
	my $remhost;
	my $remport;

	my $max_payload_size = 128*1024;

	if ($param->{port}) {
	    $remhost = 'localhost';
	    $remport = $param->{port};
	} elsif ($param->{socket}) {
	    $remhost = 'unix/';
	    $remport = $param->{socket};
	} else {
	    die "websocket_proxy: missing port or socket\n";
	}

	my $encode = sub {
	    my ($data, $opcode) = @_;

	    my $string;
	    my $payload;

	    $string = $opcode ? $opcode : "\x82"; # binary frame
	    $payload = $$data;

	    my $payload_len = length($payload);
	    if ($payload_len <= 125) {
		$string .= pack 'C', $payload_len;
	    } elsif ($payload_len <= 0xffff) {
		$string .= pack 'C', 126;
		$string .= pack 'n', $payload_len;
	    } else {
		$string .= pack 'C', 127;
		$string .= pack 'Q>', $payload_len;
	    }
	    $string .= $payload;
	    return $string;
	};

	tcp_connect $remhost, $remport, sub {
	    my ($fh) = @_
		or die "connect to '$remhost:$remport' failed: $!";

	    $self->dprint("CONNECTed to '$remhost:$remport'");

	    $reqstate->{proxyhdl} = AnyEvent::Handle->new(
		fh => $fh,
		rbuf_max => $max_payload_size,
		wbuf_max => $max_payload_size*5,
		timeout => 5,
		on_eof => sub {
		    my ($hdl) = @_;
		    eval {
			$self->log_aborted_request($reqstate);
			$self->client_do_disconnect($reqstate);
		    };
		    if (my $err = $@) { syslog('err', $err); }
		},
		on_error => sub {
		    my ($hdl, $fatal, $message) = @_;
		    eval {
			$self->log_aborted_request($reqstate, $message);
			$self->client_do_disconnect($reqstate);
		    };
		    if (my $err = $@) { syslog('err', "$err"); }
		});

	    my $proxyhdlreader = sub {
		my ($hdl) = @_;

		my $len = length($hdl->{rbuf});
		my $data = substr($hdl->{rbuf}, 0, $len > $max_payload_size ? $max_payload_size : $len, '');

		my $string = $encode->(\$data);

		$reqstate->{hdl}->push_write($string) if $reqstate->{hdl};
	    };

	    my $hdlreader = sub {
		my ($hdl) = @_;

		while (my $len = length($hdl->{rbuf})) {
		    return if $len < 2;

		    my $hdr = unpack('C', substr($hdl->{rbuf}, 0, 1));
		    my $opcode = $hdr & 0b00001111;
		    my $fin = $hdr & 0b10000000;

		    die "received fragmented websocket frame\n" if !$fin;

		    my $rsv = $hdr & 0b01110000;
		    die "received websocket frame with RSV flags\n" if $rsv;

		    my $payload_len = unpack 'C', substr($hdl->{rbuf}, 1, 1);

		    my $masked = $payload_len & 0b10000000;
		    die "received unmasked websocket frame from client\n" if !$masked;

		    my $offset = 2;
		    $payload_len = $payload_len & 0b01111111;
		    if ($payload_len == 126) {
			return if $len < 4;
			$payload_len = unpack('n', substr($hdl->{rbuf}, $offset, 2));
			$offset += 2;
		    } elsif ($payload_len == 127) {
			return if $len < 10;
			$payload_len = unpack('Q>', substr($hdl->{rbuf}, $offset, 8));
			$offset += 8;
		    }

		    die "received too large websocket frame (len = $payload_len)\n"
			if ($payload_len > $max_payload_size) || ($payload_len < 0);

		    return if $len < ($offset + 4 + $payload_len);

		    my $data = substr($hdl->{rbuf}, 0, $offset + 4 + $payload_len, ''); # now consume data

		    my $mask = substr($data, $offset, 4);
		    $offset += 4;

		    my $payload = substr($data, $offset, $payload_len);

		    # NULL-mask might be used over TLS, skip to increase performance
		    if ($mask ne pack('N', 0)) {
			# repeat 4 byte mask to payload length + up to 4 byte
			$mask = $mask x (int($payload_len / 4) + 1);
			# truncate mask to payload length
			substr($mask, $payload_len) = "";
			# (un-)apply mask
			$payload ^= $mask;
		    }

		    if ($opcode == 1 || $opcode == 2) {
			$reqstate->{proxyhdl}->push_write($payload) if $reqstate->{proxyhdl};
		    } elsif ($opcode == 8) {
			my $statuscode = unpack ("n", $payload);
			$self->dprint("websocket received close. status code: '$statuscode'");
			if ($reqstate->{proxyhdl}) {
			    $reqstate->{proxyhdl}->push_shutdown();
			}
			$hdl->push_shutdown();
		    } elsif ($opcode == 9) {
			# ping received, schedule pong
			$reqstate->{hdl}->push_write($encode->(\$payload, "\x8A")) if $reqstate->{hdl};
		    } elsif ($opcode == 0xA) {
			# pong received, continue
		    } else {
			die "received unhandled websocket opcode $opcode\n";
		    }
		}
	    };

	    my $proto = $reqstate->{proto} ? $reqstate->{proto}->{str} : 'HTTP/1.1';

	    $reqstate->{proxyhdl}->timeout(0);
	    $reqstate->{proxyhdl}->on_read($proxyhdlreader);
	    $reqstate->{hdl}->on_read($hdlreader);

	    # todo: use stop_read/start_read if write buffer grows to much

	    my $res = "$proto 101 Switching Protocols\015\012" .
		"Upgrade: websocket\015\012" .
		"Connection: upgrade\015\012" .
		"Sec-WebSocket-Accept: $wsaccept\015\012" .
		"Sec-WebSocket-Protocol: $wsproto\015\012" .
		"\015\012";

	    $self->dprint($res);

	    $reqstate->{hdl}->push_write($res);

	    # log early
	    $reqstate->{log}->{code} = 101;
	    $self->log_request($reqstate);
	};

    };
    if (my $err = $@) {
	warn $err;
	$self->log_aborted_request($reqstate, $err);
	$self->client_do_disconnect($reqstate);
    }
}

sub proxy_request {
    my ($self, $reqstate, $clientip, $host, $node, $method, $uri, $auth, $params) = @_;

    eval {
	my $target;
	my $keep_alive = 1;
	if ($host eq 'localhost') {
	    $target = "http://$host:85$uri";
	    # keep alive for localhost is not worth (connection setup is about 0.2ms)
	    $keep_alive = 0;
	} elsif (Net::IP::ip_is_ipv6($host)) {
	    $target = "https://[$host]:8006$uri";
	} else {
	    $target = "https://$host:8006$uri";
	}

	my $headers = {
	    PVEDisableProxy => 'true',
	    PVEClientIP => $clientip,
	};

	$headers->{'cookie'} = PVE::APIServer::Formatter::create_auth_cookie($auth->{ticket}, $self->{cookie_name})
	    if $auth->{ticket};
	$headers->{'Authorization'} = PVE::APIServer::Formatter::create_auth_header($auth->{api_token}, $self->{apitoken_name})
	    if $auth->{api_token};
	$headers->{'CSRFPreventionToken'} = $auth->{token}
	    if $auth->{token};
	$headers->{'Accept-Encoding'} = 'gzip' if ($reqstate->{accept_gzip} && $self->{compression});

	if (defined(my $host = $reqstate->{request}->header('Host'))) {
	    $headers->{Host} = $host;
	}

	my $content;

	if  ($method eq 'POST' || $method eq 'PUT') {
	    $headers->{'Content-Type'} = 'application/x-www-form-urlencoded';
	    # use URI object to format application/x-www-form-urlencoded content.
	    my $url = URI->new('http:');
	    $url->query_form(%$params);
	    $content = $url->query;
	    if (defined($content)) {
		$headers->{'Content-Length'} = length($content);
	    }
	}

	my $tls = {
	    # TLS 1.x only, with certificate pinning
	    method => 'any',
	    sslv2 => 0,
	    sslv3 => 0,
	    verify => 1,
	    verify_cb => sub {
		my (undef, undef, undef, $depth, undef, undef, $cert) = @_;
		# we don't care about intermediate or root certificates
		return 1 if $depth != 0;
		# check server certificate against cache of pinned FPs
		return $self->check_cert_fingerprint($cert);
	    },
	};

	# load and cache cert fingerprint if first time we proxy to this node
	$self->initialize_cert_cache($node);

	my $w; $w = http_request(
	    $method => $target,
	    headers => $headers,
	    timeout => 30,
	    recurse => 0,
	    proxy => undef, # avoid use of $ENV{HTTP_PROXY}
	    keepalive => $keep_alive,
	    body => $content,
	    tls_ctx => AnyEvent::TLS->new(%{$tls}),
	    sub {
		my ($body, $hdr) = @_;

		undef $w;

		if (!$reqstate->{hdl}) {
		    warn "proxy detected vanished client connection\n";
		    return;
		}

		eval {
		    my $code = delete $hdr->{Status};
		    my $msg = delete $hdr->{Reason};
		    my $stream = delete $hdr->{pvestreamfile};
		    delete $hdr->{URL};
		    delete $hdr->{HTTPVersion};
		    my $header = HTTP::Headers->new(%$hdr);
		    if (my $location = $header->header('Location')) {
			$location =~ s|^http://localhost:85||;
			$header->header(Location => $location);
		    }
		    if ($stream) {
			sysopen(my $fh, "$stream", O_NONBLOCK | O_RDONLY)
			    or die "open stream path '$stream' for forwarding failed: $!\n";
			my $resp = HTTP::Response->new($code, $msg, $header, undef);
			$self->response($reqstate, $resp, undef, 1, 0, $fh);
		    } else {
			my $resp = HTTP::Response->new($code, $msg, $header, $body);
			# Note: disable compression, because body is already compressed
			$self->response($reqstate, $resp, undef, 1);
		    }
		};
		warn $@ if $@;
	    });
    };
    warn $@ if $@;
}

# return arrays as \0 separated strings (like CGI.pm)
# assume data is UTF8 encoded
sub decode_urlencoded {
    my ($data) = @_;

    my $res = {};

    return $res if !$data;

    foreach my $kv (split(/[\&\;]/, $data)) {
	my ($k, $v) = split(/=/, $kv);
	$k =~s/\+/ /g;
	$k =~ s/%([0-9a-fA-F][0-9a-fA-F])/chr(hex($1))/eg;

	if (defined($v)) {
	    $v =~s/\+/ /g;
	    $v =~ s/%([0-9a-fA-F][0-9a-fA-F])/chr(hex($1))/eg;

	    $v = Encode::decode('utf8', $v);

	    if (defined(my $old = $res->{$k})) {
		$v = "$old\0$v";
	    }
	}

	$res->{$k} = $v;
    }
    return $res;
}

sub extract_params {
    my ($r, $method) = @_;

    my $params = {};

    if ($method eq 'PUT' || $method eq 'POST') {
	my $ct;
	if (my $ctype = $r->header('Content-Type')) {
	    $ct = parse_content_type($ctype);
	}
	if (defined($ct) && $ct eq 'application/json')  {
	    $params = decode_json($r->content);
	} else {
	    $params = decode_urlencoded($r->content);
	}
    }

    my $query_params = decode_urlencoded($r->url->query());

    foreach my $k (keys %{$query_params}) {
	$params->{$k} = $query_params->{$k};
    }

    return $params;
}

sub handle_api2_request {
    my ($self, $reqstate, $auth, $method, $path, $upload_state) = @_;

    eval {
	my $r = $reqstate->{request};

	my ($rel_uri, $format) = &$split_abs_uri($path, $self->{base_uri});

	my $formatter = PVE::APIServer::Formatter::get_formatter($format, $method, $rel_uri);

	if (!defined($formatter)) {
	    $self->error($reqstate, HTTP_NOT_IMPLEMENTED, "no formatter for uri $rel_uri, $format");
	    return;
	}

	#print Dumper($upload_state) if $upload_state;

	my $params;

	if ($upload_state) {
	    $params = $upload_state->{params};
	} else {
	    $params = extract_params($r, $method);
	}

	delete $params->{_dc}; # remove disable cache parameter

	my $clientip = $reqstate->{peer_host};

	my $res = $self->rest_handler($clientip, $method, $rel_uri, $auth, $params, $format);

	# HACK: see Note 1
	Net::SSLeay::ERR_clear_error();

	AnyEvent->now_update(); # in case somebody called sleep()

	my $upgrade = $r->header('upgrade');
	$upgrade = lc($upgrade) if $upgrade;

	if (my $host = $res->{proxy}) {

	    if ($self->{trusted_env}) {
		$self->error($reqstate, HTTP_INTERNAL_SERVER_ERROR, "proxy not allowed");
		return;
	    }

	    if ($host ne 'localhost' && $r->header('PVEDisableProxy')) {
		$self->error($reqstate, HTTP_INTERNAL_SERVER_ERROR, "proxy loop detected");
		return;
	    }

	    $res->{proxy_params}->{tmpfilename} = $reqstate->{tmpfilename} if $upload_state;

	    $self->proxy_request($reqstate, $clientip, $host, $res->{proxynode}, $method,
				 $r->uri, $auth, $res->{proxy_params});
	    return;

	} elsif ($upgrade && ($method eq 'GET') && ($path =~ m|websocket$|)) {
	    die "unable to upgrade to protocol '$upgrade'\n" if !$upgrade || ($upgrade ne 'websocket');
	    my $wsver = $r->header('sec-websocket-version');
	    die "unsupported websocket-version '$wsver'\n" if !$wsver || ($wsver ne '13');
	    my $wsproto_str = $r->header('sec-websocket-protocol');
	    die "missing websocket-protocol header" if !$wsproto_str;
	    my $wsproto;
	    foreach my $p (PVE::Tools::split_list($wsproto_str)) {
		$wsproto = $p if !$wsproto && $p eq 'base64';
		$wsproto = $p if $p eq 'binary';
	    }
	    die "unsupported websocket-protocol protocol '$wsproto_str'\n" if !$wsproto;
	    my $wskey = $r->header('sec-websocket-key');
	    die "missing websocket-key\n" if !$wskey;
	    # Note: Digest::SHA::sha1_base64 has wrong padding
	    my $wsaccept = Digest::SHA::sha1_base64("${wskey}258EAFA5-E914-47DA-95CA-C5AB0DC85B11") . "=";
	    if ($res->{status} == HTTP_OK) {
		$self->websocket_proxy($reqstate, $wsaccept, $wsproto, $res->{data});
		return;
	    }
	}

	my $delay = 0;
	if ($res->{status} == HTTP_UNAUTHORIZED) {
	    # always delay unauthorized calls by 3 seconds
	    $delay = 3 - tv_interval($reqstate->{starttime});
	    $delay = 0 if $delay < 0;
	}

	my $download = $res->{download};
	$download //= $res->{data}->{download}
            if defined($res->{data}) && ref($res->{data}) eq 'HASH';
	if (defined($download)) {
	    send_file_start($self, $reqstate, $download);
	    return;
	}

	my ($raw, $ct, $nocomp) = $formatter->($res, $res->{data}, $params, $path,
					       $auth, $self->{formatter_config});

	my $resp;
	if (ref($raw) && (ref($raw) eq 'HTTP::Response')) {
	    $resp = $raw;
	} else {
	    $resp = HTTP::Response->new($res->{status}, $res->{message});
	    $resp->header("Content-Type" => $ct);
	    $resp->content($raw);
	}
	$self->response($reqstate, $resp, undef, $nocomp, $delay);
    };
    if (my $err = $@) {
	$self->error($reqstate, 501, $err);
    }
}

sub handle_spice_proxy_request {
    my ($self, $reqstate, $connect_str, $vmid, $node, $spiceport) = @_;

    eval {

	my ($minport, $maxport) = PVE::Tools::spice_port_range();
	if ($spiceport < $minport || $spiceport > $maxport) {
	    die "SPICE Port $spiceport is not in allowed range ($minport, $maxport)\n";
	}

	my $clientip = $reqstate->{peer_host};
	my $r = $reqstate->{request};

        my $remip;

        if ($node ne 'localhost' && PVE::INotify::nodename() !~ m/^$node$/i) {
            $remip = $self->remote_node_ip($node);
	    $self->dprint("REMOTE CONNECT $vmid, $remip, $connect_str");
        } else {
	    $self->dprint("CONNECT $vmid, $node, $spiceport");
	}

	if ($remip && $r->header('PVEDisableProxy')) {
	    $self->error($reqstate, HTTP_INTERNAL_SERVER_ERROR, "proxy loop detected");
	    return;
	}

	$reqstate->{hdl}->timeout(0);
	$reqstate->{hdl}->wbuf_max(64*10*1024);

	my $remhost = $remip ? $remip : "localhost";
	my $remport = $remip ? 3128 : $spiceport;

	tcp_connect $remhost, $remport, sub {
	    my ($fh) = @_
		or die "connect to '$remhost:$remport' failed: $!";

	    $self->dprint("CONNECTed to '$remhost:$remport'");
	    $reqstate->{proxyhdl} = AnyEvent::Handle->new(
		fh => $fh,
		rbuf_max => 64*1024,
		wbuf_max => 64*10*1024,
		timeout => 5,
		on_eof => sub {
		    my ($hdl) = @_;
		    eval {
			$self->log_aborted_request($reqstate);
			$self->client_do_disconnect($reqstate);
		    };
		    if (my $err = $@) { syslog('err', $err); }
		},
		on_error => sub {
		    my ($hdl, $fatal, $message) = @_;
		    eval {
			$self->log_aborted_request($reqstate, $message);
			$self->client_do_disconnect($reqstate);
		    };
		    if (my $err = $@) { syslog('err', "$err"); }
		});


	    my $proxyhdlreader = sub {
		my ($hdl) = @_;

		my $len = length($hdl->{rbuf});
		my $data = substr($hdl->{rbuf}, 0, $len, '');

		#print "READ1 $len\n";
		$reqstate->{hdl}->push_write($data) if $reqstate->{hdl};
	    };

	    my $hdlreader = sub {
		my ($hdl) = @_;

		my $len = length($hdl->{rbuf});
		my $data = substr($hdl->{rbuf}, 0, $len, '');

		#print "READ0 $len\n";
		$reqstate->{proxyhdl}->push_write($data) if $reqstate->{proxyhdl};
	    };

	    my $proto = $reqstate->{proto} ? $reqstate->{proto}->{str} : 'HTTP/1.0';

	    my $startproxy = sub {
		$reqstate->{proxyhdl}->timeout(0);
		$reqstate->{proxyhdl}->on_read($proxyhdlreader);
		$reqstate->{hdl}->on_read($hdlreader);

		# todo: use stop_read/start_read if write buffer grows to much

		# a response must be followed by an empty line
		my $res = "$proto 200 OK\015\012\015\012";
		$reqstate->{hdl}->push_write($res);

		# log early
		$reqstate->{log}->{code} = 200;
		$self->log_request($reqstate);
	    };

	    if ($remip) {
		my $header = "CONNECT ${connect_str} $proto\015\012" .
		    "Host: ${connect_str}\015\012" .
		    "Proxy-Connection: keep-alive\015\012" .
		    "User-Agent: spiceproxy\015\012" .
		    "PVEDisableProxy: true\015\012" .
		    "PVEClientIP: $clientip\015\012" .
		    "\015\012";

		$reqstate->{proxyhdl}->push_write($header);
		$reqstate->{proxyhdl}->push_read(line => sub {
		    my ($hdl, $line) = @_;

		    if ($line =~ m!^$proto 200 OK$!) {
			# read the empty line after the 200 OK
			$reqstate->{proxyhdl}->unshift_read(line => sub{
			    &$startproxy();
			});
		    } else {
			$reqstate->{hdl}->push_write($line);
			$self->client_do_disconnect($reqstate);
		    }
                });
	    } else {
		&$startproxy();
	    }

	};
    };
    if (my $err = $@) {
	warn $err;
	$self->log_aborted_request($reqstate, $err);
	$self->client_do_disconnect($reqstate);
    }
}

sub handle_request {
    my ($self, $reqstate, $auth, $method, $path) = @_;

    my $base_uri = $self->{base_uri};

    eval {
	my $r = $reqstate->{request};

	# disable timeout on handle (we already have all data we need)
	# we re-enable timeout in response()
	$reqstate->{hdl}->timeout(0);

	if ($path =~ m/^\Q$base_uri\E/) {
	    $self->handle_api2_request($reqstate, $auth, $method, $path);
	    return;
	}

	if ($self->{pages} && ($method eq 'GET') && (my $handler = $self->{pages}->{$path})) {
	    if (ref($handler) eq 'CODE') {
		my $params = decode_urlencoded($r->url->query());
		my ($resp, $userid) = &$handler($self, $reqstate->{request}, $params);
		# HACK: see Note 1
		Net::SSLeay::ERR_clear_error();
		$self->response($reqstate, $resp);
	    } elsif (ref($handler) eq 'HASH') {
		if (my $filename = $handler->{file}) {
		    my $fh = IO::File->new($filename) ||
			die "unable to open file '$filename' - $!\n";
		    send_file_start($self, $reqstate, $filename);
		} else {
		    die "internal error - no handler";
		}
	    } else {
		die "internal error - no handler";
	    }
	    return;
	}

	if ($self->{dirs} && ($method eq 'GET')) {
	    # we only allow simple names
	    if ($path =~ m!^(/\S+/)([a-zA-Z0-9\-\_\.]+)$!) {
		my ($subdir, $file) = ($1, $2);
		if (my $dir = $self->{dirs}->{$subdir}) {
		    my $filename = "$dir$file";
		    my $fh = IO::File->new($filename) ||
			die "unable to open file '$filename' - $!\n";
		    send_file_start($self, $reqstate, $filename);
		    return;
		}
	    }
	}

	die "no such file '$path'\n";
    };
    if (my $err = $@) {
	$self->error($reqstate, 501, $err);
    }
}

sub file_upload_multipart {
    my ($self, $reqstate, $auth, $method, $path, $rstate) = @_;

    eval {
	my $boundary = $rstate->{boundary};
	my $hdl = $reqstate->{hdl};

	my $startlen = length($hdl->{rbuf});

	if ($rstate->{phase} == 0) { # skip everything until start
	    if ($hdl->{rbuf} =~ s/^.*?--\Q$boundary\E  \015?\012
                       ((?:[^\015]+\015\012)* ) \015?\012//xs) {
		my $header = $1;
		my ($ct, $disp, $name, $filename);
		foreach my $line (split(/\015?\012/, $header)) {
		    # assume we have single line headers
		    if ($line =~ m/^Content-Type\s*:\s*(.*)/i) {
			$ct = parse_content_type($1);
		    } elsif ($line =~ m/^Content-Disposition\s*:\s*(.*)/i) {
			($disp, $name, $filename) = parse_content_disposition($1);
		    }
		}

		if (!($disp && $disp eq 'form-data' && $name)) {
		    syslog('err', "wrong content disposition in multipart - abort upload");
		    $rstate->{phase} = -1;
		} else {

		    $rstate->{fieldname} = $name;

		    if ($filename) {
			if ($name eq 'filename') {
			    # found file upload data
			    $rstate->{phase} = 1;
			    $rstate->{filename} = $filename;
			} else {
			    syslog('err', "wrong field name for file upload - abort upload");
			    $rstate->{phase} = -1;
			}
		    } else {
			# found form data for field $name
			$rstate->{phase} = 2;
		    }
		}
	    } else {
		my $len = length($hdl->{rbuf});
		substr($hdl->{rbuf}, 0, $len - $rstate->{maxheader}, '')
		    if $len > $rstate->{maxheader}; # skip garbage
	    }
	} elsif ($rstate->{phase} == 1) { # inside file - dump until end marker
	    if ($hdl->{rbuf} =~ s/^(.*?)\015?\012(--\Q$boundary\E(--)? \015?\012(.*))$/$2/xs) {
		my ($rest, $eof) = ($1, $3);
		my $len = length($rest);
		die "write to temporary file failed - $!"
		    if syswrite($rstate->{outfh}, $rest) != $len;
		$rstate->{ctx}->add($rest);
		$rstate->{params}->{filename} = $rstate->{filename};
		$rstate->{md5sum} = $rstate->{ctx}->hexdigest;
		$rstate->{bytes} += $len;
		$rstate->{phase} =  $eof ? 100 : 0;
	    } else {
		my $len = length($hdl->{rbuf});
		my $wlen = $len - $rstate->{boundlen};
		if ($wlen > 0) {
		    my $data = substr($hdl->{rbuf}, 0, $wlen, '');
		    die "write to temporary file failed - $!"
			if syswrite($rstate->{outfh}, $data) != $wlen;
		    $rstate->{bytes} += $wlen;
		    $rstate->{ctx}->add($data);
		}
	    }
	} elsif ($rstate->{phase} == 2) { # inside normal field

	    if ($hdl->{rbuf} =~ s/^(.*?)\015?\012(--\Q$boundary\E(--)? \015?\012(.*))$/$2/xs) {
		my ($rest, $eof) = ($1, $3);
		my $len = length($rest);
		$rstate->{post_size} += $len;
		if ($rstate->{post_size} < $limit_max_post) {
		    $rstate->{params}->{$rstate->{fieldname}} = $rest;
		    $rstate->{phase} = $eof ? 100 : 0;
		} else {
		    syslog('err', "form data to large - abort upload");
		    $rstate->{phase} = -1; # skip
		}
	    }
	} else { # skip
	    my $len = length($hdl->{rbuf});
	    substr($hdl->{rbuf}, 0, $len, ''); # empty rbuf
	}

	$rstate->{read} += ($startlen - length($hdl->{rbuf}));

	if (!$rstate->{done} && ($rstate->{read} + length($hdl->{rbuf})) >= $rstate->{size}) {
	    $rstate->{done} = 1; # make sure we dont get called twice
	    if ($rstate->{phase} < 0 || !$rstate->{md5sum}) {
		die "upload failed\n";
	    } else {
		my $elapsed = tv_interval($rstate->{starttime});

		my $rate = int($rstate->{bytes}/($elapsed*1024*1024));
		syslog('info', "multipart upload complete " .
		       "(size: %d time: %ds rate: %.2fMiB/s md5sum: $rstate->{md5sum})",
		       $rstate->{bytes}, $elapsed, $rate);
		$self->handle_api2_request($reqstate, $auth, $method, $path, $rstate);
	    }
	}
    };
    if (my $err = $@) {
	syslog('err', $err);
	$self->error($reqstate, 501, $err);
    }
}

sub parse_content_type {
    my ($ctype) = @_;

    my ($ct, @params) = split(/\s*[;,]\s*/o, $ctype);

    foreach my $v (@params) {
	if ($v =~ m/^\s*boundary\s*=\s*(\S+?)\s*$/o) {
	    return wantarray ? ($ct, $1) : $ct;
	}
    }

    return  wantarray ? ($ct) : $ct;
}

sub parse_content_disposition {
    my ($line) = @_;

    my ($disp, @params) = split(/\s*[;,]\s*/o, $line);
    my $name;
    my $filename;

    foreach my $v (@params) {
	if ($v =~ m/^\s*name\s*=\s*(\S+?)\s*$/o) {
	    $name = $1;
	    $name =~ s/^"(.*)"$/$1/;
	} elsif ($v =~ m/^\s*filename\s*=\s*(.+?)\s*$/o) {
	    $filename = $1;
	    $filename =~ s/^"(.*)"$/$1/;
	}
    }

    return  wantarray ? ($disp, $name, $filename) : $disp;
}

my $tmpfile_seq_no = 0;

sub get_upload_filename {
    # choose unpredictable tmpfile name

    $tmpfile_seq_no++;
    return "/var/tmp/pveupload-" . Digest::MD5::md5_hex($tmpfile_seq_no . time() . $$);
}

sub unshift_read_header {
    my ($self, $reqstate, $state) = @_;

    $state = { size => 0, count => 0 } if !$state;

    $reqstate->{hdl}->unshift_read(line => sub {
	my ($hdl, $line) = @_;

	eval {
	    # print "$$: got header: $line\n" if $self->{debug};

	    die "too many http header lines (> $limit_max_headers)\n" if ++$state->{count} >= $limit_max_headers;
	    die "http header too large\n" if ($state->{size} += length($line)) >= $limit_max_header_size;

	    my $r = $reqstate->{request};
	    if ($line eq '') {

		my $path = uri_unescape($r->uri->path());
		my $method = $r->method();

		$r->push_header($state->{key}, $state->{val})
		    if $state->{key};

		if (!$known_methods->{$method}) {
		    my $resp = HTTP::Response->new(HTTP_NOT_IMPLEMENTED, "method '$method' not available");
		    $self->response($reqstate, $resp);
		    return;
		}

		my $conn = $r->header('Connection');
		my $accept_enc = $r->header('Accept-Encoding');
		$reqstate->{accept_gzip} = ($accept_enc && $accept_enc =~ m/gzip/) ? 1 : 0;

		if ($conn) {
		    $reqstate->{keep_alive} = 0 if $conn =~ m/close/oi;
		} else {
		    if ($reqstate->{proto}->{ver} < 1001) {
			$reqstate->{keep_alive} = 0;
		    }
		}

		my $te  = $r->header('Transfer-Encoding');
		if ($te && lc($te) eq 'chunked') {
		    # Handle chunked transfer encoding
		    $self->error($reqstate, 501, "chunked transfer encoding not supported");
		    return;
		} elsif ($te) {
		    $self->error($reqstate, 501, "Unknown transfer encoding '$te'");
		    return;
		}

		my $pveclientip = $r->header('PVEClientIP');
		my $base_uri = $self->{base_uri};

		# fixme: how can we make PVEClientIP header trusted?
		if ($self->{trusted_env} && $pveclientip) {
		    $reqstate->{peer_host} = $pveclientip;
		} else {
		    $r->header('PVEClientIP', $reqstate->{peer_host});
		}

		my $len = $r->header('Content-Length');

		my $host_header = $r->header('Host');
		if (my $rpcenv = $self->{rpcenv}) {
		    $rpcenv->set_request_host($host_header);
		}

		# header processing complete - authenticate now

		my $auth = {};
		if ($self->{spiceproxy}) {
		    my $connect_str = $host_header;
		    my ($vmid, $node, $port) = $self->verify_spice_connect_url($connect_str);
		    if (!(defined($vmid) && $node && $port)) {
			$self->error($reqstate, HTTP_UNAUTHORIZED, "invalid ticket");
			return;
		    }
		    $self->handle_spice_proxy_request($reqstate, $connect_str, $vmid, $node, $port);
		    return;
		} elsif ($path =~ m/^\Q$base_uri\E/) {
		    my $token = $r->header('CSRFPreventionToken');
		    my $cookie = $r->header('Cookie');
		    my $auth_header = $r->header('Authorization');

		    # prefer actual cookie
		    my $ticket = PVE::APIServer::Formatter::extract_auth_value($cookie, $self->{cookie_name});

		    # fallback to cookie in 'Authorization' header
		    $ticket = PVE::APIServer::Formatter::extract_auth_value($auth_header, $self->{cookie_name})
			if !$ticket;

		    # finally, fallback to API token if no ticket has been provided so far
		    my $api_token;
		    $api_token = PVE::APIServer::Formatter::extract_auth_value($auth_header, $self->{apitoken_name})
			if !$ticket;

		    my ($rel_uri, $format) = &$split_abs_uri($path, $self->{base_uri});
		    if (!$format) {
			$self->error($reqstate, HTTP_NOT_IMPLEMENTED, "no such uri");
			return;
		    }

		    eval {
			$auth = $self->auth_handler($method, $rel_uri, $ticket, $token, $api_token,
						    $reqstate->{peer_host});
		    };
		    if (my $err = $@) {
			# HACK: see Note 1
			Net::SSLeay::ERR_clear_error();
			# always delay unauthorized calls by 3 seconds
			my $delay = 3;

			if (ref($err) eq "PVE::Exception") {

			    $err->{code} ||= HTTP_INTERNAL_SERVER_ERROR,
			    my $resp = HTTP::Response->new($err->{code}, $err->{msg});
			    $self->response($reqstate, $resp, undef, 0, $delay);

			} elsif (my $formatter = PVE::APIServer::Formatter::get_login_formatter($format)) {
			    my ($raw, $ct, $nocomp) =
				$formatter->($path, $auth, $self->{formatter_config});
			    my $resp;
			    if (ref($raw) && (ref($raw) eq 'HTTP::Response')) {
				$resp = $raw;
			    } else {
				$resp = HTTP::Response->new(HTTP_UNAUTHORIZED, "Login Required");
				$resp->header("Content-Type" => $ct);
				$resp->content($raw);
			    }
			    $self->response($reqstate, $resp, undef, $nocomp, $delay);
			} else {
			    my $resp = HTTP::Response->new(HTTP_UNAUTHORIZED, $err);
			    $self->response($reqstate, $resp, undef, 0, $delay);
			}
			return;
		    }
		}

		$reqstate->{log}->{userid} = $auth->{userid};

		if ($len) {

		    if (!($method eq 'PUT' || $method eq 'POST')) {
			$self->error($reqstate, 501, "Unexpected content for method '$method'");
			return;
		    }

		    my $ctype = $r->header('Content-Type');
		    my ($ct, $boundary);
		    ($ct, $boundary)= parse_content_type($ctype) if $ctype;

		    if ($auth->{isUpload} && !$self->{trusted_env}) {
			die "upload 'Content-Type '$ctype' not implemented\n"
			    if !($boundary && $ct && ($ct eq 'multipart/form-data'));

			die "upload without content length header not supported" if !$len;

			die "upload without content length header not supported" if !$len;

			$self->dprint("start upload $path $ct $boundary");

			my $tmpfilename = get_upload_filename();
			my $outfh = IO::File->new($tmpfilename, O_RDWR|O_CREAT|O_EXCL, 0600) ||
			    die "unable to create temporary upload file '$tmpfilename'";

			$reqstate->{keep_alive} = 0;

			my $boundlen = length($boundary) + 8; # \015?\012--$boundary--\015?\012

			my $state = {
			    size => $len,
			    boundary => $boundary,
			    ctx => Digest::MD5->new,
			    boundlen =>  $boundlen,
			    maxheader => 2048 + $boundlen, # should be large enough
			    params => decode_urlencoded($r->url->query()),
			    phase => 0,
			    read => 0,
			    post_size => 0,
			    starttime => [gettimeofday],
			    outfh => $outfh,
			};
			$reqstate->{tmpfilename} = $tmpfilename;
			$reqstate->{hdl}->on_read(sub { $self->file_upload_multipart($reqstate, $auth, $method, $path, $state); });
			return;
		    }

		    if ($len > $limit_max_post) {
			$self->error($reqstate, 501, "for data too large");
			return;
		    }

		    if (!$ct || $ct eq 'application/x-www-form-urlencoded' || $ct eq 'application/json') {
			$reqstate->{hdl}->unshift_read(chunk => $len, sub {
			    my ($hdl, $data) = @_;
			    $r->content($data);
			    $self->handle_request($reqstate, $auth, $method, $path);
		        });
		    } else {
			$self->error($reqstate, 506, "upload 'Content-Type '$ctype' not implemented");
		    }
		} else {
		    $self->handle_request($reqstate, $auth, $method, $path);
		}
	    } elsif ($line =~ /^([^:\s]+)\s*:\s*(.*)/) {
		$r->push_header($state->{key}, $state->{val}) if $state->{key};
		($state->{key}, $state->{val}) = ($1, $2);
		$self->unshift_read_header($reqstate, $state);
	    } elsif ($line =~ /^\s+(.*)/) {
		$state->{val} .= " $1";
		$self->unshift_read_header($reqstate, $state);
	    } else {
		$self->error($reqstate, 506, "unable to parse request header");
	    }
	};
	warn $@ if $@;
    });
};

sub push_request_header {
    my ($self, $reqstate) = @_;

    eval {
	$reqstate->{hdl}->push_read(line => sub {
	    my ($hdl, $line) = @_;

	    eval {
		# print "got request header: $line\n" if $self->{debug};

		$reqstate->{keep_alive}--;

		if ($line =~ /(\S+)\040(\S+)\040HTTP\/(\d+)\.(\d+)/o) {
		    my ($method, $url, $maj, $min) = ($1, $2, $3, $4);

		    if ($maj != 1) {
			$self->error($reqstate, 506, "http protocol version $maj.$min not supported");
			return;
		    }

		    $self->{request_count}++; # only count valid request headers
		    if ($self->{request_count} >= $self->{max_requests}) {
			$self->{end_loop} = 1;
		    }
		    $reqstate->{log} = { requestline => $line };
		    $reqstate->{proto}->{str} = "HTTP/$maj.$min";
		    $reqstate->{proto}->{maj} = $maj;
		    $reqstate->{proto}->{min} = $min;
		    $reqstate->{proto}->{ver} = $maj*1000+$min;
		    $reqstate->{request} = HTTP::Request->new($method, $url);
		    $reqstate->{starttime} = [gettimeofday],

		    $self->unshift_read_header($reqstate);
		} elsif ($line eq '') {
		    # ignore empty lines before requests (browser bugs?)
		    $self->push_request_header($reqstate);
		} else {
		    $self->error($reqstate, 400, 'bad request');
		}
	    };
	    warn $@ if $@;
	});
    };
    warn $@ if $@;
}

sub accept {
    my ($self) = @_;

    my $clientfh;

    return if $self->{end_loop};

    # we need to m make sure that only one process calls accept
    while (!flock($self->{lockfh}, Fcntl::LOCK_EX())) {
	next if $! == EINTR;
	die "could not get lock on file '$self->{lockfile}' -  $!\n";
    }

    my $again = 0;
    my $errmsg;
    eval {
	while (!$self->{end_loop} &&
	       !defined($clientfh = $self->{socket}->accept()) &&
	       ($! == EINTR)) {};

	if ($self->{end_loop}) {
	    $again = 0;
	} else {
	    $again = ($! == EAGAIN || $! == WSAEWOULDBLOCK);
	    if (!defined($clientfh)) {
		$errmsg = "failed to accept connection: $!\n";
	    }
	}
    };
    warn $@ if $@;

    flock($self->{lockfh}, Fcntl::LOCK_UN());

    if (!defined($clientfh)) {
	return if $again;
	die $errmsg if $errmsg;
    }

    fh_nonblocking $clientfh, 1;

    return $clientfh;
}

sub wait_end_loop {
    my ($self) = @_;

    $self->{end_loop} = 1;

    undef $self->{socket_watch};

    $0 = "$0 (shutdown)" if $0 !~ m/\(shutdown\)$/;

    if ($self->{conn_count} <= 0) {
	$self->{end_cond}->send(1);
	return;
    }

    # fork and exit, so that parent starts a new worker
    if (fork()) {
	exit(0);
    }

    # else we need to wait until all open connections gets closed
    my $w; $w = AnyEvent->timer (after => 1, interval => 1, cb => sub {
	eval {
	    # todo: test for active connections instead (we can abort idle connections)
	    if ($self->{conn_count} <= 0) {
		undef $w;
		$self->{end_cond}->send(1);
	    }
	};
	warn $@ if $@;
    });
}


sub check_host_access {
    my ($self, $clientip) = @_;

    $clientip = PVE::APIServer::Utils::normalize_v4_in_v6($clientip);
    my $cip = Net::IP->new($clientip);

    if (!$cip) {
	$self->dprint("client IP not parsable: $@");
	return 0;
    }

    my $match_allow = 0;
    my $match_deny = 0;

    if ($self->{allow_from}) {
	foreach my $t (@{$self->{allow_from}}) {
	    if ($t->overlaps($cip)) {
		$match_allow = 1;
		$self->dprint("client IP allowed: ". $t->prefix());
		last;
	    }
	}
    }

    if ($self->{deny_from}) {
	foreach my $t (@{$self->{deny_from}}) {
	    if ($t->overlaps($cip)) {
		$self->dprint("client IP denied: ". $t->prefix());
		$match_deny = 1;
		last;
	    }
	}
    }

    if ($match_allow == $match_deny) {
	# match both allow and deny, or no match
	return $self->{policy} && $self->{policy} eq 'allow' ? 1 : 0;
    }

    return $match_allow;
}

sub accept_connections {
    my ($self) = @_;

    my ($clientfh, $handle_creation);
    eval {

	while ($clientfh = $self->accept()) {

	    my $reqstate = { keep_alive => $self->{keep_alive} };

	    # stop keep-alive when there are many open connections
	    if ($self->{conn_count} + 1 >= $self->{max_conn_soft_limit}) {
		$reqstate->{keep_alive} = 0;
	    }

	    if (my $sin = getpeername($clientfh)) {
		my ($pfamily, $pport, $phost) = PVE::Tools::unpack_sockaddr_in46($sin);
		($reqstate->{peer_port}, $reqstate->{peer_host}) = ($pport,  Socket::inet_ntop($pfamily, $phost));
	    } else {
		$self->dprint("getpeername failed: $!");
		close($clientfh);
		next;
	    }

	    if (!$self->{trusted_env} && !$self->check_host_access($reqstate->{peer_host})) {
		$self->dprint("ABORT request from $reqstate->{peer_host} - access denied");
		$reqstate->{log}->{code} = 403;
		$self->log_request($reqstate);
		close($clientfh);
		next;
	    }

	    # Increment conn_count before creating new handle, since creation
	    # triggers callbacks, which can potentialy decrement (e.g.
	    # on_error) conn_count before AnyEvent::Handle->new() returns.
	    $handle_creation = 1;
	    $self->{conn_count}++;
	    $reqstate->{hdl} = AnyEvent::Handle->new(
		fh => $clientfh,
		rbuf_max => 64*1024,
		timeout => $self->{timeout},
		linger => 0, # avoid problems with ssh - really needed ?
		on_eof   => sub {
		    my ($hdl) = @_;
		    eval {
			$self->log_aborted_request($reqstate);
			$self->client_do_disconnect($reqstate);
		    };
		    if (my $err = $@) { syslog('err', $err); }
		},
		on_error => sub {
		    my ($hdl, $fatal, $message) = @_;
		    eval {
			$self->log_aborted_request($reqstate, $message);
			$self->client_do_disconnect($reqstate);
		    };
		    if (my $err = $@) { syslog('err', "$err"); }
		},
		($self->{tls_ctx} ? (tls => "accept", tls_ctx => $self->{tls_ctx}) : ()));
	    $handle_creation = 0;

	    $self->dprint("ACCEPT FH" .  $clientfh->fileno() . " CONN$self->{conn_count}");

	    $self->push_request_header($reqstate);
	}
    };

    if (my $err = $@) {
	syslog('err', $err);
	$self->dprint("connection accept error: $err");
	close($clientfh);
	if ($handle_creation) {
	    if ($self->{conn_count} <= 0) {
		warn "connection count <= 0 not decrementing!\n";
	    } else {
		$self->{conn_count}--;
	    }
	}
	$self->{end_loop} = 1;
    }

    $self->wait_end_loop() if $self->{end_loop};
}

# Note: We can't open log file in non-blocking mode and use AnyEvent::Handle,
# because we write from multiple processes, and that would arbitrarily mix output
# of all processes.
sub open_access_log {
    my ($self, $filename) = @_;

    my $old_mask = umask(0137);;
    my $logfh = IO::File->new($filename, ">>") ||
	die "unable to open log file '$filename' - $!\n";
    umask($old_mask);

    $logfh->autoflush(1);

    $self->{logfh} = $logfh;
}

sub write_log {
    my ($self, $data) = @_;

    return if !defined($self->{logfh}) || !$data;

    my $res = $self->{logfh}->print($data);

    if (!$res) {
	delete $self->{logfh};
	syslog('err', "error writing access log");
	$self->{end_loop} = 1; # terminate asap
    }
}

sub atfork_handler {
    my ($self) = @_;

    eval {
	# something else do to ?
	close($self->{socket});
    };
    warn $@ if $@;
}

sub run {
    my ($self) = @_;

    $self->{end_cond}->recv;
}

sub new {
    my ($this, %args) = @_;

    my $class = ref($this) || $this;

    foreach my $req (qw(socket lockfh lockfile)) {
	die "misssing required argument '$req'" if !defined($args{$req});
    }

    my $self = bless { %args }, $class;

    $self->{cookie_name} //= 'PVEAuthCookie';
    $self->{apitoken_name} //= 'PVEAPIToken';
    $self->{base_uri} //= "/api2";
    $self->{dirs} //= {};
    $self->{title} //= 'API Inspector';
    $self->{compression} //= 1;

    # formatter_config: we pass some configuration values to the Formatter
    $self->{formatter_config} = {};
    foreach my $p (qw(apitoken_name cookie_name base_uri title)) {
	$self->{formatter_config}->{$p} = $self->{$p};
    }
    $self->{formatter_config}->{csrfgen_func} =
	$self->can('generate_csrf_prevention_token');

    # add default dirs which includes jquery and bootstrap
    my $jsbase = '/usr/share/javascript';
    add_dirs($self->{dirs}, '/js/' => "$jsbase/");
    # libjs-bootstrap uses symlinks for this, which we do not want to allow..
    my $glyphicons = '/usr/share/fonts/truetype/glyphicons/';
    add_dirs($self->{dirs}, '/js/bootstrap/fonts/' => "$glyphicons");

    # init inotify
    PVE::INotify::inotify_init();

    fh_nonblocking($self->{socket}, 1);

    $self->{end_loop} = 0;
    $self->{conn_count} = 0;
    $self->{request_count} = 0;
    $self->{timeout} = 5 if !$self->{timeout};
    $self->{keep_alive} = 0 if !defined($self->{keep_alive});
    $self->{max_conn} = 800 if !$self->{max_conn};
    $self->{max_requests} = 8000 if !$self->{max_requests};

    $self->{policy} = 'allow' if !$self->{policy};

    $self->{end_cond} = AnyEvent->condvar;

    if ($self->{ssl}) {
	my $ssl_defaults = {
	    # Note: older versions are considered insecure, for example
	    # search for "Poodle"-Attack
	    method => 'any',
	    sslv2 => 0,
	    sslv3 => 0,
	    cipher_list => 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256',
	    honor_cipher_order => 1,
	};

	foreach my $k (keys %$ssl_defaults) {
	    $self->{ssl}->{$k} //= $ssl_defaults->{$k};
	}

	if (!defined($self->{ssl}->{dh_file})) {
	    $self->{ssl}->{dh} = 'skip2048';
	}

	my $tls_ctx_flags = &Net::SSLeay::OP_NO_COMPRESSION | &Net::SSLeay::OP_SINGLE_ECDH_USE | &Net::SSLeay::OP_SINGLE_DH_USE;
	if ( delete $self->{ssl}->{honor_cipher_order} ) {
	    $tls_ctx_flags |= &Net::SSLeay::OP_CIPHER_SERVER_PREFERENCE;
	}

	$self->{tls_ctx} = AnyEvent::TLS->new(%{$self->{ssl}});
	Net::SSLeay::CTX_set_options($self->{tls_ctx}->{ctx}, $tls_ctx_flags);
    }

    if ($self->{spiceproxy}) {
	$known_methods = { CONNECT => 1 };
    }

    $self->open_access_log($self->{logfile}) if $self->{logfile};

    $self->{max_conn_soft_limit} = $self->{max_conn} > 100 ? $self->{max_conn} - 20 : $self->{max_conn};

    $self->{socket_watch} = AnyEvent->io(fh => $self->{socket}, poll => 'r', cb => sub {
	eval {
	    if ($self->{conn_count} >= $self->{max_conn}) {
		my $w; $w = AnyEvent->timer (after => 1, interval => 1, cb => sub {
		    if ($self->{conn_count} < $self->{max_conn}) {
			undef $w;
			$self->accept_connections();
		    }
		});
	    } else {
		$self->accept_connections();
	    }
	};
	warn $@ if $@;
    });

    $self->{term_watch} = AnyEvent->signal(signal => "TERM", cb => sub {
	undef $self->{term_watch};
	$self->wait_end_loop();
    });

    $self->{quit_watch} = AnyEvent->signal(signal => "QUIT", cb => sub {
	undef $self->{quit_watch};
	$self->wait_end_loop();
    });

    $self->{inotify_poll} = AnyEvent->timer(after => 5, interval => 5, cb => sub {
	PVE::INotify::poll(); # read inotify events
    });

    return $self;
}

# static helper to add directory including all subdirs
# This can be used to setup $self->{dirs}
sub add_dirs {
    my ($result_hash, $alias, $subdir) = @_;

    $result_hash->{$alias} = $subdir;

    my $wanted = sub {
	my $dir = $File::Find::dir;
	if ($dir =~m!^$subdir(.*)$!) {
	    my $name = "$alias$1/";
	    $result_hash->{$name} = "$dir/";
	}
    };

    find({wanted => $wanted, follow => 0, no_chdir => 1}, $subdir);
}

# abstract functions - subclass should overwrite/implement them

sub verify_spice_connect_url {
    my ($self, $connect_str) = @_;

    die "implement me";

    #return ($vmid, $node, $port);
}

# formatters can call this when the generate a new page
sub generate_csrf_prevention_token {
    my ($username) = @_;

    return undef; # do nothing by default
}

sub auth_handler {
    my ($self, $method, $rel_uri, $ticket, $token, $api_token, $peer_host) = @_;

    die "implement me";

    # return {
    #    ticket => $ticket,
    #    token => $token,
    #    userid => $username,
    #    age => $age,
    #    isUpload => $isUpload,
    #    api_token => $api_token,
    #};
}

sub rest_handler {
    my ($self, $clientip, $method, $rel_uri, $auth, $params, $format) = @_;

    # please do not raise exceptions here (always return a result).

    return {
	status => HTTP_NOT_IMPLEMENTED,
	message => "Method '$method $rel_uri' not implemented",
    };

    # this should return the following properties, which
    # are then passed to the Formatter

    # status: HTTP status code
    # message: Error message
    # errors: more detailed error hash (per parameter)
    # info: reference to JSON schema definition - useful to format output
    # data: result data

    # total: additional info passed to output
    # changes:  additional info passed to output

    # if you want to proxy the request to another node return this
    # { proxy => $remip, proxynode => $node, proxy_params => $params };

    # to pass the request to the local priviledged daemon use:
    # { proxy => 'localhost' , proxy_params => $params };

    # to download aspecific file use:
    # { download => "/path/to/file" };
}

sub check_cert_fingerprint {
    my ($self, $cert) = @_;

     die "implement me";
 }

sub initialize_cert_cache {
    my ($self, $node) = @_;

    die "implement me";
}

sub remote_node_ip {
    my ($self, $node) = @_;

    die "implement me";

    # return $remip;
}


1;
