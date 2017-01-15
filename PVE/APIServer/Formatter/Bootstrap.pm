package PVE::APIServer::Formatter::Bootstrap;

use strict;
use warnings;
use URI::Escape;
use HTML::Entities;
use JSON;

# FIXME: remove console code??

# Helpers to generate simple html pages using Bootstrap markup.

my $jssrc = <<_EOJS;
PVE.open_vm_console = function(node, vmid) {
    console.log("open vm " + vmid + " on node " + node);

    var downloadWithName = function(uri, name) {
	var link =  jQuery('#pve_console_anchor');
	link.attr("href", uri);

	// Note: we need to tell android the correct file name extension
	// but we do not set 'download' tag for other environments, because
	// It can have strange side effects (additional user prompt on firefox)
	var andriod = navigator.userAgent.match(/Android/i) ? true : false;
	if (andriod) {
	    link.attr("download", name);
	}

	if (document.createEvent) {
	    var evt = document.createEvent("MouseEvents");
	    evt.initMouseEvent('click', true, true, window, 1, 0, 0, 0, 0, false, false, false, false, 0, null);
	    link.get(0).dispatchEvent(evt);
	} else {
	    link.get(0).fireEvent('onclick');
	}
    };

    jQuery.ajax("/api2/json/console", {
      data: { vmid: vmid, node: node },
      headers: { CSRFPreventionToken: PVE.CSRFPreventionToken },
      dataType: 'json',
      type: 'POST',
      error: function(jqXHR, textStatus, errorThrown) {
	  // fixme: howto view JS errors ?
	  console.log("ERROR " +  textStatus + ": " + errorThrown);
      },
      success:   function(data) {
	  var raw = "[virt-viewer]\\n";
	  jQuery.each(data.data, function(k, v) {
	      raw += k + "=" + v + "\\n";
	  });
	  var url = 'data:application/x-virt-viewer;charset=UTF-8,' +
	      encodeURIComponent(raw);

	  downloadWithName(url, "pve-spice.vv");
      }
    });
};
_EOJS

sub new {
    my ($class, $res, $url, $auth, $config) = @_;

    my $self = bless {
	url => $url,
	title => $config->{title},
	cookie_name => $config->{cookie_name},
	js => '',
    };

    if (my $username = $auth->{userid}) {
	$self->{csrftoken} = $config->{csrfgen_func}->($username);
    }

    return $self;
}

sub body {
    my ($self, $html) = @_;

    my $jssetup = "PVE = {};\n\n"; # create namespace

    if ($self->{csrftoken}) {
	$jssetup .= "PVE.CSRFPreventionToken = '$self->{csrftoken}';\n";
    }

    $jssetup .= "PVE.delete_auth_cookie = function() {\n";

    if ($self->{cookie_name}) {
	$jssetup .= "  document.cookie = \"$self->{cookie_name}=; expires=Thu, 01 Jan 1970 00:00:01 GMT; path=/; secure;\";\n";
    };
    $jssetup .= "};\n";

    return <<_EOD;
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>$self->{title}</title>

    <!-- Bootstrap -->
    <link href="/css/bootstrap.min.css" rel="stylesheet">

<script type="text/javascript">
$jssetup
$jssrc
</script>

    <style>
body {
	padding-top: 70px;
}
    </style>

    <!-- jQuery (necessary for Bootstrap's JavaScript plugins) -->
    <script src="/js/jquery-3.3.1.min.js"></script>
    <!-- Include all compiled plugins (below), or include individual files as needed -->
    <script src="/js/bootstrap.min.js"></script>

  </head>
  <body>
    <a class="hidden" id="pve_console_anchor"></a>
    $html
    <script type="text/javascript">
      $self->{js}
    </script>
  </body>
</html>
_EOD
}

my $comp_id_counter = 0;

sub el {
    my ($self, %param) = @_;

    $param{tag} = 'div' if !$param{tag};

    my $id;

    my $html = "<$param{tag}";

    if (wantarray) {
	$comp_id_counter++;
	$id = "pveid$comp_id_counter";
	$html .= " id=$id";
    }

    my $skip = {
	tag => 1,
	cn => 1,
	html => 1,
	text => 1,
    };

    my $boolattr = {
	required => 1,
	autofocus => 1,
    };

    my $noescape = {
	placeholder => 1,
    };

    foreach my $attr (keys %param)  {
	next if $skip->{$attr};
	my $v = $noescape->{$attr} ? $param{$attr} : uri_escape_utf8($param{$attr},"[^\/\ A-Za-z0-9\-\._~]");
	next if !defined($v);
	if ($boolattr->{$attr}) {
	    $html .= " $attr" if $v;
	} else {
	    $html .= " $attr=\"$v\"";
	}
    }

    $html .= ">";


    if (my $cn = $param{cn}) {
	if(ref($cn) eq 'ARRAY'){
	    foreach my $rec (@$cn) {
		$html .= $self->el(%$rec);
	    }
	} else {
	    $html .= $self->el(%$cn);
	}
    } elsif ($param{html}) {
	$html .= $param{html};
    } elsif ($param{text}) {
	$html .= encode_entities($param{text});
    }

    $html .= "</$param{tag}>";

    return wantarray ? ($html, $id) : $html;
}

sub alert {
    my ($self, %param) = @_;

    return $self->el(class => "alert alert-danger", %param);
}

sub add_js {
    my ($self, $js) = @_;

    $self->{js} .= $js . "\n";
}

my $format_event_callback = sub {
    my ($info) = @_;

    my $pstr = encode_json($info->{param});
    return "function(e){$info->{fn}.apply(e, $pstr);}";
};

sub button {
    my ($self, %param) = @_;

    $param{tag} = 'button';
    $param{class} = "btn btn-default btn-xs";

    if (my $click = delete $param{click}) {
	my ($html, $id) = $self->el(%param);
	my $cb = &$format_event_callback($click);
	$self->add_js("jQuery('#$id').on('click', $cb);");
	return $html;
    } else {
	return $self->el(%param);
    }
}

1;
