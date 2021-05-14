package PVE::APIServer::Formatter::HTML;

use strict;
use warnings;

use PVE::APIServer::Formatter;
use HTTP::Status;
use JSON;
use HTML::Entities;
use PVE::JSONSchema;
use PVE::APIServer::Formatter::Bootstrap;
use PVE::APIServer::Formatter::Standard;

my $portal_format = 'html';
my $portal_ct = 'text/html;charset=UTF-8';

my $get_portal_base_url = sub {
    my ($config) = @_;
    return "$config->{base_uri}/$portal_format";
};

my $get_portal_login_url = sub {
    my ($config) = @_;
    return "$config->{base_uri}/$portal_format/access/ticket";
};

sub render_page {
    my ($doc, $html, $config) = @_;

    my $items = [];

    push @$items, {
	tag => 'li',
	cn => {
	    tag => 'a',
	    href => $get_portal_login_url->($config),
	    onClick => "PVE.delete_auth_cookie();",
	    text => "Logout",
	}};

    my $base_url = $get_portal_base_url->($config);

    my $nav = $doc->el(
	class => "navbar navbar-inverse navbar-fixed-top",
	role => "navigation", cn => {
	    class => "container", cn => [
		{
		    class => "navbar-header", cn => [
			{
			    tag => 'button',
			    type => 'button',
			    class => "navbar-toggle",
			    'data-toggle' => "collapse",
			    'data-target' => ".navbar-collapse",
			    cn => [
				{ tag => 'span', class => 'sr-only', text => "Toggle navigation" },
				{ tag => 'span', class => 'icon-bar' },
				{ tag => 'span', class => 'icon-bar' },
				{ tag => 'span', class => 'icon-bar' },
			    ],
			},
			{
			    tag => 'a',
			    class => "navbar-brand",
			    href => $base_url,
			    text => $config->{title},
			},
		    ],
		},
		{
		    class => "collapse navbar-collapse",
		    cn => {
			tag => 'ul',
			class => "nav navbar-nav",
			cn => $items,
		    },
		},
	    ],
	});

    $items = [];
    my @pcomp = split('/', $doc->{url});
    shift @pcomp; # empty
    shift @pcomp; # api2
    shift @pcomp; # $format

    my $href = $base_url;
    push @$items, { tag => 'li', cn => {
	tag => 'a',
	href => $href,
	text => 'Home'}};

    foreach my $comp (@pcomp) {
	$href .= "/$comp";
	push @$items, { tag => 'li', cn => {
	    tag => 'a',
	    href => $href,
	    text => $comp}};
    }

    my $breadcrumbs = $doc->el(tag => 'ol', class => 'breadcrumb container', cn => $items);

    return $doc->body($nav . $breadcrumbs . $html);
}

my $login_form = sub {
    my ($config, $doc, $param, $errmsg) = @_;

    $param = {} if !$param;

    my $username = $param->{username} || '';
    my $password = $param->{password} || '';

    my $items = [
	{
	    tag => 'label',
	    text => "Please sign in",
	},
	{
	    tag => 'input',
	    type => 'text',
	    class => 'form-control',
	    name => 'username',
	    value => $username,
	    placeholder => "Enter user name",
	    required => 1,
	    autofocus => 1,
	},
	{
	    tag => 'input',
	    type => 'password',
	    class => 'form-control',
	    name => 'password',
	    value => $password,
	    placeholder => 'Password',
	    required => 1,
	},
    ];

    my $html = '';

    $html .= $doc->alert(text => $errmsg) if ($errmsg);

    $html .= $doc->el(
	class => 'container',
	cn => {
	    tag => 'form',
	    role => 'form',
	    method => 'POST',
	    action => $get_portal_login_url->($config),
	    cn => [
		{
		    class => 'form-group',
		    cn => $items,
		},
		{
		    tag => 'button',
		    type => 'submit',
		    class => 'btn btn-lg btn-primary btn-block',
		    text => "Sign in",
		},
	    ],
	});

    return $html;
};

PVE::APIServer::Formatter::register_login_formatter($portal_format, sub {
    my ($path, $auth, $config) = @_;

    my $headers = HTTP::Headers->new(Location => $get_portal_login_url->($config));
    return HTTP::Response->new(301, "Moved", $headers);
});

PVE::APIServer::Formatter::register_formatter($portal_format, sub {
    my ($res, $data, $param, $path, $auth, $config) = @_;

    # fixme: clumsy!
    PVE::APIServer::Formatter::Standard::prepare_response_data($portal_format, $res);
    $data = $res->{data};

    my $html = '';
    my $doc = PVE::APIServer::Formatter::Bootstrap->new($res, $path, $auth, $config);

    if (!HTTP::Status::is_success($res->{status})) {
	$html .= $doc->alert(text => "Error $res->{status}: $res->{message}");
    }

    my $lnk;

    if (my $info = $res->{info}) {
	$html .= $doc->el(tag => 'h3', text => 'Description');
	$html .= $doc->el(tag => 'p', text => $info->{description});

	$lnk = PVE::JSONSchema::method_get_child_link($info);
    }

    if ($lnk && $data && $data->{data} && HTTP::Status::is_success($res->{status})) {

	my $href = $lnk->{href};
	if ($href =~ m/^\{(\S+)\}$/) {

	    my $items = [];

	    my $prop = $1;
	    $path =~ s/\/+$//; # remove trailing slash

	    foreach my $elem (sort {$a->{$prop} cmp $b->{$prop}} @{$data->{data}}) {
		next if !ref($elem);

		if (defined(my $value = $elem->{$prop})) {
		    my $tv = to_json($elem, {pretty => 1, allow_nonref => 1, canonical => 1});

		    push @$items, {
			tag => 'a',
			class => 'list-group-item',
			href => "$path/$value",
			cn => [
			    {
				tag => 'h4',
				class => 'list-group-item-heading',
				text => $value,
			    },
			    {
				tag => 'pre',
				class => 'list-group-item',
				text => $tv,
			    },
			],
		    };
		}
	    }

	    $html .= $doc->el(class => 'list-group', cn => $items);

	} else {

	    my $json = to_json($data, {allow_nonref => 1, pretty => 1, canonical => 1});
	    $html .= $doc->el(tag => 'pre', text => $json);
 	}

    } else {

	my $json = to_json($data, {allow_nonref => 1, pretty => 1, canonical => 1});
	$html .= $doc->el(tag => 'pre', text => $json);
    }

    $html = $doc->el(class => 'container', html => $html);

    my $raw = render_page($doc, $html, $config);
    return ($raw, $portal_ct);
});

PVE::APIServer::Formatter::register_page_formatter(
    'format' => $portal_format,
    method => 'GET',
    path => "/access/ticket",
    code => sub {
	my ($res, $data, $param, $path, $auth, $config) = @_;

	my $doc = PVE::APIServer::Formatter::Bootstrap->new($res, $path, $auth, $config);

	my $html = $login_form->($config, $doc);

	my $raw = render_page($doc, $html, $config);
	return ($raw, $portal_ct);
    });

PVE::APIServer::Formatter::register_page_formatter(
    'format' => $portal_format,
    method => 'POST',
    path => "/access/ticket",
    code => sub {
	my ($res, $data, $param, $path, $auth, $config) = @_;

	if (HTTP::Status::is_success($res->{status})) {
	    my $cookie = PVE::APIServer::Formatter::create_auth_cookie(
		$data->{ticket}, $config->{cookie_name});

	    my $headers = HTTP::Headers->new(Location => $get_portal_base_url->($config),
					     'Set-Cookie' => $cookie);
	    return HTTP::Response->new(301, "Moved", $headers);
	}

	# Note: HTTP server redirects to 'GET /access/ticket', so below
	# output is not really visible.

	my $doc = PVE::APIServer::Formatter::Bootstrap->new($res, $path, $auth, $config);

	my $html = $login_form->($config, $doc);

	my $raw = render_page($doc, $html, $config);
	return ($raw, $portal_ct);
    });

1;
