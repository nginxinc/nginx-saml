#!/usr/bin/perl

# (C) Ivan Ovchinnikov
# (C) Nginx, Inc.

# Tests for njs-based SAML SSO solution.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

use MIME::Base64;
use XML::LibXML;
use JSON::PP;
use URI::Escape;
use DateTime;

use IO::Uncompress::RawInflate qw(rawinflate $RawInflateError);
use IO::Compress::RawDeflate qw(rawdeflate $RawDeflateError);

use Crypt::OpenSSL::X509;
use Crypt::OpenSSL::RSA;
use Digest::SHA qw(sha1 sha256 sha384 sha512);

use constant false => 0;
use constant true  => 1;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

eval { require JSON::PP; };
plan(skip_all => "JSON::PP not installed") if $@;

my $t = Test::Nginx->new()->has(qw/http rewrite proxy gzip api keyval/)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    variables_hash_max_size 2048;

    js_import samlsp from saml_sp.js;

    upstream my_backend {
        zone my_backend 64k;
        server localhost:8088;
    }

    map $host $saml_debug {
        default "1";
    }
    
    keyval_zone zone=saml_sp_entity_id:1M state=%%TESTDIR%%/saml_sp_entity_id.json;
    keyval $host $saml_sp_entity_id zone=saml_sp_entity_id;

    keyval_zone zone=saml_sp_acs_url:1M state=%%TESTDIR%%/saml_sp_acs_url.json;
    keyval $host $saml_sp_acs_url zone=saml_sp_acs_url;

    keyval_zone zone=saml_sp_request_binding:1M state=%%TESTDIR%%/saml_sp_request_binding.json;
    keyval $host $saml_sp_request_binding zone=saml_sp_request_binding;

    keyval_zone zone=saml_sp_sign_authn:1M state=%%TESTDIR%%/saml_sp_sign_authn.json;
    keyval $host $saml_sp_sign_authn zone=saml_sp_sign_authn;

    keyval_zone zone=saml_sp_signing_key:1M state=%%TESTDIR%%/saml_sp_signing_key.json;
    keyval $host $saml_sp_signing_key zone=saml_sp_signing_key;
    
    keyval_zone zone=saml_sp_decryption_key:1M state=%%TESTDIR%%/saml_sp_decryption_key.json;
    keyval $host $saml_sp_decryption_key zone=saml_sp_decryption_key;

    keyval_zone zone=saml_sp_force_authn:1M state=%%TESTDIR%%/saml_sp_force_authn.json;
    keyval $host $saml_sp_force_authn zone=saml_sp_force_authn;

    keyval_zone zone=saml_sp_nameid_format:1M state=%%TESTDIR%%/saml_sp_nameid_format.json;
    keyval $host $saml_sp_nameid_format zone=saml_sp_nameid_format;

    keyval_zone zone=saml_sp_relay_state:1M state=%%TESTDIR%%/saml_sp_relay_state.json;
    keyval $host $saml_sp_relay_state zone=saml_sp_relay_state;

    keyval_zone zone=saml_sp_want_signed_response:1M state=%%TESTDIR%%/saml_sp_want_signed_response.json;
    keyval $host $saml_sp_want_signed_response zone=saml_sp_want_signed_response;

    keyval_zone zone=saml_sp_want_signed_assertion:1M state=%%TESTDIR%%/saml_sp_want_signed_assertion.json;
    keyval $host $saml_sp_want_signed_assertion zone=saml_sp_want_signed_assertion;

    keyval_zone zone=saml_sp_want_encrypted_assertion:1M state=%%TESTDIR%%/saml_sp_want_encrypted_assertion.json;
    keyval $host $saml_sp_want_encrypted_assertion zone=saml_sp_want_encrypted_assertion;

    keyval_zone zone=saml_idp_entity_id:1M state=%%TESTDIR%%/saml_idp_entity_id.json;
    keyval $host $saml_idp_entity_id zone=saml_idp_entity_id;

    keyval_zone zone=saml_idp_sso_url:1M state=%%TESTDIR%%/saml_idp_sso_url.json;
    keyval $host $saml_idp_sso_url zone=saml_idp_sso_url;

    keyval_zone zone=saml_idp_verification_certificate:1M state=%%TESTDIR%%/saml_idp_verification_certificate.json;
    keyval $host $saml_idp_verification_certificate zone=saml_idp_verification_certificate;

    keyval_zone zone=saml_sp_slo_url:1M state=%%TESTDIR%%/saml_sp_slo_url.json;
    keyval $host $saml_sp_slo_url zone=saml_sp_slo_url;

    keyval_zone zone=saml_sp_slo_binding:1M state=%%TESTDIR%%/saml_sp_slo_binding.json;
    keyval $host $saml_sp_slo_binding zone=saml_sp_slo_binding;

    keyval_zone zone=saml_sp_sign_slo:1M state=%%TESTDIR%%/saml_sp_sign_slo.json;
    keyval $host $saml_sp_sign_slo zone=saml_sp_sign_slo;

    keyval_zone zone=saml_idp_slo_url:1M state=%%TESTDIR%%/saml_idp_slo_url.json;
    keyval $host $saml_idp_slo_url zone=saml_idp_slo_url;

    keyval_zone zone=saml_sp_want_signed_slo:1M state=%%TESTDIR%%/saml_sp_want_signed_slo.json;
    keyval $host $saml_sp_want_signed_slo zone=saml_sp_want_signed_slo;

    keyval_zone zone=saml_logout_landing_page:1M state=%%TESTDIR%%/saml_logout_landing_page.json;
    keyval $host $saml_logout_landing_page zone=saml_logout_landing_page;

    keyval_zone zone=saml_cookie_flags:1M state=%%TESTDIR%%/saml_cookie_flags.json;
    keyval $host $saml_cookie_flags zone=saml_cookie_flags;

    keyval_zone zone=redirect_base:1M state=%%TESTDIR%%/redirect_base.json;
    keyval $host $redirect_base zone=redirect_base;

    keyval_zone zone=proto:1M state=%%TESTDIR%%/proto.json;
    keyval $host $proto zone=proto;

    keyval_zone zone=saml_request_id:1M state=saml_request_id.json timeout=5m;
    keyval_zone zone=saml_response_id:1M state=saml_response_id.json timeout=1h;
    keyval_zone zone=saml_session_access:1M state=saml_session_access.json timeout=1h;
    keyval_zone zone=saml_name_id:1M state=saml_name_id.json timeout=1h;
    keyval_zone zone=saml_name_id_format:1M state=saml_name_id_format.json timeout=1h;
    keyval_zone zone=saml_session_index:1M state=saml_session_index.json timeout=1h;
    keyval_zone zone=saml_authn_context_class_ref:1M state=saml_authn_context_class_ref.json timeout=1h;
    keyval_zone zone=saml_attrib_uid:1M state=saml_attrib_uid.json timeout=1h;
    keyval_zone zone=saml_attrib_name:1M state=saml_attrib_name.json timeout=1h;
    keyval_zone zone=saml_attrib_memberOf:1M state=saml_attrib_memberOf.json timeout=1h;
    keyval_zone zone=saml_attrib_foo:1M state=saml_attrib_foo.json timeout=1h;

    keyval $saml_request_id $saml_request_redeemed zone=saml_request_id;
    keyval $saml_response_id $saml_response_redeemed zone=saml_response_id;
    keyval $cookie_auth_token $saml_access_granted zone=saml_session_access;
    keyval $cookie_auth_token $saml_name_id zone=saml_name_id;
    keyval $cookie_auth_token $saml_name_id_format zone=saml_name_id_format;
    keyval $cookie_auth_token $saml_session_index zone=saml_session_index;
    keyval $cookie_auth_token $saml_authn_context_class_ref zone=saml_authn_context_class_ref;

    keyval $cookie_auth_token $saml_attrib_uid zone=saml_attrib_uid;
    keyval $cookie_auth_token $saml_attrib_name zone=saml_attrib_name;
    keyval $cookie_auth_token $saml_attrib_memberOf zone=saml_attrib_memberOf;
    keyval $cookie_auth_token $saml_attrib_foo zone=saml_attrib_foo;

    server {
        listen       127.0.0.1:8080;
        server_name  sp.exmaple.com;

        set $saml_request_id "";
        set $saml_response_id "";
        set $internal_error_message "SAML Authentication failed. If problem persists, contact your system administrator. ";
        js_var $internal_error_details;
        client_max_body_size 64k;
        client_body_buffer_size 64k;
        gunzip on;

        location = /saml/acs {
            js_content samlsp.handleSingleSignOn;
            status_zone "SAMLSSO ACS";
            error_page 500 @saml_error; 
        }

        location = /saml/sls {
            js_content samlsp.handleSingleLogout;
            status_zone "SAMLSSO SLS";
            error_page 500 @saml_error; 
        }

        location @do_samlsp_flow {
            js_content samlsp.initiateSingleSignOn;
            set $cookie_auth_token "";
        }

        location = /login {
            js_content samlsp.initiateSingleSignOn;
            status_zone "SAMLSSO login";
            error_page 500 @saml_error;
        }

        location = /logout {
            js_content samlsp.initiateSingleLogout;
            status_zone "SAMLSSO logout";
            error_page 500 @saml_error;
        }

        location = /_logout {
            default_type text/plain;
            return 200 "Logged out\n";
        }

        location @saml_error {
            status_zone "SAMLSP error";
            default_type text/plain;
            return 500 "$internal_error_message $internal_error_details";
        }

        location /api {
            api write=on;
            allow all;
        }

        location / {
            error_page 401 = @do_samlsp_flow;
            if ($saml_access_granted != "1") {
                return 401;
            }
            proxy_set_header Cookie "user=$saml_name_id;";
            proxy_pass http://my_backend;
            default_type text/html;
        }
    }

    server {
        listen       8088;
        server_name  localhost;

        location / {
            return 200 "Welcome $cookie_user";
        }
    }
}

EOF

my $d = $t->testdir();

$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

foreach my $name ('sp.example.com', 'idp.example.com') {
	system('openssl req -x509 -new '
		. "-config $d/openssl.conf -subj /CN=$name/ "
		. "-out $d/$name.crt -keyout $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";

	system('openssl x509 '
		. "-in $d/$name.crt -outform DER "
		. "-out $d/$name.der "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't convert $name.pem to $name.der: $!\n";

	system('openssl x509 -inform DER '
		. "-in $d/$name.der -pubkey -noout "
		. "> $d/$name.spki 2>&1") == 0
		or die "Can't extract pub key from $name.der: $!\n";
}

my @mspki = ("$d/sp.example.com.spki", "$d/idp.example.com.spki");
$t->write_file('multiple.spki', read_file(\@mspki));

my $idp_priv = $t->read_file('idp.example.com.key');
my $sp_pub = $t->read_file('sp.example.com.crt');

my $js_filename = 'saml_sp.js';
$t->write_file($js_filename, read_file("../$js_filename"));

$t->try_run('no njs available')->plan(128);

my $api_version = (sort { $a <=> $b } @{ api() })[-1];
my $kv = "/api/$api_version/http/keyvals";

my $acs = '/saml/acs';
my $sls = '/saml/sls';

###############################################################################

my $cfg = {
	saml_sp_entity_id => 'http://sp.example.com',
	saml_sp_acs_url => 'http://sp.example.com:8080/saml/acs',
	saml_sp_request_binding => 'HTTP-POST',
	saml_sp_sign_authn => 'true',
	saml_sp_signing_key => "$d/sp.example.com.key",
	saml_sp_decryption_key => "$d/sp.example.com.key",
	saml_sp_force_authn => 'true',
	saml_sp_nameid_format => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
	saml_sp_relay_state => '/foo?a=b',
	saml_sp_want_signed_response => 'false',
	saml_sp_want_signed_assertion => 'false',
	saml_sp_want_encrypted_assertion => 'false',
	saml_idp_entity_id => 'http://idp.example.com',
	saml_idp_sso_url => 'http://idp.example.com:8090/sso',
	saml_idp_verification_certificate => "$d/idp.example.com.spki",
	saml_sp_slo_url => 'http://sp.example.com:8080/saml/sls',
	saml_sp_slo_binding => 'HTTP-POST',
	saml_sp_sign_slo => 'false',
	saml_idp_slo_url => 'http://idp.example.com:8090/slo',
	saml_sp_want_signed_slo => 'false',
	saml_logout_landing_page => '/_logout',
	saml_cookie_flags => 'Path=/; SameSite=lax;',
};

cfg_post($cfg, 1);

## SAML Authentication Request

my $r = parse_response(get('/'));

is($r->{Action}, $cfg->{saml_idp_sso_url}, 'authn request post action');
is($r->{RelayState}, $cfg->{saml_sp_relay_state},
	'authn request post relaystate');
is($r->{Type}, 'AuthnRequest', 'authn request header type');
is($r->{Version}, '2.0', 'authn request version');
is($r->{ProtocolBinding}, 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
	'authn request protocolbinding');
like($r->{ID}, qr/^_[a-f0-9]{40}$/, 'authn request id');
ok(is_issue_instant_valid($r->{IssueInstant}), 'authn request issueinstant');
is($r->{AssertionConsumerServiceURL}, $cfg->{saml_sp_acs_url},
	'authn request acs url');
is($r->{Destination}, $cfg->{saml_idp_sso_url}, 'authn request destination');
is($r->{ForceAuthn}, $cfg->{saml_sp_force_authn},
	'authn request forceauthn true');
is($r->{Issuer}, $cfg->{saml_sp_entity_id}, 'authn request issuer url');
is($r->{isValid}, 1, 'authn request sign valid');
is($r->{NameIDPolicyFormat}, $cfg->{saml_sp_nameid_format},
	'authn request nameidpolicy format');
like(get("$kv/saml_request_id"), qr/"$r->{ID}":"1"/,
	'authn request id redeemed');

# Reconfiguration

$cfg->{saml_sp_entity_id} = 'urn:example:a123,0%7C00~z456/789?+abc?=xyz#12/3';
$cfg->{saml_sp_request_binding} = 'HTTP-Redirect';
$cfg->{saml_sp_sign_authn} = 'false';
$cfg->{saml_sp_force_authn} = 'false';
$cfg->{saml_sp_relay_state} = '/foo?a=b';
cfg_post($cfg);

$r = parse_response(get('/'));

like($r->{Action}, qr/$cfg->{saml_idp_sso_url}\?SAMLRequest=/,
	'authn request get location');
is($r->{RelayState}, $cfg->{saml_sp_relay_state},
	'authn request get relaystate');
ok(!defined($r->{ForceAuthn}), 'authn request forceauthn false');
is($r->{Issuer}, $cfg->{saml_sp_entity_id}, 'authn request issuer urn');
is($r->{isSigned}, 0, 'authn request not signed');

# AuthenRequest config validation

cfg_verify('saml_sp_entity_id', 'saml_sp_entity_id validation');
cfg_verify('saml_sp_request_binding', 'saml_sp_request_binding validation');
cfg_verify('saml_sp_force_authn', 'saml_sp_force_authn validation');
cfg_verify('saml_sp_nameid_format', 'saml_sp_nameid_format validation');
cfg_verify('saml_sp_sign_authn', 'saml_sp_sign_authn validation');

### SAML Authentication Response

$r = init_sso($cfg, 1);
like(get('/', auth_token => get_auth_token($r)), qr/Welcome user1/,
	'sp-initiated sso');
like($r, qr{302.*http://sp.example.com:8080/foo\?a=b}s,
	'sp sso redirect to relay state');
like($r, qr/lax/, 'sp sso cookie flags');

cfg_post({saml_sp_relay_state => ""});
$r = init_sso($cfg, 1, auth_redir => '/foo?a=b');
like($r, qr{302.*http://sp.example.com:8080/foo\?a=b}s,
	'sp sso redirect to request uri');

# Keyval attributes validation

like(get("$kv/saml_response_id"), qr/"_nginx_[^"]+":\s*"1"/,
	'kv response id');
like(get("$kv/saml_name_id"), qr/user1/, 'kv response name id');
like(get("$kv/saml_name_id_format"), qr/unspecified/,
	'kv response name id format');
like(get("$kv/saml_session_index"), qr/_nginx_sessionindex_/,
	'kv response session index');
like(get("$kv/saml_authn_context_class_ref"), qr/Password/,
	'kv authn context class ref');
like(get("$kv/saml_attrib_uid"), qr/"1"/, 'kv uid attr');
like(get("$kv/saml_attrib_name"), qr/"Alan Alda"/, 'kv name attr');
like(get("$kv/saml_attrib_memberOf"), qr/"group1, admins, students"/,
	'kv memberof attr');
like(get("$kv/saml_attrib_foo"), qr/"bar"/, 'kv namespace-qualified attr');

### Signature validation

$cfg->{saml_sp_want_signed_response} = 'false';
$cfg->{saml_sp_want_signed_assertion} = 'false';
cfg_post({saml_sp_want_signed_response => 'false',
	saml_sp_want_signed_assertion => 'false'});

$r = init_sso($cfg);
like(get('/', auth_token => get_auth_token($r)), qr/Welcome user1/,
	'response and assertion unsigned');

cfg_post({saml_sp_want_signed_response => 'true'});
$r = init_sso($cfg);
like($r, qr/500.*Message is unsigned/s,
	'want signed response got unsigned');

$cfg->{saml_sp_want_signed_response} = 'true';
$r = init_sso($cfg);
like(get('/', auth_token => get_auth_token($r)), qr/Welcome user1/,
	'response signed');

cfg_post({saml_sp_want_signed_assertion => 'true'});
$r = init_sso($cfg);
like($r, qr/500.*Message is unsigned/s,
	'want signed assertion got unsigned');

$cfg->{saml_sp_want_signed_assertion} = 'true';
$r = init_sso($cfg);
like(get('/', auth_token => get_auth_token($r)), qr/Welcome user1/,
	'response and assertion signed');

cfg_post({saml_idp_verification_certificate => "$d/multiple.spki"});
$r = init_sso($cfg);
like(get('/', auth_token => get_auth_token($r)), qr/Welcome user1/,
	'multiple idp certs');

cfg_post({saml_idp_verification_certificate => "$d/sp.example.com.key"});
$r = init_sso($cfg);
like($r, qr/500.*Error verifying.*signature.*error:Type=X509_PUBKEY/s,
	'wrong cert type');

cfg_post({saml_idp_verification_certificate => "not_found"});
$r = init_sso($cfg);
like($r, qr/500.*Failed to read.*public key from file/s,
	'idp cert file not found');

cfg_post({saml_idp_verification_certificate => "$d/sp.example.com.spki"});
$r = init_sso($cfg);
like($r, qr/500.*Key index 0: signature verification failed/s,
	'wrong idp cert');
cfg_post({saml_idp_verification_certificate => "$d/idp.example.com.spki"});

my $xml_obj = produce_saml('Response', $cfg);

$r = modify_saml_obj($xml_obj, '//ds:Reference', 'URI', '#foo');
like($r, qr/500.*reference URI.*does not point to the parent/s,
	'signature reference uri mismatch');

$r = modify_saml_obj($xml_obj, '//ds:Transform', 'Algorithm', 'foo');
like($r, qr/500.*unexpected digest transform/s,
	'signature unexpected digest transform');

$r = modify_saml_obj($xml_obj, '//ds:DigestMethod', 'Algorithm', 'foo');
like($r, qr/500.*unexpected digest Algorithm/s,
	'signature unexpected digest algorithm');

$r = modify_saml_obj($xml_obj, '//ds:DigestMethod', 'Algorithm',
	'http://www.w3.org/2000/09/xmldsig#sha1');
like($r, qr/500.*signature verification failed/s,
	'signature wrong digest algorithm');

$r = modify_saml_obj($xml_obj, '//ds:DigestValue', 'text', 'foo');
like($r, qr/500.*signature verification failed/s,
	'signature digest value mismatch');

$r = modify_saml_obj($xml_obj, '//ds:SignatureMethod', 'Algorithm', 'foo');
like($r, qr/500.*unexpected signature Algorithm/s,
	'signature unexpected algorithm');

$r = modify_saml_obj($xml_obj, '//ds:SignatureMethod', 'Algorithm',
	'http://www.w3.org/2000/09/xmldsig#rsa-sha1');
like($r, qr/500.*signature verification failed/s, 'signature wrong algorithm');

$r = modify_saml_obj($xml_obj, '//ds:SignatureValue', 'text', 'foo');
like($r, qr/500.*signature verification failed/s, 'signature value mismatch');

### Response validation

$cfg->{saml_sp_want_signed_response} = 'false';
$cfg->{saml_sp_want_signed_assertion} = 'false';
cfg_post({saml_sp_want_signed_response => 'false'});
cfg_post({saml_sp_want_signed_assertion => 'false'});

$xml_obj = produce_saml('Response', $cfg);

$r = modify_saml_obj($xml_obj, '/samlp:Response', 'ID', 'foo');
$r = modify_saml_obj($xml_obj, '/samlp:Response', 'ID', 'foo');
like($r, qr/HTTP\/1\.1 500.*ID.*redeemed/s, 'response id redeemed');

$r = modify_saml_obj($xml_obj, '/samlp:Response', 'ID');
like($r, qr/HTTP\/1\.1 500.*ID.*is missing/s, 'response no id');

$r = modify_saml_obj($xml_obj, '/samlp:Response', 'InResponseTo', 'foo');
like($r, qr/HTTP\/1\.1 500.*"foo" not found/s, 'inresponseto not found');

$r = modify_saml_obj($xml_obj, '/samlp:Response', 'InResponseTo');
like(get('/', auth_token => get_auth_token($r)), qr/Welcome user1/,
	'idp-initiated sso');

$r = modify_saml_obj($xml_obj, '/samlp:Response', 'Destination');
like(get('/', auth_token => get_auth_token($r)), qr/Welcome user1/,
	'response no destination');

$r = modify_saml_obj($xml_obj, '/samlp:Response', 'Destination', 'foo');
like($r, qr/HTTP\/1\.1 500.*not match SP ACS URL/s,
	'response wrong destination');

$r = modify_saml_obj($xml_obj, '/samlp:Response', 'Version', '1.0');
like($r, qr/HTTP\/1\.1 500.*Unsupported SAML Version/s,
	'response unsupported version');

my ($ptime, $ftime) = get_time();
$r = modify_saml_obj($xml_obj, '/samlp:Response', 'IssueInstant', $ftime);
like($r, qr/HTTP\/1\.1 500.*IssueInstant.*in the future/s,
	'response future issue instant');

$r = modify_saml_obj($xml_obj, '/samlp:Response', 'IssueInstant');
like($r, qr/HTTP\/1\.1 500.*IssueInstant.*is missing/s,
	'response no issue instant');

$r = modify_saml_obj($xml_obj, '//saml:Issuer');
like($r, qr/HTTP\/1\.1 500/s, 'response no issuer');

$r = modify_saml_obj($xml_obj, '//saml:Issuer', 'text', 'foo');
like($r, qr/HTTP\/1\.1 500.*Issuer "foo" does not match IdP EntityID/s,
	'response wrong issuer');

$r = modify_saml_obj($xml_obj, '//samlp:StatusCode', 'Value', 'foo');
like($r, qr/HTTP\/1\.1 500.*Error: StatusCode: foo/s,
	'response status not success');

$r = modify_saml_obj($xml_obj, '//saml:Assertion', 'Version', '1.0');
like($r, qr/HTTP\/1\.1 500.*Unsupported SAML Version/s,
	'assertion unsupported version');

$r = modify_saml_obj($xml_obj, '//saml:Assertion', 'ID');
like($r, qr/HTTP\/1\.1 500.*ID.*is missing/s, 'assertion no id');

$r = modify_saml_obj($xml_obj, '//saml:Assertion', 'IssueInstant', $ftime);
like($r, qr/HTTP\/1\.1 500.*IssueInstant.*in the future/s,
	'assertion future issue instant');

$r = modify_saml_obj($xml_obj, '//saml:NameID');
like($r, qr/HTTP\/1\.1 500.*NameID element is missing/s,
	'assertion no name id');

$r = modify_saml_obj($xml_obj, '//saml:SubjectConfirmation');
like(get('/', auth_token => get_auth_token($r)), qr/Welcome user1/,
	'assertion no subject confirmation');

$r = modify_saml_obj($xml_obj, '//saml:SubjectConfirmationData');
like($r, qr/HTTP\/1\.1 500.*SubjectConfirmationData.*is missing/s,
	'assertion no subject confirmation data');

$r = modify_saml_obj($xml_obj, '//saml:SubjectConfirmationData',
	'NotOnOrAfter', $ptime);
like($r, qr/HTTP\/1\.1 500.*Subject has expired/s,
	'assertion subject has expired');

$r = modify_saml_obj($xml_obj, '//saml:Conditions');
like($r, qr/HTTP\/1\.1 500.*Conditions.*is missing/s,
	'assertion no conditions');

$r = modify_saml_obj($xml_obj, '//saml:Conditions', 'NotBefore', $ftime);
like($r, qr/HTTP\/1\.1 500.*Assertion is not yet valid/s,
	'assertion is not yet valid');

$r = modify_saml_obj($xml_obj, '//saml:Conditions', 'NotOnOrAfter', $ptime);
like($r, qr/HTTP\/1\.1 500.*Assertion has expired/s, 'assertion has expired');

$r = modify_saml_obj($xml_obj, '//saml:AudienceRestriction');
like(get('/', auth_token => get_auth_token($r)), qr/Welcome user1/,
	'assertion no audience restriction');

$r = modify_saml_obj($xml_obj, '//saml:Audience', 'text', 'foo');
like($r, qr/HTTP\/1\.1 500.*Assertion is not intended for this Service/s,
	'assertion wrong audience');

$r = modify_saml_obj($xml_obj, '//saml:AuthnStatement');
like(get('/', auth_token => get_auth_token($r)), qr/Welcome user1/,
	'assertion no authn statement');

$r = modify_saml_obj($xml_obj, '//saml:AuthnStatement', 'SessionNotOnOrAfter',
	$ptime);
like($r, qr/HTTP\/1\.1 500.*Assertion Session has expired/s,
	'assertion session has expired');

$r = modify_saml_obj($xml_obj, '//saml:AuthnStatement', 'SessionIndex');
like(get('/', auth_token => get_auth_token($r)), qr/Welcome user1/,
	'assertion no sessionindex');

$r = modify_saml_obj($xml_obj, '//saml:AuthnContextClassRef');
like($r, qr/HTTP\/1\.1 500.*AuthnContextClassRef.*is missing/s,
	'assertion no authncontextclassref');

$r = modify_saml_obj($xml_obj, '//saml:AttributeStatement');
like(get('/', auth_token => get_auth_token($r)), qr/Welcome user1/,
	'assertion no attribute statement');

### SP-initiated logout

# Logout Request

$r = parse_response(get('/logout', 
	auth_token => get_auth_token(init_sso($cfg))));

is($r->{Action}, $cfg->{saml_idp_slo_url}, 'sp logout request post action');
is($r->{RelayState}, $cfg->{saml_logout_landing_page},
	'sp logout request post relaystate');
is($r->{Type}, 'LogoutRequest', 'sp logout request msg type');
is($r->{Version}, '2.0', 'sp logout request version');
like($r->{ID}, qr/^_[a-f0-9]{40}$/, 'sp logout request id');
ok(is_issue_instant_valid($r->{IssueInstant}),
	'sp logout request issueinstant');
is($r->{Destination}, $cfg->{saml_idp_slo_url},
	'sp logout request destination');
is($r->{Issuer}, $cfg->{saml_sp_entity_id}, 'sp logout request issuer');
is($r->{isSigned}, 0, 'sp logout request unsigned');
is($r->{NameID}, 'user1', 'sp logout request nameid');
like(get("$kv/saml_request_id"), qr/"$r->{ID}":"1"/,
	'sp logout request id redeemed');

$r = parse_response(get('/logout'));
like($r, qr{302.*Location:\shttp://sp.example.com:8080/_logout.*
	Set-Cookie:\sauth_token=;\sExpires.*1970.*
	Set-Cookie:\sauth_redir=;.*}msx, 'sp logout request with no session');

# Reconfiguration

$cfg->{saml_sp_slo_binding} = 'HTTP-Redirect';
$cfg->{saml_sp_sign_slo} = 'true';
cfg_post({saml_sp_slo_binding => 'HTTP-Redirect', saml_sp_sign_slo => 'true'});

my $auth_token = get_auth_token(init_sso($cfg));
$r = parse_response(get('/logout', auth_token => $auth_token));

like($r->{Action}, qr/$cfg->{saml_idp_slo_url}/,
	'sp logout request get location');
is($r->{RelayState}, $cfg->{saml_logout_landing_page},
	'sp logout request get relaystate');
is($r->{isValid}, 1, 'sp logout request signed');

# Logout Response

($r, $auth_token) = init_slo($cfg, sp_initiated => 1);
like($r, qr{302.*Location:\shttp://sp.example.com:8080/_logout.*
	Set-Cookie:\sauth_token=;\sExpires.*1970.*
	Set-Cookie:\sauth_redir=;\sExpires.*1970.*}msx,
	'idp logout response post method');
like(get("$kv/saml_name_id"), qr/"$auth_token":"-"/, 'slo nameid cleared');
like(get("$kv/saml_session_access"), qr/"$auth_token":"-"/,
	'slo session access cleared');

($r, undef) = init_slo($cfg, sp_initiated => 1, method => 'get');
like($r, qr{302.*Location:\shttp://sp.example.com:8080/_logout.*
	Set-Cookie:\sauth_token=;\sExpires.*1970.*
	Set-Cookie:\sauth_redir=;\sExpires.*1970.*}msx,
	'idp logout response get method');

cfg_post({saml_sp_want_signed_slo => 'true'});
($r, undef) = init_slo($cfg, sp_initiated => 1);
like($r, qr/500.*Message is unsigned/s, 'idp logout response unsigned');

$cfg->{saml_sp_want_signed_slo} = 'true';
($r, undef) = init_slo($cfg, sp_initiated => 1);
like($r, qr{302.*Location:\shttp://sp.example.com:8080/_logout.*
	Set-Cookie:\sauth_token=;\sExpires.*1970.*
	Set-Cookie:\sauth_redir=;\sExpires.*1970.*}msx,
	'idp logout response signed');

$cfg->{saml_sp_want_signed_slo} = 'false';
cfg_post({saml_sp_want_signed_slo => 'false'});

# Logout Response validation

$auth_token = get_auth_token(init_sso($cfg));
$r = parse_response(get('/logout', auth_token => $auth_token));
$xml_obj = produce_saml('LogoutResponse', $cfg, $r->{ID});

$r = modify_saml_obj($xml_obj, '//samlp:Status', undef, undef,
	auth_token => $auth_token, relay_state => $cfg->{saml_logout_landing_page});
like($r, qr/500.*Status element is missing/s,
	'idp logout response no status');

$r = modify_saml_obj($xml_obj, '//samlp:StatusCode', undef, undef,
	auth_token => $auth_token, relay_state => $cfg->{saml_logout_landing_page});
like($r, qr/500.*StatusCode element is missing/s,
	'idp logout response no status code');

$r = modify_saml_obj($xml_obj, '//samlp:StatusCode', 'Value', undef,
	auth_token => $auth_token, relay_state => $cfg->{saml_logout_landing_page});
like($r, qr/500.*StatusCode element is missing/s,
	'idp logout response status code no value');

$r = modify_saml_obj($xml_obj, '//samlp:StatusCode', 'Value', 'foo',
	auth_token => $auth_token, relay_state => $cfg->{saml_logout_landing_page});
like($r, qr/500.*StatusCode: foo/s, 'idp logout response status code not success');

### IdP-initiated logout

# Logout Request

cfg_post({saml_sp_want_signed_slo => 'true'});
($r, undef) = init_slo($cfg);
like($r, qr/500.*Message is unsigned/s, 'idp logout request unsigned');

$cfg->{saml_sp_want_signed_slo} = 'true';
($r, undef) = init_slo($cfg);
is($r->{StatusCode}, 'urn:oasis:names:tc:SAML:2.0:status:Success',
	'idp logout request signed');

# Logout Request validation

$cfg->{saml_sp_want_signed_slo} = 'false';
cfg_post({saml_sp_want_signed_slo => 'false'});

$auth_token = get_auth_token(init_sso($cfg));
$xml_obj = produce_saml('LogoutRequest', $cfg);

$r = modify_saml_obj($xml_obj, '//saml:NameID', undef, undef,
	auth_token => $auth_token);
like($r, qr/500.*NameID element is missing in the Subject/s,
	'idp logout request no nameid');

$r = parse_response(modify_saml_obj($xml_obj, '//saml:NameID', 'text', 'foo',
	auth_token => $auth_token));
is($r->{StatusCode}, 'urn:oasis:names:tc:SAML:2.0:status:Requester',
	'idp logout request wrong nameid');

# Logout Response

($r, undef) = init_slo($cfg, relay_state => '/foo?a=b');
like($r->{Action}, qr/$cfg->{saml_idp_slo_url}\?SAMLResponse=/s,
	'sp logout response get location');
like($r->{Action}, qr{&RelayState=/foo\?a=b}s,
	'sp logout response get relaystate');
is($r->{Type}, 'LogoutResponse', 'sp logout response type');
is($r->{Version}, '2.0', 'sp logout response version');
like($r->{ID}, qr/^_[a-f0-9]{40}$/, 'sp logout response id');
ok(is_issue_instant_valid($r->{IssueInstant}),
	'sp logout response issueinstant');
is($r->{Destination}, $cfg->{saml_idp_slo_url},
	'sp logout response destination');
is($r->{Issuer}, $cfg->{saml_sp_entity_id}, 'sp logout response issuer url');
is($r->{isValid}, 1, 'sp logout response sign valid');
is($r->{StatusCode}, 'urn:oasis:names:tc:SAML:2.0:status:Success',
	'sp logout response status code');
is($r->{Cookie}, 'auth_token=; auth_redir=',
	'sp logout response session cookie cleared');
like(get("$kv/saml_request_id"), qr/"$r->{ID}":"1"/,
	'sp logout response request id redeemed');

# Reconfiguration
$cfg->{saml_sp_slo_binding} = 'HTTP-POST';
$cfg->{saml_sp_sign_slo} = 'false';
cfg_post({saml_sp_slo_binding => 'HTTP-POST', saml_sp_sign_slo => 'false'});

($r, undef) = init_slo($cfg, relay_state => '/foo?a=b');
is($r->{Action}, $cfg->{saml_idp_slo_url}, 'sp logout response post action');
is($r->{RelayState}, '/foo?a=b', 'sp logout response post relaystate');
is($r->{isSigned}, 0, 'sp logout response not signed');

($r, undef) = init_slo($cfg);
is($r->{RelayState}, undef, 'sp logout response no relaystate');

###############################################################################

sub get_auth_token {
	my ($r) = @_;

	return ($r =~ /Set-Cookie: auth_token=([^;]+);/)[0];
}

sub init_sso {
	my ($config, $sp, %extra) = @_;

	my $id = $sp ? parse_response(get('/'))->{ID} : undef;
	my $xml = produce_saml('Response', $config, $id);
	return send_saml($xml, $acs, %extra);
}

sub init_slo {
	my ($cfg, %extra) = @_;

	my $auth_token = get_auth_token(init_sso($cfg));

	if ($extra{sp_initiated}) {
		my $logout_response = parse_response(get('/logout',
			auth_token => $auth_token));
		my $saml_response = produce_saml('LogoutResponse', $cfg,
			$logout_response->{ID});
		return (send_saml($saml_response, $sls, auth_token => $auth_token,
			relay_state => $cfg->{saml_logout_landing_page}, %extra), $auth_token);
	} else {
		my $saml_request = produce_saml('LogoutRequest', $cfg);
		return (parse_response(send_saml($saml_request, $sls,
			auth_token => $auth_token, %extra)), $auth_token);
	}
}

sub modify_saml_obj {
	my ($xml_obj, $element, $attribute, $new_val, %extra) = @_;

	my $new_xml_obj = $xml_obj->cloneNode(1);
	my $xpc = initialize_saml_xpath_context($new_xml_obj);
	my $root = $new_xml_obj->documentElement();

	if (!$xpc->findnodes('//ds:Signature')) {
		$root->setAttribute('ID', '_nginx_' . rand(1));
	}

	my $url = $root->localname eq 'Response' ? $acs : $sls;
	return send_saml($new_xml_obj, $url, %extra) unless $element;

	my ($node) = $xpc->findnodes($element);
	return send_saml($new_xml_obj, $url, %extra) unless $node;

	if ($attribute) {
		if ($attribute eq 'text') {
			$node->removeChildNodes();
			$node->appendText($new_val);
		} else {
			if (defined $new_val) {
				$node->setAttribute($attribute, $new_val);
			} else {
				$node->removeAttribute($attribute);
			}
		}
	} else {
		$node->unbindNode();
	}

	return send_saml($new_xml_obj, $url, %extra);
}

sub parse_xml_string {
	my $parser = XML::LibXML->new();
	$parser->keep_blanks(0);
	return $parser->parse_string(shift);
}

sub initialize_saml_xpath_context {
	my $xpc = XML::LibXML::XPathContext->new(shift);
	$xpc->registerNs('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
	$xpc->registerNs('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');
	$xpc->registerNs('ds', 'http://www.w3.org/2000/09/xmldsig#');
	return $xpc;
}

sub parse_response {
	my ($r) = @_;
	my %result;
	my ($saml_base64, $relay_state, $dest, $xml_str);

	if ($r =~ /HTTP\/1\.. 302/) {
		($dest, $saml_base64, $relay_state) = parse_http_302($r);
		return $r unless $saml_base64;
		$xml_str = inflate_base64($saml_base64);
	} elsif ($r =~ /HTTP\/1\.. 200/) {
		($dest, $saml_base64, $relay_state) = parse_http_200($r);
		$xml_str = decode_base64(uri_unescape($saml_base64));
	} else {
		return $r;
	}

	my @cookies = $r =~ /Set-Cookie: (.*?);/g;
	$result{Cookie} = join '; ', @cookies;

	my $xml_obj = parse_xml_string($xml_str);
	my $xpc = initialize_saml_xpath_context($xml_obj);

	extract_saml_attributes(\%result, $xml_obj, $xpc, $dest, $relay_state);

	return \%result;
}

sub parse_http_302 {
	my ($r) = @_;
	my ($dest) = $r =~ /Location: (.*?)\n/;
	my ($saml_base64) = $r =~ m{(?:SAMLResponse|SAMLRequest)=([^&]+)};
	my ($relay_state) = $r =~ m{RelayState=([^&\r\n]+)};
	return ($dest, $saml_base64, $relay_state);
}

sub parse_http_200 {
	my ($r) = @_;
	my ($dest) = $r =~ /<form method="post" action="(.*?)">/;
	my ($saml_base64) = $r =~ 
		/name="(?:SAMLResponse|SAMLRequest)" value="(.*?)"/;
	my ($relay_state) = $r =~ /name="RelayState" value="(.*?)"/;
	return ($dest, $saml_base64, $relay_state);
}

sub inflate_base64 {
	my ($saml_base64) = @_;
	my $deflated = decode_base64(uri_unescape($saml_base64));
	my $xml_str;
	rawinflate(\$deflated => \$xml_str) 
		or die "rawinflate failed: $RawInflateError\n";
	return $xml_str;
}

sub extract_saml_attributes {
	my ($result, $xml_obj, $xpc, $dest, $relay_state) = @_;
	my $hdr = $xml_obj->documentElement();

	foreach my $attr (qw(Version ID IssueInstant Destination ProtocolBinding
						 AssertionConsumerServiceURL ForceAuthn)) {
		$result->{$attr} = $hdr->getAttribute($attr);
	}

	$result->{Type} = $hdr->localname;
	$result->{Action} = $dest;
	$result->{RelayState} = $relay_state;
	$result->{Issuer} = get_node_text($xpc, '//saml:Issuer');
	$result->{NameID} = get_node_text($xpc, '//saml:NameID');

	my ($signature_node) = $xpc->findnodes('//ds:Signature');
	if ($signature_node) {
		$result->{isValid} = 
			verify_saml_signature($signature_node,$sp_pub);
	} else {
		$result->{isSigned} = 0;
	}

	my ($name_id_policy_node) = $xpc->findnodes('//samlp:NameIDPolicy');
	if ($name_id_policy_node) {
		$result->{NameIDPolicyFormat} = 
			$name_id_policy_node->getAttribute('Format');
	}

	my ($status_code) = $xpc->findnodes('//samlp:StatusCode');
	if ($status_code) {
		$result->{StatusCode} = $status_code->getAttribute('Value');
	}
}

sub get_node_text {
	my ($xpc, $xpath) = @_;
	my ($node) = $xpc->findnodes($xpath);
	return $node ? $node->textContent : undef;
}

sub produce_saml {
	my ($type, $cfg, $in_resp_to) = @_;

	my $xml_obj = parse_xml_string(gen_tmpl($type));
	my $xpc = initialize_saml_xpath_context($xml_obj);
	my $msg = $xml_obj->documentElement();

	my ($ptime, $ftime) = get_time();

	# Header processing
	my $new_id = '_nginx_' . rand(1);
	$msg->setAttribute('ID', $new_id);
	$msg->setAttribute('IssueInstant', $ptime);


	if (defined $in_resp_to) {
		$msg->setAttribute('InResponseTo', $in_resp_to);
	} else {
		$msg->removeAttribute('InResponseTo');
	}

	# Issuer processing
	my (@issuer_element) = $xpc->findnodes('//saml:Issuer');
	foreach my $issuer (@issuer_element) {
		$issuer->removeChildNodes();
		$issuer->appendText($cfg->{saml_idp_entity_id});
	}

	my (@signature_element) = $xpc->findnodes('//ds:Signature');

	if ($type eq 'Response') {
		$msg->setAttribute('Destination', $cfg->{saml_sp_acs_url});

		# Assertion processing
		my ($assertion_element) = $xpc->findnodes('//saml:Assertion');
		$assertion_element->setAttribute('IssueInstant', $ptime);

		# Subject processing
		my ($nameid_element) = $xpc->findnodes('//saml:NameID');
		$nameid_element->setAttribute('SPNameQualifier',
			$cfg->{saml_sp_entity_id});

		# Conditions processing
		my ($conditions_element) = $xpc->findnodes('//saml:Conditions');
		$conditions_element->setAttribute('NotBefore', $ptime);
		$conditions_element->setAttribute('NotOnOrAfter', $ftime);
		my ($audience_element) = $xpc->findnodes('//saml:Audience');
		$audience_element->removeChildNodes();
		$audience_element->appendText($cfg->{saml_sp_entity_id});

		# AuthnStatement processing
		my ($authn_statement_element) =
			$xpc->findnodes('//saml:AuthnStatement');
		$authn_statement_element->setAttribute('AuthnInstant', $ptime);
		$authn_statement_element->setAttribute('SessionNotOnOrAfter', $ftime);

		# Signature processing
		if ($cfg->{saml_sp_want_signed_assertion} eq 'true') {
			digest_saml($signature_element[1], true);
			signature_saml($signature_element[1], $idp_priv, true);
		} else {
			$signature_element[1]->parentNode->
				removeChild($signature_element[1]);
		}

		if ($cfg->{saml_sp_want_signed_response} eq 'true') {
			digest_saml($signature_element[0], true);
			signature_saml($signature_element[0], $idp_priv, true);
		} else {
			$signature_element[0]->parentNode->
				removeChild($signature_element[0]);
		}
	} elsif ($type eq 'LogoutResponse') {
		$msg->setAttribute('Destination', $cfg->{saml_sp_slo_url});

		# Status processing
		my ($status_code_element) = $xpc->findnodes('//samlp:StatusCode');
		$status_code_element->setAttribute('Value',
			'urn:oasis:names:tc:SAML:2.0:status:Success');

		# Signature processing
		if ($cfg->{saml_sp_want_signed_slo} eq 'true') {
			digest_saml($signature_element[0], true);
			signature_saml($signature_element[0], $idp_priv, true);
		} else {
			$signature_element[0]->parentNode->
				removeChild($signature_element[0]);
		}
	} elsif ($type eq 'LogoutRequest') {
		$msg->setAttribute('Destination', $cfg->{saml_sp_slo_url});

		# Subject processing
		my ($nameid_element) = $xpc->findnodes('//saml:NameID');
		$nameid_element->setAttribute('SPNameQualifier',
			$cfg->{saml_idp_entity_id});

		# Signature processing
		if ($cfg->{saml_sp_want_signed_slo} eq 'true') {
			digest_saml($signature_element[0], true);
			signature_saml($signature_element[0], $idp_priv, true);
		} else {
			$signature_element[0]->parentNode->
				removeChild($signature_element[0]);
		}
	} else {
		die "Unknown SAML message type: $type";
	}

	return $xml_obj;
}

sub send_saml {
	my ($xml_obj, $dst, %extra) = @_;
	my ($r, $b64);

	$dst //= $acs;

	$XML::LibXML::skipXMLDeclaration = 1;
	my $xml_str = $xml_obj->toString();

	if (exists($extra{method}) && $extra{method} eq 'get') {
		my $compressed_xml;
		rawdeflate(\$xml_str => \$compressed_xml)
			or die "rawdeflate failed: $RawDeflateError\n";
		$b64 = encode_base64($compressed_xml, '');
		my $url = $dst . "?SAMLResponse=" . uri_escape($b64) .
			($extra{relay_state} ? "&RelayState=" . $extra{relay_state} : "");
		$r = get($url, %extra);
	} else {
		$b64 = encode_base64($xml_str, '');
		my $body = "SAMLResponse=" . uri_escape($b64) .
			($extra{relay_state} ? "&RelayState=" . $extra{relay_state} : "");
		$r = http_post($dst, $body, %extra);
	}

	return $r;
}

sub cfg_post {
	my ($arg, $post, $host) = @_;
	$host //= 'sp.example.com';
	my $json;

	if (ref $arg eq 'HASH') {
		$json = $arg;
	} elsif (!ref $arg) {
		my ($key, $value) = each %{decode_json($arg)};
		$cfg->{$key} = $value;
		$json = {$key => $value};
	} else {
		die "Invalid arguments for cfg_post";
	}

	for my $key (keys %$json) {
		my $value = $json->{$key};
		my $data = { $host => $value };
		my $data_string = encode_json($data);

		if ($post) {
			http_post("$kv/$key", $data_string);
		} else {
			http_patch("$kv/$key", $data_string);
		}
	}
}

sub cfg_verify {
	my ($param, $test_name) = @_;

	my $url = "$kv/$param";
	my $original_value = getkv($url);

	http_patch($url, '{"sp.example.com": ""}');
	my $r = get('/login');
	http_patch($url, $original_value);

	like($r, qr/(?=.*Invalid)(?=.*$param)/s, $test_name);

	return $r;
}

sub http_post {
	my ($url, $body, %extra) = @_;
	my $len = length($body);

	my $auth_token = $extra{auth_token} || '';
	my $auth_redir = $extra{auth_redir} || '';

	http(<<EOF);
POST $url HTTP/1.0
Host: sp.example.com
Content-Length: $len
Cookie: auth_token=$auth_token
Cookie: auth_redir=$auth_redir
Content-Type: application/x-www-form-urlencoded

$body
EOF
}

sub http_patch {
	my ($url, $body) = @_;
	my $len = length($body);

	http(<<EOF);
PATCH $url HTTP/1.1
Host: sp.example.com
Connection: close
Content-Length: $len

$body
EOF
}

sub get {
	my ($uri, %extra) = @_;

	my $auth_token = $extra{auth_token} || '';

	http(<<EOF);
GET $uri HTTP/1.0
Host: sp.example.com
Cookie: auth_token=$auth_token

EOF
}

sub recode {
	my $json = JSON::PP::decode_json(shift);
	JSON::PP->new()->canonical()->encode($json);
}

sub getkv {
	my ($uri) = @_;

	get($uri) =~ /\x0d\x0a?\x0d\x0a?(.*)/ms;
	recode($1);
}

sub api {
	my ($uri, %extra) = @_;

	$uri = defined $uri ? "/api/$api_version$uri" : '/api';
	my ($body) = http_get($uri, %extra) =~ /.*?\x0d\x0a?\x0d\x0a?(.*)/ms;

	return decode_json($body);
}

sub validate_saml_signature {
	my ($xmlDoc, $public_key_pem) = @_;

	my $xpc = XML::LibXML::XPathContext->new($xmlDoc);
	$xpc->registerNs('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
	$xpc->registerNs('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');
	$xpc->registerNs('ds', 'http://www.w3.org/2000/09/xmldsig#');

	my ($signature_node) = $xpc->findnodes('//ds:Signature');
	return 0 unless $signature_node;

	my ($signed_info_node) = $xpc->findnodes('./ds:SignedInfo',
		$signature_node);
	my ($signature_method_node) = $xpc->findnodes('./ds:SignatureMethod',
		$signed_info_node);
	my $signature_algorithm = $signature_method_node->
		getAttribute('Algorithm');

	my $hash_alg;
	if ($signature_algorithm eq 'http://www.w3.org/2000/09/xmldsig#rsa-sha1') {
		$hash_alg = 'SHA1';
	} elsif ($signature_algorithm eq 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256') {
		$hash_alg = 'SHA256';
	} elsif ($signature_algorithm eq 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384') {
		$hash_alg = 'SHA384';
	} elsif ($signature_algorithm eq 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512') {
		$hash_alg = 'SHA512';
	} else {
		die "Unsupported signature algorithm: $signature_algorithm";
	}

	my ($signature_value_node) = 
		$xpc->findnodes('./ds:SignatureValue', $signature_node);
	my $signature_value_base64 = $signature_value_node->textContent;
	my $signature_value = decode_base64($signature_value_base64);

	my ($reference_node) = 
		$xpc->findnodes('./ds:Reference', $signed_info_node);
	my $id_attr = $reference_node->getAttribute('URI');
	$id_attr =~ s/^#//;

	my $signed_element =
		$xpc->findnodes(sprintf('//*[@ID="%s"]', $id_attr))->[0];
	my $signed_info_c14n = $signed_info_node->toStringEC14N();

	$signature_node->parentNode->removeChild($signature_node);
	my $c14n_xml = $signed_element->toStringEC14N();

	my $pubkey =
		Crypt::OpenSSL::X509->new_from_string($public_key_pem)->pubkey();
	my $rsa_pub = Crypt::OpenSSL::RSA->new_public_key($pubkey);
	$rsa_pub -> use_pkcs1_padding();

	my $digest;
	if ($hash_alg eq 'SHA1') {
		$digest = sha1($c14n_xml);
		$rsa_pub->use_sha1_hash();
	} elsif ($hash_alg eq 'SHA256') {
		$digest = sha256($c14n_xml);
		$rsa_pub->use_sha256_hash();
	} elsif ($hash_alg eq 'SHA384') {
		$digest = sha384($c14n_xml);
		$rsa_pub->use_sha384_hash();
	} elsif ($hash_alg eq 'SHA512') {
		$digest = sha512($c14n_xml);
		$rsa_pub->use_sha512_hash();
	}

	my $is_valid;

	$is_valid = $rsa_pub->verify($signed_info_c14n, $signature_value);

	return $is_valid;
}

sub verify_saml_signature {
	my ($root, $public_key_pem) = @_;

	my $signature_result = signature_saml($root, $public_key_pem);
	my $digest_result = digest_saml($root);

	return $digest_result && $signature_result;
}

sub get_hash_algorithm {
	my ($url) = @_;

	my %alg_map = (
		'http://www.w3.org/2000/09/xmldsig#sha1' => 'SHA1',
		'http://www.w3.org/2001/04/xmlenc#sha256' => 'SHA256',
		'http://www.w3.org/2001/04/xmlenc#sha384' => 'SHA384',
		'http://www.w3.org/2001/04/xmlenc#sha512' => 'SHA512',
		'http://www.w3.org/2000/09/xmldsig#rsa-sha1' => 'SHA1',
		'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' => 'SHA256',
		'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384' => 'SHA384',
		'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512' => 'SHA512',
	);

	return $alg_map{$url} || die "Unsupported algorithm: $url";
}

sub digest_saml {
	my ($signature_node, $produce) = @_;

	my $xpc = XML::LibXML::XPathContext->new($signature_node);
	$xpc->registerNs('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
	$xpc->registerNs('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');
	$xpc->registerNs('ds', 'http://www.w3.org/2000/09/xmldsig#');

	my $parent_node = $signature_node->parentNode;
	
	my ($signed_info_node) =
		$xpc->findnodes('./ds:SignedInfo', $signature_node)->[0];
	my ($reference_node) =
		$xpc->findnodes('./ds:Reference', $signed_info_node)->[0];

	my $id = $parent_node->getAttribute('ID');
	$reference_node->setAttribute('URI', "#$id");

	my @transforms =
		$xpc->findnodes('./ds:Transforms/ds:Transform', $reference_node);
	my @transform_algs = map { $_->getAttribute('Algorithm') } @transforms;

	my $with_comments = ($transform_algs[1] =~ /WithComments/);

	my $digest_method =
		$xpc->findnodes('./ds:DigestMethod', $reference_node)->[0];
	my $alg = $digest_method->getAttribute('Algorithm');

	my $hash = get_hash_algorithm($alg);

	my $next_sibling = $signature_node->nextSibling();
	$signature_node->unbindNode();
	my $parent_node_c14n = $parent_node->toStringEC14N($with_comments);
	$parent_node->insertBefore($signature_node, $next_sibling);

	my %hash_func_map = (
		'SHA1' => sub { return sha1($_[0]); },
		'SHA256' => sub { return sha256($_[0]); },
		'SHA384' => sub { return sha384($_[0]); },
		'SHA512' => sub { return sha512($_[0]); },
	);

	my $digest;
	if (exists $hash_func_map{$hash}) {
		$digest = $hash_func_map{$hash}->($parent_node_c14n);
	} else {
		die "Unsupported hash algorithm: $hash";
	}

	my $b64_digest = encode_base64($digest, '');

	my ($digest_value_node) =
		$xpc->findnodes('./ds:DigestValue', $reference_node);

	if ($produce) {
		$digest_value_node->removeChildNodes();
		$digest_value_node->appendText($b64_digest);
		return;
	}

	my $expected_digest = $digest_value_node->textContent();

	return $expected_digest eq $b64_digest;
}

sub signature_saml {
	my ($signature_node, $key_data, $produce) = @_;

	my $xpc = XML::LibXML::XPathContext->new($signature_node);
	$xpc->registerNs('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
	$xpc->registerNs('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');
	$xpc->registerNs('ds', 'http://www.w3.org/2000/09/xmldsig#');

	my ($signature_value_node) =
		$xpc->findnodes('./ds:SignatureValue', $signature_node);
	my $signature_value_base64 = $signature_value_node->textContent;
	my $signature_value = decode_base64($signature_value_base64);

	my ($signed_info_node) =
		$xpc->findnodes('./ds:SignedInfo', $signature_node);
	my ($signature_method_node) =
		$xpc->findnodes('./ds:SignatureMethod', $signed_info_node);
	my $alg = $signature_method_node->getAttribute('Algorithm');

	my $hash_alg = get_hash_algorithm($alg);

	my $canonicalization_method = $xpc->findnodes('./ds:CanonicalizationMethod',
		$signed_info_node)->[0]->getAttribute('Algorithm');
	my $with_comments = ($canonicalization_method =~ /WithComments/);

	my $signed_info_c14n = $signed_info_node->toStringEC14N($with_comments);

	my $rsa = $produce ? Crypt::OpenSSL::RSA->new_private_key($key_data)
		: Crypt::OpenSSL::RSA->new_public_key(
			Crypt::OpenSSL::X509->new_from_string($key_data)->pubkey()
		);

	$rsa->use_pkcs1_padding();

	my %hash_func_map = (
		'SHA1' => sub { $_[0]->use_sha1_hash(); },
		'SHA256' => sub { $_[0]->use_sha256_hash(); },
		'SHA384' => sub { $_[0]->use_sha384_hash(); },
		'SHA512' => sub { $_[0]->use_sha512_hash(); },
	);

	if (exists $hash_func_map{$hash_alg}) {
		$hash_func_map{$hash_alg}->($rsa);
	} else {
		die "Unsupported hash algorithm: $hash_alg";
	}

	my $result;
	if ($produce) {
		my $signature_value = $rsa->sign($signed_info_c14n);
		my $b64_signature_value = encode_base64($signature_value, '');

		my ($signature_value_node) =
			$xpc->findnodes('./ds:SignatureValue', $signature_node);
		$signature_value_node->removeChildNodes();
		$signature_value_node->appendText($b64_signature_value);

		$result = $signature_value_node;
	} else {
		$result = $rsa->verify($signed_info_c14n, $signature_value);
	}

	return $result;

}

sub get_time {
	my $now = DateTime->now;
	my $past_time = $now->clone->subtract(minutes => 5)->strftime('%FT%TZ');
	my $future_time = $now->add(minutes => 5)->strftime('%FT%TZ');

	return ($past_time, $future_time);
}

sub is_issue_instant_valid {
	my $issue_instant = shift;

	if ($issue_instant =~ /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?Z$/) {
		my ($year, $month, $day, $hour, $minute, $second) = ($1, $2, $3, $4, $5, $6);

		my $issue_instant_dt = DateTime->new(
			year   => $year,
			month  => $month,
			day    => $day,
			hour   => $hour,
			minute => $minute,
			second => $second,
			time_zone => 'UTC',
		);

		my $current_time = DateTime->now(time_zone => 'UTC');
		my $min_time = $current_time->clone->subtract(seconds => 5);
		my $max_time = $current_time->clone->add(seconds => 5);

		return ($issue_instant_dt >= $min_time) && ($issue_instant_dt <= $max_time);
	}

	return 0;
}

sub read_file {
	my ($files) = @_;
	my $content = '';

	$files = [$files] unless ref $files eq 'ARRAY';

	for my $file (@$files) {
		local $/;
		open my $fh, '<', $file or die "Failed to open $file: $!";
		my $c = <$fh>;
		close $fh;
		$content .= $c;
	}

	return $content;
}

sub gen_tmpl {
	my ($type) = @_;

	my $signature = <<'END_XML';
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
	<ds:SignedInfo>
		<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
		<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
		<ds:Reference URI="#${id}">
			<ds:Transforms>
				<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
				<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
			</ds:Transforms>
			<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
			<ds:DigestValue></ds:DigestValue>
		</ds:Reference>
	</ds:SignedInfo>
	<ds:SignatureValue></ds:SignatureValue>
</ds:Signature>
END_XML

	my $response = <<END_XML;
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
				xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
				ID=""
				Version="2.0"
				IssueInstant=""
				Destination=""
				InResponseTo=""
				>
	<saml:Issuer></saml:Issuer>
	$signature
	<samlp:Status>
		<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
	</samlp:Status>
	<saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
					xmlns:xs="http://www.w3.org/2001/XMLSchema"
					ID="_nginx_assertion"
					Version="2.0"
					IssueInstant=""
					>
		<saml:Issuer></saml:Issuer>
		$signature
		<saml:Subject>
			<saml:NameID SPNameQualifier=""
						Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
						>user1</saml:NameID>
			<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
				<saml:SubjectConfirmationData NotOnOrAfter=""
											Recipient=""
											InResponseTo=""
											/>
			</saml:SubjectConfirmation>
		</saml:Subject>
		<saml:Conditions NotBefore=""
						NotOnOrAfter=""
						>
			<saml:AudienceRestriction>
				<saml:Audience></saml:Audience>
			</saml:AudienceRestriction>
		</saml:Conditions>
		<saml:AuthnStatement AuthnInstant=""
							SessionNotOnOrAfter=""
							SessionIndex="_nginx_sessionindex_"
							>
			<saml:AuthnContext>
				<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
			</saml:AuthnContext>
		</saml:AuthnStatement>
		<saml:AttributeStatement>
			<saml:Attribute Name="uid"
							NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
							>
				<saml:AttributeValue xsi:type="xs:string">1</saml:AttributeValue>
			</saml:Attribute>
			<saml:Attribute Name="memberOf"
							NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
							>
				<saml:AttributeValue xsi:type="xs:string">group1, admins, students</saml:AttributeValue>
			</saml:Attribute>
			<saml:Attribute Name="email"
							NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
							>
				<saml:AttributeValue xsi:type="xs:string">user1</saml:AttributeValue>
			</saml:Attribute>
			<saml:Attribute Name="name"
							NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
							>
				<saml:AttributeValue xsi:type="xs:string">Alan Alda</saml:AttributeValue>
			</saml:Attribute>
			<saml:Attribute Name="telephoneNumber"
							NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
							>
				<saml:AttributeValue xsi:type="xs:string">+31(0)12345678</saml:AttributeValue>
			</saml:Attribute>
			<saml:Attribute Name="http://schemas.example.com/identity/claims/foo"
							>
				<saml:AttributeValue xsi:type="xs:string">bar</saml:AttributeValue>
			</saml:Attribute>
		</saml:AttributeStatement>
	</saml:Assertion>
</samlp:Response>
END_XML

	my $logout_request = <<END_XML;
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
					 xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
					 ID=""
					 Version="2.0"
					 IssueInstant=""
					 Destination=""
					 NotOnOrAfter=""
					 >
	<saml:Issuer></saml:Issuer>
	$signature
	<saml:NameID SPNameQualifier=""
				 Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
				 >user1</saml:NameID>
	<samlp:SessionIndex>_nginx_sessionindex</samlp:SessionIndex>
</samlp:LogoutRequest>
END_XML

my $logout_response = <<END_XML;
<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
					  Destination=""
					  ID=""
					  InResponseTo=""
					  IssueInstant=""
					  Version="2.0"
					  >
	<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"></saml:Issuer>
	$signature
	<samlp:Status>
		<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
	</samlp:Status>
</samlp:LogoutResponse>
END_XML
	
	if ($type eq 'Response') {
		return $response;
	} elsif ($type eq 'LogoutRequest') {
		return $logout_request;
	} elsif ($type eq 'LogoutResponse') {
		return $logout_response;
	} else {
		die "unknown type: $type";
	}
}

###############################################################################
