#!/bin/bash

# In this example:

# SAML SP: vm-test.ff.lan
# SAML iDP: ubuntu.ff.lan

curl -i -X POST -H "Host: api" http://127.0.0.1/api/8/http/keyvals/keyval_saml_sp_entity_id -d '{"vm-test.ff.lan":"http://vm-test.ff.lan"}'
curl -i -X POST -H "Host: api" http://127.0.0.1/api/8/http/keyvals/keyval_saml_sp_acs_url -d '{"vm-test.ff.lan":"http://vm-test.ff.lan/saml/acs"}'
curl -i -X POST -H "Host: api" http://127.0.0.1/api/8/http/keyvals/keyval_saml_sp_slo_url -d '{"vm-test.ff.lan":"http://vm-test.ff.lan/saml/slo"}'
curl -i -X POST -H "Host: api" http://127.0.0.1/api/8/http/keyvals/keyval_saml_sp_relay_state -d '{"vm-test.ff.lan":"http://vm-test.ff.lan/landing_page"}'
curl -i -X POST -H "Host: api" http://127.0.0.1/api/8/http/keyvals/keyval_saml_sp_signing_certificate -d '{"vm-test.ff.lan":"authn_sign.crt"}'
curl -i -X POST -H "Host: api" http://127.0.0.1/api/8/http/keyvals/keyval_saml_sp_signing_key -d '{"vm-test.ff.lan":"authn_sign.key"}'
curl -i -X POST -H "Host: api" http://127.0.0.1/api/8/http/keyvals/keyval_saml_sp_force_authn -d '{"vm-test.ff.lan":"false"}'
curl -i -X POST -H "Host: api" http://127.0.0.1/api/8/http/keyvals/keyval_saml_sp_nameid_format -d '{"vm-test.ff.lan":"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"}'
curl -i -X POST -H "Host: api" http://127.0.0.1/api/8/http/keyvals/keyval_saml_sp_want_signed_assertion -d '{"vm-test.ff.lan":"true"}'
curl -i -X POST -H "Host: api" http://127.0.0.1/api/8/http/keyvals/keyval_saml_idp_entity_id -d '{"vm-test.ff.lan":"http://ubuntu.ff.lan:8080/simplesaml/saml2/idp/metadata.php"}'
curl -i -X POST -H "Host: api" http://127.0.0.1/api/8/http/keyvals/keyval_saml_idp_sso_url -d '{"vm-test.ff.lan":"http://ubuntu.ff.lan:8080/simplesaml/saml2/idp/SSOService.php"}'
curl -i -X POST -H "Host: api" http://127.0.0.1/api/8/http/keyvals/keyval_saml_idp_verification_certificate -d '{"vm-test.ff.lan":"/etc/nginx/conf/saml.spki"}'
curl -i -X POST -H "Host: api" http://127.0.0.1/api/8/http/keyvals/keyval_saml_idp_sign_authn -d '{"vm-test.ff.lan":"false"}'
curl -i -X POST -H "Host: api" http://127.0.0.1/api/8/http/keyvals/keyval_saml_idp_slo_url -d '{"vm-test.ff.lan":"http://ubuntu.ff.lan:8080/simplesaml/saml2/idp/SingleLogoutService.php"}'
curl -i -X POST -H "Host: api" http://127.0.0.1/api/8/http/keyvals/keyval_saml_sp_request_binding -d '{"vm-test.ff.lan":"HTTP-POST"}'
curl -i -X POST -H "Host: api" http://127.0.0.1/api/8/http/keyvals/keyval_saml_cookie_flags -d '{"http":"Path=/; SameSite=lax;"}'
curl -i -X POST -H "Host: api" http://127.0.0.1/api/8/http/keyvals/keyval_saml_cookie_flags -d '{"https":"Path=/; SameSite=lax; HttpOnly; Secure;"}'
