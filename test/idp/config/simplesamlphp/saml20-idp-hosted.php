<?php
/**
 * SAML 2.0 IdP configuration for SimpleSAMLphp.
 *
 * See: https://simplesamlphp.org/docs/stable/simplesamlphp-reference-idp-hosted
 */

$metadata['__DYNAMIC:1__'] = [
    /*
     * The hostname of the server (VHOST) that will use this SAML entity.
     *
     * Can be '__DEFAULT__', to use this entry by default.
     */
    'host' => '__DEFAULT__',

    // X.509 key and certificate. Relative to the cert directory.
    'privatekey' => 'saml.key',
    'certificate' => 'saml.pem',

    /*
     * Authentication source to use. Must be one that is configured in
     * 'config/authsources.php'.
     */
    'auth' => 'example-userpass',
    'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    'simplesaml.nameidattribute' => 'email',
    'userid.attribute' => 'email',
    'SingleSignOnServiceBinding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
    'SingleLogoutServiceBinding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    'signature.algorithm' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    'assertion.encryption' => FALSE,
    'nameid.encryption' => FALSE,
    'saml20.sign.response' => TRUE,
    'saml20.sign.assertion' => FALSE,
    'sign.logout' => FALSE,
    'validate.authnrequest' => TRUE,
    'validate.logout' => FALSE,

    'OrganizationName' => [
        'en' => 'NGINX SAML',
        'ru' => 'энджин-икс самл',
    ],
    'OrganizationURL' => [
        'en' => 'https://example.org',
        'ru' => 'https://example.ru',
    ],
    /* Uncomment the following to use the uri NameFormat on attributes. */
    /*
    'attributes.NameFormat' => 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
    'authproc' => [
        // Convert LDAP names to oids.
        100 => ['class' => 'core:AttributeMap', 'name2oid'],
    ],
    */

    /*
     * Uncomment the following to specify the registration information in the
     * exported metadata. Refer to:
     * http://docs.oasis-open.org/security/saml/Post2.0/saml-metadata-rpi/v1.0/cs01/saml-metadata-rpi-v1.0-cs01.html
     * for more information.
     */
    /*
    'RegistrationInfo' => [
        'authority' => 'urn:mace:example.org',
        'instant' => '2008-01-17T11:28:03Z',
        'policies' => [
            'en' => 'http://example.org/policy',
            'es' => 'http://example.org/politica',
        ],
    ],
    */
];

$metadata['https://idp.route443.dev/ssopost-sas0-vauthn0-eas0-eni0/'] = array(
    'host' => '__DEFAULT__',
    'privatekey' => 'saml.key',
    'certificate' => 'saml.pem',
    'auth' => 'example-userpass',
    'userid.attribute' => 'email',
    'SingleSignOnServiceBinding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
    'SingleLogoutServiceBinding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    'signature.algorithm' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
    'assertion.encryption' => FALSE,
    'nameid.encryption' => FALSE,
    'saml20.sign.response' => FALSE,
    'saml20.sign.assertion' => FALSE,
    'sign.logout' => FALSE,
    'validate.authnrequest' => FALSE,
    'validate.logout' => FALSE,
);

$metadata['https://idp.route443.dev/ssopost-sas0-vauthn1-eas0-eni0/'] = array(
    'host' => '__DEFAULT__',
    'privatekey' => 'saml.key',
    'certificate' => 'saml.pem',
    'auth' => 'example-userpass',
    'userid.attribute' => 'email',
    'SingleSignOnServiceBinding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
    'SingleLogoutServiceBinding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    'signature.algorithm' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
    'assertion.encryption' => FALSE,
    'nameid.encryption' => FALSE,
    'saml20.sign.response' => FALSE,
    'saml20.sign.assertion' => FALSE,
    'sign.logout' => FALSE,
    'validate.authnrequest' => TRUE,
    'validate.logout' => FALSE,
);

$metadata['https://idp.route443.dev/ssopost-sas1-vauthn1-eas0-eni0/'] = array(
    'host' => '__DEFAULT__',
    'privatekey' => 'saml.key',
    'certificate' => 'saml.pem',
    'auth' => 'example-userpass',
    'userid.attribute' => 'email',
    'SingleSignOnServiceBinding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
    'SingleLogoutServiceBinding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    'signature.algorithm' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
    'assertion.encryption' => FALSE,
    'nameid.encryption' => FALSE,
    'saml20.sign.response' => TRUE,
    'saml20.sign.assertion' => TRUE,
    'sign.logout' => FALSE,
    'validate.authnrequest' => TRUE,
    'validate.logout' => FALSE,
);

$metadata['https://idp.route443.dev/ssopost-sas1-vauthn1-eas1-eni0/'] = array(
    'host' => '__DEFAULT__',
    'privatekey' => 'saml.key',
    'certificate' => 'saml.pem',
    'auth' => 'example-userpass',
    'userid.attribute' => 'email',
    'SingleSignOnServiceBinding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
    'SingleLogoutServiceBinding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    'signature.algorithm' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
    'assertion.encryption' => TRUE,
    'nameid.encryption' => FALSE,
    'saml20.sign.response' => TRUE,
    'saml20.sign.assertion' => TRUE,
    'sign.logout' => FALSE,
    'validate.authnrequest' => TRUE,
    'validate.logout' => FALSE,
);

$metadata['https://idp.route443.dev/ssoredir-sas1-vauthn1-eas0-eni0/'] = array(
    'host' => '__DEFAULT__',
    'privatekey' => 'saml.key',
    'certificate' => 'saml.pem',
    'auth' => 'example-userpass',
    'userid.attribute' => 'email',
    'SingleSignOnServiceBinding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    'SingleLogoutServiceBinding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    'signature.algorithm' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
    'assertion.encryption' => FALSE,
    'nameid.encryption' => FALSE,
    'saml20.sign.response' => TRUE,
    'saml20.sign.assertion' => TRUE,
    'sign.logout' => FALSE,
    'validate.authnrequest' => TRUE,
    'validate.logout' => FALSE,
);

$metadata['https://idp.route443.dev/ssoredir-sas1-vauthn1-eas1-eni0/'] = array(
    'host' => '__DEFAULT__',
    'privatekey' => 'saml.key',
    'certificate' => 'saml.pem',
    'auth' => 'example-userpass',
    'userid.attribute' => 'email',
    'SingleSignOnServiceBinding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    'SingleLogoutServiceBinding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    'signature.algorithm' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
    'assertion.encryption' => TRUE,
    'nameid.encryption' => FALSE,
    'saml20.sign.response' => TRUE,
    'saml20.sign.assertion' => TRUE,
    'sign.logout' => FALSE,
    'validate.authnrequest' => TRUE,
    'validate.logout' => FALSE,
);

$metadata['https://idp.route443.dev/ssopost-art-sas1-vauthn1-eas1-eni0/'] = array(
    'host' => '__DEFAULT__',
    'privatekey' => 'saml.key',
    'certificate' => 'saml.pem',
    'auth' => 'example-userpass',
    'userid.attribute' => 'email',
    'SingleSignOnServiceBinding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
    'SingleLogoutServiceBinding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    'signature.algorithm' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
    'assertion.encryption' => TRUE,
    'nameid.encryption' => FALSE,
    'saml20.sign.response' => TRUE,
    'saml20.sign.assertion' => TRUE,
    'sign.logout' => FALSE,
    'validate.authnrequest' => TRUE,
    'validate.logout' => FALSE,
    'saml20.sendartifact' => TRUE,
);

$metadata['https://idp.route443.dev/ssopost-art-sas1-vauthn1-eas1-eni1/'] = array(
    'host' => '__DEFAULT__',
    'privatekey' => 'saml.key',
    'certificate' => 'saml.pem',
    'auth' => 'example-userpass',
    'userid.attribute' => 'email',
    'SingleSignOnServiceBinding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
    'SingleLogoutServiceBinding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    'signature.algorithm' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
    'assertion.encryption' => TRUE,
    'nameid.encryption' => TRUE,
    'saml20.sign.response' => TRUE,
    'saml20.sign.assertion' => TRUE,
    'sign.logout' => FALSE,
    'validate.authnrequest' => TRUE,
    'validate.logout' => FALSE,
    'saml20.sendartifact' => TRUE,
);

$metadata['https://idp.route443.dev/ssopost-sas1-vauthn1-sha256/'] = array(
    'host' => '__DEFAULT__',
    'privatekey' => 'saml.key',
    'certificate' => 'saml.pem',
    'auth' => 'example-userpass',
    'userid.attribute' => 'email',
    'SingleSignOnServiceBinding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
    'SingleLogoutServiceBinding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    'signature.algorithm' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    'assertion.encryption' => FALSE,
    'nameid.encryption' => FALSE,
    'saml20.sign.response' => TRUE,
    'saml20.sign.assertion' => TRUE,
    'sign.logout' => FALSE,
    'validate.authnrequest' => TRUE,
    'validate.logout' => FALSE,
);

$metadata['https://idp.route443.dev/ssopost-sas1-vauthn1-sha384/'] = array(
    'host' => '__DEFAULT__',
    'privatekey' => 'saml.key',
    'certificate' => 'saml.pem',
    'auth' => 'example-userpass',
    'userid.attribute' => 'email',
    'SingleSignOnServiceBinding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
    'SingleLogoutServiceBinding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    'signature.algorithm' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384',
    'assertion.encryption' => FALSE,
    'nameid.encryption' => FALSE,
    'saml20.sign.response' => TRUE,
    'saml20.sign.assertion' => TRUE,
    'sign.logout' => FALSE,
    'validate.authnrequest' => TRUE,
    'validate.logout' => FALSE,
);

$metadata['https://idp.route443.dev/ssopost-sas1-vauthn1-sha512/'] = array(
    'host' => '__DEFAULT__',
    'privatekey' => 'saml.key',
    'certificate' => 'saml.pem',
    'auth' => 'example-userpass',
    'userid.attribute' => 'email',
    'SingleSignOnServiceBinding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
    'SingleLogoutServiceBinding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    'signature.algorithm' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
    'assertion.encryption' => FALSE,
    'nameid.encryption' => FALSE,
    'saml20.sign.response' => TRUE,
    'saml20.sign.assertion' => TRUE,
    'sign.logout' => FALSE,
    'validate.authnrequest' => TRUE,
    'validate.logout' => FALSE,
);