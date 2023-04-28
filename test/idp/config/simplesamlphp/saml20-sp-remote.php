<?php
/**
 * SAML 2.0 remote SP metadata for SimpleSAMLphp.
 *
 * See: https://simplesamlphp.org/docs/stable/simplesamlphp-reference-sp-remote
 */
$metadata[getenv('SIMPLESAMLPHP_SP_ENTITY_ID')] = array(
    'AssertionConsumerService' => getenv('SIMPLESAMLPHP_SP_ASSERTION_CONSUMER_SERVICE'),
    'SingleLogoutService' => getenv('SIMPLESAMLPHP_SP_SINGLE_LOGOUT_SERVICE'),
);

$metadata['http://sp.route443.dev'] = array (
  'entityid' => 'http://sp.route443.dev',
  'contacts' => 
  array (
  ),
  'metadata-set' => 'saml20-sp-remote',
  'AssertionConsumerService' => 
  array (
    0 => 
    array (
      'Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
      'Location' => 'http://sp.route443.dev/saml/acs',
      'index' => 0,
      'isDefault' => true,
    ),
  ),
  'SingleLogoutService' => 
  array (
    0 => 
    array (
      'Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
      'Location' => 'http://sp.route443.dev/saml/sls',
      'ResponseLocation' => 'http://sp.route443.dev/saml/sls',
    ),
  ),
  'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  'certificate' => 'saml.crt',
  'signature.privatekey' => 'saml.key',
  'SingleSignOnServiceBinding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
  'SingleLogoutServiceBinding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
  'saml20.sign.response' => TRUE,
  'saml20.sign.assertion' => TRUE,
  'sign.logout' => TRUE,
  'redirect.sign' => TRUE,
  'signature.algorithm' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
  'validate.authnrequest' => TRUE,
  'validate.logout' => TRUE,
  'assertion.encryption' => FALSE,
  'nameid.encryption' => FALSE,
);