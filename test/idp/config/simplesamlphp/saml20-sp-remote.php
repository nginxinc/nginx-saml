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
    1 => 
    array (
      'Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
      'Location' => 'http://sp.route443.dev/saml/sls',
      'ResponseLocation' => 'http://sp.route443.dev/saml/sls',
    ),
  ),
  'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
  'keys' => 
  array (
    0 => 
    array (
      'encryption' => false,
      'signing' => true,
      'type' => 'X509Certificate',
      'X509Certificate' => 'MIIERTCCAy2gAwIBAgIBAjANBgkqhkiG9w0BAQsFADBCMRMwEQYDVQQDEwpuZ2lueC1zYW1sMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExETAPBgNVBAcTCFNhbiBKb3NlMB4XDTIzMDEyNjA1NTkzMloXDTMzMDEyMzA1NTkzMlowSTEaMBgGA1UEAxMRc2lnbi5yb3V0ZTQ0My5kZXYxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTERMA8GA1UEBxMIU2FuIEpvc2UwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDBBf0jHxvbZtHfwneJF94ga0XQkw7InHgrqD+RQW0wQ/Xlz54f+31MsBzz+ZmDA5IlVWYHhf+CZz5WFT0lstKHM6P52SdntdEqwV89KBB00e/fhs6/6JdFMlmwdyUEySYGa8gtr7GPVVmMjtQ8pryJLC8hC0DCpABoTkgzPy2YZrwlE3L4bejsttSUwAsM+TIgoe0emuoYza7ezB4ba4WBFo7noUiEZub7wrbDLdpaTzl5q0aHkRRfSHy0PQ5NGlp0H8DyeHKWjHSR9Om8XMSrKU1PAprF+Tf0S9MF2oLfDxP2AEWpmyC1joC2a8TbTGkTey/SxsuNW665Iv07BC23AgMBAAGjggE9MIIBOTAJBgNVHRMEAjAAMBEGCWCGSAGG+EIBAQQEAwIGQDALBgNVHQ8EBAMCBaAwMwYJYIZIAYb4QgENBCYWJE9wZW5TU0wgR2VuZXJhdGVkIFNlcnZlciBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQUGSHB6+BPP91/Ay882eOAcRVlIM4wcQYDVR0jBGowaIAUDQkhYVuQSYaVvbv9SY/FlgDJNY+hRqREMEIxEzARBgNVBAMTCm5naW54LXNhbWwxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTERMA8GA1UEBxMIU2FuIEpvc2WCCHd1u0LHIQCyMCcGA1UdJQQgMB4GCCsGAQUFBwMBBggrBgEFBQcDAgYIKwYBBQUIAgIwHAYDVR0RBBUwE4IRc2lnbi5yb3V0ZTQ0My5kZXYwDQYJKoZIhvcNAQELBQADggEBAG8ZGiea/rpI5ZWmptr5pcAKAym5VNENWBZ7YnJVEuYUhjCgZSQvt498D5zCHUZtiuxkbOV8xEvUunPtFfx5s+nKolJndBPSbxy3LvYI2SDHtGYRi5iJ38SpNIy1lV1In4OkKUKxJrl6SnTQoy2w+m4GbDWl6xgDLKMDJccJZ1tgtlKF29BYX9lv20ev0d1qESCoz9ovC1oOW2XUETl03WYPa2mIQnOaDswzLhS/psTUDeoMYcRGRMyaKrzl6zuw+G3IHQbgh/hCe77AXf8BFC8g2hmte7k4TGM1K3VggmB6TdqmmMyS9yW9bz8C3oM5Wdaa43fMYVeGxNeVjfcFbWI=',
    ),
  ),
  'validate.authnrequest' => true,
  'saml20.sign.assertion' => true,
);