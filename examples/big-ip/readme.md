
Alright, let's go through the process of integrating NGINX Plus as a SAML Service Provider (SP) with the Big-IP APM as a SAML Identity Provider (IdP).

- [Introduction to SAML and its Implementation in NGINX Plus and Big-IP APM](#introduction-to-saml-and-its-implementation-in-nginx-plus-and-big-ip-apm)
  - [NGINX Plus as a SAML Service Provider (SP)](#nginx-plus-as-a-saml-service-provider-sp)
  - [Big-IP APM as a SAML Identity Provider (IdP)](#big-ip-apm-as-a-saml-identity-provider-idp)
- [Prerequisites for Configuring NGINX Plus as SAML SP and Big-IP APM as SAML IdP](#prerequisites-for-configuring-nginx-plus-as-saml-sp-and-big-ip-apm-as-saml-idp)
  - [For NGINX Plus](#for-nginx-plus)
  - [For Big-IP APM](#for-big-ip-apm)
- [Preparation of Certificates for SP (NGINX Plus) and IdP (Big-IP APM)](#preparation-of-certificates-for-sp-nginx-plus-and-idp-big-ip-apm)
- [Configuring Big-IP APM as a SAML Identity Provider (IdP)](#configuring-big-ip-apm-as-a-saml-identity-provider-idp)
- [Configuring NGINX Plus as a SAML SP](#configuring-nginx-plus-as-a-saml-sp)
  - [Understanding and Configuring saml\_sp\_configuration.conf](#understanding-and-configuring-saml_sp_configurationconf)
  - [Adjusting frontend.conf for Your Environment](#adjusting-frontendconf-for-your-environment)
  - [Reviewing saml\_sp.server\_conf](#reviewing-saml_spserver_conf)
- [Configuring the Key-Value Store in NGINX Plus](#configuring-the-key-value-store-in-nginx-plus)
  - [Understanding the Role of the Key-Value Store in SAML](#understanding-the-role-of-the-key-value-store-in-saml)
  - [Configuring Default Key-Value Zones](#configuring-default-key-value-zones)
  - [Adding Additional Key-Value Zones for Custom SAML Attributes](#adding-additional-key-value-zones-for-custom-saml-attributes)
- [Testing and Verifying the Configuration](#testing-and-verifying-the-configuration)
  - [SAML Flow Verification](#saml-flow-verification)
  - [Checking Logs](#checking-logs)
  - [Testing SP-initiated Logout Functionality](#testing-sp-initiated-logout-functionality)
  - [Testing IdP-initiated Logout Functionality](#testing-idp-initiated-logout-functionality)
- [Troubleshooting Common Configuration Issues](#troubleshooting-common-configuration-issues)
- [Big-IP raw config](#big-ip-raw-config)

# Introduction to SAML and its Implementation in NGINX Plus and Big-IP APM
Security Assertion Markup Language (SAML) is an open standard for exchanging authentication and authorization data between an IdP and a SP. It simplifies user management by allowing applications to delegate authentication and authorization decisions to a trusted IdP.

NGINX Plus and F5's Big-IP Access Policy Manager (APM) are both capable of utilizing SAML for user authentication, but they each play distinct roles within a SAML environment.

## NGINX Plus as a SAML Service Provider (SP)
In a SAML environment, NGINX Plus can be configured to act as a SAML SP. This allows NGINX Plus to delegate user authentication to a trusted IdP. This configuration enables a single sign-on (SSO) experience for users, as they only need to authenticate once with the IdP to access multiple services protected by NGINX Plus.

> **_Please note_** that as of now, SAML Metadata, a standard way of exchanging information between SAML entities, is not supported by NGINX Plus. Therefore, configuration must be done manually, involving a review and update of various configuration files to match your IdP's configuration.

## Big-IP APM as a SAML Identity Provider (IdP)
F5's Big-IP APM can be set up as a SAML IdP. In this role, Big-IP APM handles user authentication and provides SAML assertions to SPs, such as NGINX Plus. These assertions include information about the user, such as their username, email address, and roles.

In this guide, we will cover how to configure NGINX Plus as a SAML SP and Big-IP APM as a SAML IdP, and how these two systems can be used together to provide a seamless SSO experience for users.

In the following sections, we'll delve into the specifics of configuring these settings, starting with the prerequisites for setting up NGINX Plus as a SAML SP and Big-IP APM as a SAML IdP.

# Prerequisites for Configuring NGINX Plus as SAML SP and Big-IP APM as SAML IdP
Before you start configuring NGINX Plus as a SAML SP and Big-IP APM as a SAML IdP, there are several prerequisites to ensure that the configuration process is smooth and successful.

## For NGINX Plus
1. **NGINX Plus R29 or later**: You will need NGINX Plus R29 or a later version to support the SAML SP feature.

2. **SAML SP configuration files**: There are multiple configuration files involved in setting up NGINX Plus as a SAML SP. You will need to review and modify these files to match your IdP's configuration.

3. **A valid SSL/TLS certificate**: SSL/TLS is required for secure communication between the SP and IdP. Make sure you have a valid SSL/TLS certificate installed on your NGINX Plus server.

4. **Private key for SP**: A private key is required for the SP to sign the AuthnRequest and SingleLogout messages.

5. **Public key/certificate of IdP**: The SP needs the public key/certificate of the IdP to verify the SAML assertions.

## For Big-IP APM
**Big-IP APM version 11.0 or later**: You will need Big-IP APM version 11.0 or a later version to support the SAML IdP feature.

1. **SAML IdP configuration on Big-IP APM**: You need to properly configure the SAML IdP settings on your Big-IP APM.

2. **Authentication provider**: User accounts need to be properly configured on your Big-IP APM, including the appropriate user groups and authentication methods.

3. **Public key of SP**: The IdP needs the public key of the SP to verify SAML messages from the SP.

4. **Private key for IdP**: A private key is required for the IdP to sign SAML assertions and responses.

Once these prerequisites are met, you can move on to configuring NGINX Plus as a SAML SP and Big-IP APM as a SAML IdP. The subsequent sections of this guide will provide a detailed walkthrough of this process.

# Preparation of Certificates for SP (NGINX Plus) and IdP (Big-IP APM)

In SAML authentication, it is critical to ensure secure communication between the SP and IdP. This is achieved through the use of SSL/TLS certificates. In this context, the SP and IdP both require specific public and private keys.

Let's go over the requirements and how to generate these keys for both entities.

First, create an OpenSSL configuration file openssl.conf:

```shell
cat > openssl.conf <<EOF
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF
```

Next, generate self-signed certificates for both SP and IdP:

```shell
for name in sp.example.com idp.example.com
do
    openssl req -x509 -new -config openssl.conf -subj /CN=$name/ -out $name.crt -keyout $name.key
    openssl x509 -in $name.crt -outform DER -out $name.der
    openssl x509 -inform DER -in $name.der -pubkey -noout > $name.spki
done
```

In the above commands:

1. `openssl req -x509 -new -config openssl.conf -subj /CN=$name/ -out $name.crt -keyout $name.key` creates a new self-signed certificate and corresponding private key.

2. `openssl x509 -in $name.crt -outform DER -out $name.der` converts the certificate to DER format.

3. `openssl x509 -inform DER -in $name.der -pubkey -noout > $name.spki` extracts the public key from the DER formatted certificate.

> **_Please note_** that these keys are sensitive, and should be handled with appropriate security measures to prevent unauthorized access. Also note that for simplicity we will use the same keys for both SAML authentication and SSL/TLS layer, which is not recommended in a production environment.

Once these keys are prepared and stored appropriately, you can proceed with the configuration of NGINX Plus as SAML SP and Big-IP APM as SAML IdP.

# Configuring Big-IP APM as a SAML Identity Provider (IdP)

Big-IP APM can be configured as a SAML Identity Provider (IdP). Here are the steps to configure it:

1. **Access the Big-IP Configuration Utility**: Log into the BIG-IP system. This is typically accessed via a management web interface on the device's IP address.

2. **Uploading Certificates to Big-IP APM**:
   - Navigate to **System** -> **Certificate Management** -> **SSL Certificate List**.
   - Click on **Import**.
   - Select Certificate or Key based on the file you are uploading.
   - Choose Create **New** and provide a name for the certificate or key.
   - Browse and select the relevant `.crt` or `.key` file, i.e., `idp.example.com.crt`, `idp.example.com.key`, and `sp.example.com.crt`.
   - Click on **Import**.
   - Repeat for all files.

3. **Navigate to the SAML Configuration Section**: On the left tab, click **Access** -> **Federation** -> **SAML Identity Provider** -> **Local IdP Services**.

4. **Create a New Local IdP Service**: Click **Create**. On the new page, fill in the fields as follows:
   - **IdP Service Name**: Enter a name for the Local IdP service.
   - **IdP Entity ID**: This is a URI that uniquely identifies the SAML IdP. It can be any string, but a URL is typically used, such as `https://idp.example.com/saml-idp`.
   - **Assertion Settings**. Choose the SAML Assertion subject type and value. Assertion Subject Type: `Email Address`, Assertion Subject Value: `%{session.logon.last.logonname}`.
   - **SAML Attributes**. Add some attributes:
     - Name: `uid`, Value: `123`
     - Name: `memberOf`, Value: `%{session.ad.last.attr.memberOf}`
     - Name: `userPrincipalName`, Value: `%{session.ad.last.attr.userPrincipalName}`
     - Name: `dn`, Value: `%{session.ad.last.attr.dn}`
     - Any other [APM session variables](https://techdocs.f5.com/kb/en-us/products/big-ip_apm/manuals/product/apm-config-11-4-0/apm_config_sessionvars.html) of your choice. 
   - **Security Settings**. Use the `idp.example.com.crt` and `idp.example.com.key` that we generated in the previous step.
   - Click **OK** once done.

5. **Configure External SP Connector**: To allow NGINX Plus to use Big-IP APM as a SAML IdP, you need to add it as a SP connector. Navigate to **Access** -> **Federation** -> **SAML Identity Provider** -> **External SP Connectors**. Click **Create** and on the new page, fill in the fields as follows:
   - **General Settings**. **Service Provider Name**: `sp.example.com`, **Service Provider Entity ID**: `https://sp.example.com/saml-sp`
   - **Endpoint Settings**. Fill in the **Assertion Consumer Service (ACS)** URL. The ACS URL is where the SAML assertion will be sent after authentication; by default it should be `https://sp.example.com/saml/acs`. The **Binding** is **POST**.
   - **Security Settings**. Check the **Require Signed Authentication Request** checkbox and specify the SP certificate you generated earlier, `sp.example.com.crt`. Check the **Response must be signed** and **Assertion must be signed**. **Signing Algorithm** is `RSA-SHA256`.
   - **SLO Service Settings**. By default, as the endpoint where NGINX Plus processes all SLO-related messages, we use the `/saml/sls`, so **Single Logout Request URL** and **Single Logout Response URL** must match `https://sp.example.com/saml/sls`.
   - Click **OK** once done.

6. Now you must bind the created SP connector to your IdP. 
   - Navigate to **Access** -> **Federation** -> **SAML Identity Provider** -> **Local IdP Services**.
   - Select created in the previous step local IdP service and click **Bind/Unbind SP Connectors**.
   - Select `sp.example.com` SP connector and click **OK**.

7. **Create and Apply an Access Policy**: This allows you to define who can authenticate and the attributes that are passed in the SAML assertion.
   - Navigate to **Access** -> **Access Profiles (Per-Session Policies)**.
   - Create a new profile or edit an existing one. In the visual policy editor, you can add items like *Logon Page*, **AD Auth** and **AD Query** (if you're using Active Directory). Your policy might look like this: **Start** -> **Logon Page** -> **AD Auth** -> **AD Query** -> **Allow**
   - When assign the local IdP service `idp.example.com` as **SSO Configuration** object to your **Access Profile**.
   - Don't forget to apply the access policy to the virtual server you're using.

> **_NOTE_** Big-IP APM configuration without customization groups will be given at the very end.

After following these steps, your Big-IP APM system should be configured as a SAML Identity Provider (IdP) that can authenticate users for NGINX Plus.
Please refer to the Big-IP APM documentation for more detailed instructions if needed.

# Configuring NGINX Plus as a SAML SP

Before we begin, make sure you've uploaded the necessary certificates (sp.example.com.crt, sp.example.com.key and idp.example.com.spki) to the server where NGINX Plus is installed. Let's agree that you uploaded them to the `/etc/nginx/conf.d` directory. In addition, check if the user under which your NGINX process is running has access to certificates files, if not, then run the following commands:

```shell
sudo chmod +r /etc/nginx/conf.d/sp.example.com.key 
sudo chown nginx:nginx /etc/nginx/conf.d/sp.example.com.*
sudo chown nginx:nginx /etc/nginx/conf.d/idp.example.com.spki
```

## Understanding and Configuring saml_sp_configuration.conf

This configuration file contains the primary configurations for SPs and IdPs. It comprises several map{} blocks that need to be adjusted according to your SP and IdP setup:
```nginx
map $host $saml_sp_entity_id {
    default "https://sp.example.com/saml-sp";
}

map $host $saml_sp_acs_url {
    default "https://sp.example.com/saml/acs";
}

map $host $saml_sp_sign_authn {
    default "true";
}

map $host $saml_sp_signing_key {
    default "conf.d/sp.example.com.key";
}

map $host $saml_sp_want_signed_response {
    default "true";
}

map $host $saml_sp_want_signed_assertion {
    default "true";
}

map $host $saml_idp_entity_id {
    default "https://idp.example.com/saml-idp";
}

map $host $saml_idp_sso_url {
    # The SAML SSO location is always "/saml/idp/profile/redirectorpost/sso".
    default "https://idp.example.com/saml/idp/profile/redirectorpost/sso";
}

map $host $saml_idp_verification_certificate {
    default "conf.d/idp.example.com.spki";
}

map $host $saml_sp_slo_url {
    default "https://sp.example.com/saml/sls";
}

map $host $saml_sp_slo_binding {
    default 'HTTP-POST';
}

map $host $saml_sp_sign_slo {
    default "true";
}

map $host $saml_idp_slo_url {
    # The SAML SingleLogoutService location is always "/saml/idp/profile/post/sls"
    # for the "HTTP-POST" binding and "/saml/idp/profile/redirect/sls" for the
    # "HTTP-Redirect" binding in per-session policy on Big-IP APM.
    default "https://idp.example.com/saml/idp/profile/post/sls";
}

map $host $saml_idp_slo_response_url {
    # Please note that the SLO request location and the SLO response location
    # are not the same for the Big-IP APM. This is quite rare and most IdPs
    # have a single address, however this is not the case for Big-IP and the
    # response location is always "/saml/idp/profile/post/slr" for the
    # "HTTP-POST" binding and "/saml/idp/profile/redirect/slr" for the Redirect.
    default "https://idp.example.com/saml/idp/profile/post/slr";
}

map $host $saml_sp_want_signed_slo {
    default "true";
}
```

If NGINX Plus is deployed behind another proxy or load balancer, modify the `map...$redirect_base` and `map...$proto` blocks to define how to obtain the original protocol and port number.

## Adjusting frontend.conf for Your Environment

This file is responsible for the reverse proxy configuration.

```nginx
# Modify the upstream group to match your backend site or leave as is
upstream my_backend {
    zone my_backend 64k;
    server localhost:8088;
}

# Custom log format to include the 'NameID' subject in the REMOTE_USER field
log_format saml_sso '$remote_addr - $saml_name_id [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

# Configure the preferred listen port and enable SSL/TLS configuration:
server {
    # Functional locations implementing SAML SSO support
    include conf.d/saml_sp.server_conf;

    # Reduce severity level as required
    error_log /var/log/nginx/error.log debug;

    listen 443 ssl;
    server_name         sp.example.com;
    ssl_certificate     conf.d/sp.example.com.crt;
    ssl_certificate_key conf.d/sp.example.com.key;

    location / {
        error_page 401 = @do_samlsp_flow;

        if ($saml_access_granted != "1") {
            return 401;
        }

        proxy_set_header username $saml_name_id;
        proxy_set_header userPrincipalName $saml_attrib_userPrincipalName;
        proxy_set_header memberOf $saml_attrib_memberOf;
        proxy_set_header dn $saml_attrib_dn;

        access_log /var/log/nginx/access.log saml_sso;
    }
}

# Fake/Demo backend app
server {
    listen 8088;

    location / {
        return 200 "Hello, $http_username!\n Your DN is $http_dn\n Your groups are $http_memberOf\n";
        default_type text/plain;
    }
}
```

## Reviewing saml_sp.server_conf

This is the NGINX configuration for handling IdP Responses. Typically, no changes are required here, but there is one significant parameter to keep an eye on.
Modify the client_body_buffer_size directive to match the maximum size of IdP response (post body).

This completes the basic configuration of NGINX Plus as a SAML SP. Let's move on to the next part.

# Configuring the Key-Value Store in NGINX Plus

## Understanding the Role of the Key-Value Store in SAML

The [key-value store](https://nginx.org/en/docs/http/ngx_http_keyval_module.html) in NGINX Plus is used to maintain persistent storage for SAML sessions and extracted SAML attributes. This ensures that session data is preserved, even in the event of a system reboot or if the NGINX Plus instance is restarted. Moreover, it plays a crucial role in preventing replay attacks by storing SAML message identifiers.

## Configuring Default Key-Value Zones

The default configuration file `saml_sp_configuration.conf` includes several key-value zones to handle common SAML scenarios. These zones store data like message identifiers, session access information, NameID and NameID format values, and more. Each zone is defined with a `keyval_zone` directive, specifying the zone name, memory allocation, state file location, and timeout duration. This default configuration should be reviewed and adjusted to suit your environment.

## Adding Additional Key-Value Zones for Custom SAML Attributes

If you need access to any extracted SAML attribute as a NGINX variable, you need to create a separate `key-value` zone, as well as a `keyval` record for each such attribute. In our example, we have added SAML attributes such as `uid`, `userPrincipalName`, `memberOf` and `dn` so our configuration will look like this:

```nginx
keyval_zone    zone=saml_attrib_uid:1M state=/var/lib/nginx/state/saml_attrib_uid.json timeout=1h;
keyval         $cookie_auth_token $saml_attrib_uid zone=saml_attrib_uid;

keyval_zone    zone=saml_attrib_userPrincipalName:1M state=/var/lib/nginx/state/saml_attrib_userPrincipalName.json timeout=1h;
keyval         $cookie_auth_token $saml_attrib_userPrincipalName zone=saml_attrib_userPrincipalName;

keyval_zone    zone=saml_attrib_memberOf:1M state=/var/lib/nginx/state/saml_attrib_memberOf.json timeout=1h;
keyval         $cookie_auth_token $saml_attrib_memberOf zone=saml_attrib_memberOf;

keyval_zone    zone=saml_attrib_dn:1M state=/var/lib/nginx/state/saml_attrib_dn.json timeout=1h;
keyval         $cookie_auth_token $saml_attrib_dn zone=saml_attrib_dn;
```

> **_NOTE_:** 
> - The variable name includes the prefix `$saml_attrib_`. In the example above, the full variable name would be `$saml_attrib_userPrincipalName`.
> - The optional `state` parameter specifies a file that keeps the current state of the key-value database in the JSON format and makes it persistent across nginx restarts. We use the default path for Linux, however you can change it to suit your requirements.
> - Ensure that you adjust the size of the key-value zones and the `timeouts` according to your use case.

This concludes the configuration of the Key-Value Store in NGINX Plus. Now, your SAML SP is set up and ready for use.

# Testing and Verifying the Configuration

## SAML Flow Verification

Once your SAML SP (NGINX Plus) and IdP (Big-IP APM) have been configured, it is essential to verify that the SAML flow works as expected. This involves confirming that a user can successfully authenticate through the IdP and access resources protected by the SP.

To verify that the SAML flow is working as expected, follow these step-by-step instructions:

1. Start the SP-initiated SAML Flow

In a new browser window, attempt to access a resource that is protected by NGINX Plus, your SP. For example, if you have configured NGINX Plus to protect the URL https://sp.example.com/secure, enter this URL in the browser's address bar:

```http
GET https://sp.example.com/ HTTP/1.1
Host: sp.example.com

HTTP/1.1 200 OK
Server: nginx/1.23.4
Content-Type: text/html
Content-Length: 3460
Set-Cookie: auth_redir=/secure; Path=/; SameSite=lax; HttpOnly; Secure;
```

2. Redirection to IdP

The SP should automatically detect that you are not authenticated and redirect you to the login page of Big-IP APM, your IdP. The address bar of the browser should now display the URL of the IdP's login page.

```http
POST https://idp.example.com/saml/idp/profile/redirectorpost/sso HTTP/1.1
Host: idp.example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 2400
Referer: https://sp.example.com/

HTTP/1.0 302 Found
Server: BigIP
Location: /my.policy
Set-Cookie: LastMRH_Session=***;path=/;secure
MRHSession=***;path=/;secure
MRHSHint=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; path=/;secure
Connection: close
```

SAML AuthnRequest (HTTP-POST binding):
```xml
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    AssertionConsumerServiceURL="https://sp.example.com/saml/acs"
                    Destination="https://idp.example.com/saml/idp/profile/redirectorpost/sso"
                    ID="_bb8e45adbffc333b89afd5090bc33794ac627903"
                    IssueInstant="2023-05-27T20:08:12.650Z"
                    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                    Version="2.0"
                    >
    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sp.example.com/saml-sp</saml:Issuer>
    <ds:Signature>
    ...
    </ds:Signature>
    <samlp:NameIDPolicy AllowCreate="true"
                        Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
                        />
</samlp:AuthnRequest>
```

3. Authentication at the IdP

At the IdP's login page, enter the credentials of a user that has been configured in the IdP. After submitting the credentials, the IdP should authenticate the user.

4. SAML Assertion

After successful authentication, the IdP should create a SAML assertion containing the user's authentication status and attributes. This assertion is then sent back to the SP in a SAML response.

```http
POST https://sp.example.com/saml/acs HTTP/1.1
Host: sp.example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 10001
Origin: https://idp.example.com
Cookie: auth_redir=/secure
```

SAML Response:
```xml
<saml2p:Response ID="_ea59cfcb0fc8aad9cb99460d150655cd5f7999"
                 InResponseTo="_bb8e45adbffc333b89afd5090bc33794ac627903"
                 IssueInstant="2023-05-27T20:08:20Z"
                 Destination="https://sp.example.com/saml/acs"
                 xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
                 Version="2.0"
                 >
    <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example.com/saml-idp</saml2:Issuer>
    <ds:Signature>
    ...
    </ds:Signature>
    <saml2p:Status>
        <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
    </saml2p:Status>
    <saml2:Assertion Version="2.0"
                     ID="_619d600b2a169a86d0ef322456a6b074f4722e"
                     IssueInstant="2023-05-27T20:08:20Z"
                     xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                     >
        <saml2:Issuer>https://idp.example.com/saml-idp</saml2:Issuer>
        <ds:Signature>
        ...
        </ds:Signature>
        <saml2:Subject>
            <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user1</saml2:NameID>
            <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml2:SubjectConfirmationData NotOnOrAfter="2023-05-27T20:18:20Z"
                                               InResponseTo="_bb8e45adbffc333b89afd5090bc33794ac627903"
                                               Recipient="https://sp.example.com/saml/acs"
                                               />
            </saml2:SubjectConfirmation>
        </saml2:Subject>
        <saml2:Conditions NotBefore="2023-05-27T20:05:20Z"
                          NotOnOrAfter="2023-05-27T20:18:20Z"
                          >
            <saml2:AudienceRestriction>
                <saml2:Audience>https://sp.example.com/saml-sp</saml2:Audience>
            </saml2:AudienceRestriction>
        </saml2:Conditions>
        <saml2:AuthnStatement AuthnInstant="2023-05-27T20:08:20Z"
                              SessionIndex="_619d600b2a169a86d0ef322456a6b074f4722e"
                              >
            <saml2:AuthnContext>
                <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
            </saml2:AuthnContext>
        </saml2:AuthnStatement>
        <saml2:AttributeStatement>
            <saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                             Name="uid"
                             NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
                             >
                <saml2:AttributeValue xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">123</saml2:AttributeValue>
            </saml2:Attribute>
            <saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                             Name="memberOf"
                             NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
                             >
                <saml2:AttributeValue xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">CN=SecGroup1,CN=Users,DC=example,DC=com</saml2:AttributeValue>
            </saml2:Attribute>
            <saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                             Name="userPrincipalName"
                             NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
                             >
                <saml2:AttributeValue xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">user1@example.com</saml2:AttributeValue>
            </saml2:Attribute>
            <saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                             Name="dn"
                             NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
                             >
                <saml2:AttributeValue xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">CN=user1,CN=Users,DC=example,DC=com</saml2:AttributeValue>
            </saml2:Attribute>
        </saml2:AttributeStatement>
    </saml2:Assertion>
</saml2p:Response>
```

5. Processing the SAML Response

Upon receiving the SAML response, the NGINX Plus should validate it and extract the user's authentication status and attributes. If the SAML response is valid and the user is authenticated, the SP should create a new session (`auth_token` cookie) for the user and redirect back to the initial location:

```http
HTTP/1.1 302 Moved Temporarily
Server: nginx/1.23.4
Content-Length: 145
Connection: keep-alive
Set-Cookie: auth_token=_00ee7caea72a323d543b93a29a4fb5176bcd36f5; Path=/; SameSite=lax; HttpOnly; Secure;
Location: https://sp.example.com:443/secure
```

6. Accessing the Protected Resource

After a successful session creation, the SP should allow the user to access the previously requested protected resource. The protected resource should now be displayed in the browser:

```http
GET https://sp.example.com/secure HTTP/1.1
Host: sp.example.com
Cookie: auth_redir=/secure; auth_token=_00ee7caea72a323d543b93a29a4fb5176bcd36f5

HTTP/1.1 200 OK
Server: nginx/1.23.4

Hello, user1!
Your DN is CN=user1,CN=Users,DC=example,DC=com
Your groups are CN=SecGroup1,CN=Users,DC=example,DC=com
```

If all of these steps complete without any errors or unexpected behavior, then your SAML flow is working correctly.

## Checking Logs

Checking the logs of both the SP and IdP can provide valuable information about the SAML flow. On the SP side (NGINX Plus), verify that the `auth_token` cookies are being set correctly. On the IdP side (Big-IP APM), ensure that the authentication process completes without errors and that the SAML assertion is being sent to the SP.

NGINX debug.log:
```
2023/05/27 20:40:20 [info] 1507155#1507155: *66 js: SAML SP success, creating session _00ee7caea72a323d543b93a29a4fb5176bcd36f5
```

NGINX access.log:
```
10.10.10.69 - user1 [27/May/2023:20:40:20 +0000] "GET /secure HTTP/1.1" 200 119 "https://idp.example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0" "-"
```

## Testing SP-initiated Logout Functionality

To verify that SP-initiated logout functionality is working correctly, you can follow the steps below:

1. Initiate Logout

Once you have an authenticated session, you can initiate the logout process by accessing the logout URL configured in your SP. For example, if you have set up https://sp.example.com/logout as the logout URL in NGINX Plus, enter this URL in the browser's address bar.

```http
GET https://sp.example.com/logout HTTP/1.1
Host: sp.example.com
Connection: keep-alive
Cookie: auth_redir=/secure; auth_token=_00ee7caea72a323d543b93a29a4fb5176bcd36f5

HTTP/1.1 200 OK
Server: nginx/1.23.4
Content-Length: 3276
```

2. Logout Request to IdP

The SP should create a SAML logout request and redirect your browser to the IdP with this request:

```xml
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                     Destination="https://idp.example.com/saml/idp/profile/post/sls"
                     ID="_9a4fbaf900ab1ef9518dd65bfc3bc1efb3723edb"
                     IssueInstant="2023-05-27T20:47:03.163Z"
                     Version="2.0"
                     >
    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sp.example.com/saml-sp</saml:Issuer>
    <ds:Signature>
    ...
    </ds:Signature>
    <saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">user1</saml:NameID>
</samlp:LogoutRequest>
```

3. Processing the Logout Request

The IdP should process the logout request, invalidate the user's session on the IdP side, and send a SAML logout response back to the SP.

```http
POST https://idp.example.com/saml/idp/profile/post/sls HTTP/1.1
Host: idp.example.com
Content-Length: 2194
Referer: https://sp.example.com/

HTTP/1.1 200 OK
Content-Length: 4278
Set-Cookie: MRHSession=deleted;expires=Thu, 01-Jan-1970 00:00:01 GMT;path=/;secure
Set-Cookie: F5_ST=deleted;expires=Thu, 01-Jan-1970 00:00:01 GMT;path=/;secure
Set-Cookie: MRHSHint=deleted;expires=Thu, 01-Jan-1970 00:00:01 GMT;path=/;secure
Set-Cookie: F5_HT_shrinked=deleted;expires=Thu, 01-Jan-1970 00:00:01 GMT;path=/;secure
Set-Cookie: F5_fullWT=deleted;expires=Thu, 01-Jan-1970 00:00:01 GMT;path=/;secure
Set-Cookie: MRHSequence=deleted;expires=Thu, 01-Jan-1970 00:00:01 GMT;path=/;secure
```

4. Logout Response to SP

Your browser should be redirected back to the SP with the SAML logout response from the IdP.

```http
POST https://sp.example.com/saml/sls HTTP/1.1
Host: sp.example.com
Referer: https://idp.example.com/
Cookie: auth_redir=/secure; auth_token=_00ee7caea72a323d543b93a29a4fb5176bcd36f5

HTTP/1.1 302 Moved Temporarily
Server: nginx/1.23.4
Set-Cookie: auth_token=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/; SameSite=lax; HttpOnly; Secure;
auth_redir=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/; SameSite=lax; HttpOnly; Secure;
Location: https://sp.example.com:443/_logout
```

```xml
<saml2p:LogoutResponse xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
                       ID="_c65b85c8934353cd9e0316f907b88ceb7aa021"
                       Version="2.0"
                       IssueInstant="2023-05-27T20:47:03Z"
                       InResponseTo="_9a4fbaf900ab1ef9518dd65bfc3bc1efb3723edb"
                       Destination="https://sp.example.com/saml/sls"
                       >
    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example.com/saml-idp</saml:Issuer>
    <ds:Signature>
    ...
    </ds:Signature>
    <saml2p:Status>
        <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
    </saml2p:Status>
</saml2p:LogoutResponse>
```

5. Processing the Logout Response

The SP should process the SAML logout response and if valid, it should invalidate the user's session on the SP side:

```http
Set-Cookie: auth_token=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/; SameSite=lax; HttpOnly; Secure;
Set-Cookie: auth_redir=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/; SameSite=lax; HttpOnly; Secure;
```

6. Logout Confirmation

The SP can then display a logout confirmation message or redirect the user to a public (unprotected) resource.

```http
GET https://sp.example.com/_logout HTTP/1.1
Host: sp.example.com

HTTP/1.1 200 OK
Server: nginx/1.23.4

Logged out
```

If all these steps complete without any errors, it indicates that your SP-initiated logout functionality is working correctly.

## Testing IdP-initiated Logout Functionality

1. Initiate Logout

Initiate a logout from the IdP's side. On Big-IP APM, this can be done by clicking the "Logout" button on the Webtop or by directly accessing the logout location `/vdesk/hangup.php3`.

```http
GET https://idp.example.com/vdesk/hangup.php3 HTTP/1.1
Host: idp.example.com

HTTP/1.1 200 OK
```

2. Logout Request to SP

The IdP should create a SAML logout request and send it to the SP, which your browser will relay.

```http
POST https://sp.example.com/saml/sls HTTP/1.1
Host: sp.example.com
Content-Length: 3972
Origin: https://idp.example.com
Cookie: auth_redir=/; auth_token=_a13da74f175cbd368f994576ba81cddb47fd7ef3

HTTP/1.1 200 OK
Server: nginx/1.23.4
Content-Length: 3339
Connection: keep-alive
Set-Cookie: auth_token=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/; SameSite=lax; HttpOnly; Secure;
Set-Cookie: auth_redir=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/; SameSite=lax; HttpOnly; Secure;
```

IdP-initiated LogoutRequest:
```xml
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                     ID="_5333183776ec86b34e57b1fd98f3908561500b"
                     Version="2.0"
                     IssueInstant="2023-05-27T21:16:19Z"
                     NotOnOrAfter="2023-05-27T21:22:19Z"
                     Destination="https://sp.example.com/saml/sls"
                     >
    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example.com/saml-idp</saml:Issuer>
    <ds:Signature>
    ...
    </ds:Signature>
    <saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                 Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
                 >user1</saml:NameID>
    <samlp:SessionIndex xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">_093491ae264610ffdea421cbf854f0e82445f4</samlp:SessionIndex>
</samlp:LogoutRequest>
```

3. Processing the Logout Request

The SP should process the logout request and, if it's valid, it should invalidate the user's session on the SP side:

```http
Set-Cookie: auth_token=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/; SameSite=lax; HttpOnly; Secure;
Set-Cookie: auth_redir=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/; SameSite=lax; HttpOnly; Secure;
```

4. Logout Response to IdP

Then, the SP should create a SAML logout response and your browser should redirect back to the IdP with this response.

```http
POST https://idp.example.com/saml/idp/profile/post/slr HTTP/1.1
Host: idp.example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 2279
Referer: https://sp.example.com/
Cookie: LastMRH_Session=***; TIN=297000; MRHSession=***

HTTP/1.1 302 Moved Temporarily
Content-Length: 0
Location: /vdesk/hangup.php3
```

SAML LogoutResponse:
```xml
<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                      Destination="https://idp.example.com/saml/idp/profile/post/slr"
                      ID="_2c762f953d8c5a366d27c34515875aa295f430bd"
                      InResponseTo="_5333183776ec86b34e57b1fd98f3908561500b"
                      IssueInstant="2023-05-27T21:16:19.500Z"
                      Version="2.0"
                      >
    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sp.example.com/saml-sp</saml:Issuer>
    <ds:Signature>
    ...
    </ds:Signature>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
    </samlp:Status>
</samlp:LogoutResponse>
```

5. Processing the Logout Response

The IdP should process the logout response and invalidate the user's session on the IdP side.

```http
GET https://idp.example.com/vdesk/hangup.php3 HTTP/1.1
Host: idp.example.com

HTTP/1.1 200 OK
Date: Sat, 27 May 2023 21:16:19 GMT
Server: BigIP
Set-Cookie: MRHSession=deleted;expires=Thu, 01-Jan-1970 00:00:01 GMT;path=/;secure
Set-Cookie: F5_ST=deleted;expires=Thu, 01-Jan-1970 00:00:01 GMT;path=/;secure
Set-Cookie: MRHSHint=deleted;expires=Thu, 01-Jan-1970 00:00:01 GMT;path=/;secure
Set-Cookie: F5_HT_shrinked=deleted;expires=Thu, 01-Jan-1970 00:00:01 GMT;path=/;secure
Set-Cookie: F5_fullWT=deleted;expires=Thu, 01-Jan-1970 00:00:01 GMT;path=/;secure
Set-Cookie: MRHSequence=deleted;expires=Thu, 01-Jan-1970 00:00:01 GMT;path=/;secure
```

# Troubleshooting Common Configuration Issues

When dealing with SAML configuration issues, the following considerations might help:

1. Insufficient Read Permissions for Private and/or Public Keys

In case NGINX lacks read permissions for certificates or keys, the following error will be logged in the debug.log:

```
[error] 1507155#1507155: *79 js: SAML SSO Error: ReferenceID: undefined ReferenceError: Failed to read private or public key from file "conf.d/sp.example.com.key": Permission denied
```

Check the access permissions to the key and certificate files. The NGINX process must have read permissions for these files. If you have root access, you can change the file permissions using the `chmod` command:

```shell
sudo chmod 644 /path/to/your/key_or_certificate_file
```

You can also change the owner of the files to the NGINX user:

```shell
sudo chown nginx:nginx /path/to/your/key_or_certificate_file
```

Make sure to consider security implications before changing file permissions or ownership.

2. Insufficient Write Permissions to the State File

If the NGINX process lacks write permissions to the state file (the file that keeps the current state of the key-value database), a similar error might be seen in the logs:

```
2023/05/25 19:15:31 [alert] 499449#499449: open() "/etc/nginx/conf.d/saml_session_index.json.tmp" failed (13: Permission denied)
```

You'll need to ensure that NGINX has write permissions to the folder where you are going to store the state files.

3. Some SAML Attributes Unavailable as NGINX Variables

Another potential issue is when some SAML attributes are not available as NGINX variables. Check your settings in `saml_sp_configuration.conf`. Remember that if you need access to any extracted SAML attribute as a NGINX variable, you need to create a separate `key-value` zone, as well as a `keyval` record for each such attribute. The variable name includes the prefix `$saml_attrib_`.

4. Enabling Debug Information for SAML SSO

The variable `$saml_debug` can be set to enable detailed error reporting for SAML SSO. When this variable is defined, the `saml_sp.js` script will log verbose debugging information to the NGINX debug log and also return the NJS call stack within the HTTP response in case of an error. This can be extremely useful for identifying the exact location within the script where the error is occurring, as it provides a detailed error trace.

Here is how you can define the variable:

```nginx
map $host $saml_debug {
    default "1";
}
```

> **_Please note_**, enabling `$saml_debug` may expose sensitive debugging information within the HTTP responses and logs, therefore it is highly recommended to not use this option in a production environment. Remember to disable this variable once you've finished your debugging process to prevent unnecessary logging and potential information exposure.

# Big-IP raw config

```tcl
#TMSH-VERSION: 17.1.0

apm aaa active-directory /Common/example-ad {
    admin-encrypted-password mypassword
    admin-name admin
    domain example.com
    domain-controller dc.example.com
    use-pool disabled
}

apm policy access-policy /Common/psp-saml-demo {
    default-ending /Common/psp-saml-demo_end_deny
    items {
        /Common/psp-saml-demo_act_active_directory_auth { }
        /Common/psp-saml-demo_act_active_directory_query { }
        /Common/psp-saml-demo_act_logon_page { }
        /Common/psp-saml-demo_end_allow { }
        /Common/psp-saml-demo_end_deny { }
        /Common/psp-saml-demo_ent { }
    }
    start-item /Common/psp-saml-demo_ent
}

apm policy policy-item /Common/psp-saml-demo_act_active_directory_auth {
    agents {
        /Common/psp-saml-demo_act_active_directory_auth_ag {
            type aaa-active-directory
        }
    }
    caption "AD Auth"
    color 1
    item-type action
    rules {
        {
            caption Successful
            expression "expr {[mcget {session.ad.last.authresult}] == 1}"
            next-item /Common/psp-saml-demo_act_active_directory_query
        }
        {
            caption fallback
            next-item /Common/psp-saml-demo_end_deny
        }
    }
}
apm policy policy-item /Common/psp-saml-demo_act_active_directory_query {
    agents {
        /Common/psp-saml-demo_act_active_directory_query_ag {
            type aaa-active-directory
        }
    }
    caption "AD Query"
    color 1
    item-type action
    rules {
        {
            caption "Active Directory Query has Passed"
            expression "expr {[mcget {session.ad.last.queryresult}] == 1}"
            next-item /Common/psp-saml-demo_end_allow
        }
        {
            caption fallback
            next-item /Common/psp-saml-demo_end_deny
        }
    }
}
apm policy policy-item /Common/psp-saml-demo_act_logon_page {
    agents {
        /Common/psp-saml-demo_act_logon_page_ag {
            type logon-page
        }
    }
    caption "Logon Page"
    color 1
    item-type action
    rules {
        {
            caption fallback
            next-item /Common/psp-saml-demo_act_active_directory_auth
        }
    }
}
apm policy policy-item /Common/psp-saml-demo_end_allow {
    agents {
        /Common/psp-saml-demo_end_allow_ag {
            type ending-allow
        }
    }
    caption Allow
    color 1
    item-type ending
}
apm policy policy-item /Common/psp-saml-demo_end_deny {
    agents {
        /Common/psp-saml-demo_end_deny_ag {
            type ending-deny
        }
    }
    caption Deny
    color 2
    item-type ending
}
apm policy policy-item /Common/psp-saml-demo_ent {
    caption Start
    color 1
    rules {
        {
            caption fallback
            next-item /Common/psp-saml-demo_act_logon_page
        }
    }
}
apm policy agent aaa-active-directory /Common/psp-saml-demo_act_active_directory_auth_ag {
    server /Common/example-ad
    type auth
}
apm policy agent aaa-active-directory /Common/psp-saml-demo_act_active_directory_query_ag {
    query-attrname { cn displayName distinguishedName dn employeeID givenName homeMDB mail memberOf mobile msDS-ResultantPSO name objectGUID otherMobile pager primaryGroupID pwdLastSet sAMAccountName sn telephoneNumber userAccountControl userPrincipalName }
    server /Common/example-ad
    type query
}
apm policy agent ending-allow /Common/psp-saml-demo_end_allow_ag { }
apm policy agent ending-deny /Common/psp-saml-demo_end_deny_ag {
    customization-group /Common/psp-saml-demo_end_deny_ag
}
apm policy agent logon-page /Common/psp-saml-demo_act_logon_page_ag {
    customization-group /Common/psp-saml-demo_act_logon_page_ag
}
apm profile access /Common/psp-saml-demo {
    accept-languages { en }
    access-policy /Common/psp-saml-demo
    app-service none
    customization-group /Common/psp-saml-demo_logout
    customization-key none
    default-language en
    domain-cookie none
    eps-group /Common/psp-saml-demo_eps
    errormap-group /Common/psp-saml-demo_errormap
    exchange-profile none
    framework-installation-group /Common/psp-saml-demo_framework_installation
    general-ui-group /Common/psp-saml-demo_general_ui
    generation 5
    generation-action noop
    httponly-cookie false
    log-settings {
        /Common/default-log-setting
    }
    logout-uri-include none
    logout-uri-timeout 5
    modified-since-last-policy-sync true
    named-scope none
    oauth-profile none
    persistent-cookie false
    samesite-cookie false
    scope profile
    secure-cookie true
    sso-name /Common/idp.example.com
    type all
    user-identity-method http
}
apm report default-report {
    report-name sessionReports/sessionSummary
    user /Common/admin
}
apm sso saml /Common/idp.example.com {
    attributes {
        {
            multi-values { 123 }
            name uid
        }
        {
            multi-values { "%{session.ad.last.attr.memberOf}" }
            name memberOf
        }
        {
            multi-values { "%{session.ad.last.attr.userPrincipalName}" }
            name userPrincipalName
        }
        {
            multi-values { "%{session.ad.last.attr.dn}" }
            name dn
        }
    }
    entity-id https://idp.example.com/saml-idp
    idp-certificate /Common/idp.example.com
    idp-signkey /Common/idp.example.com.key
    saml-profiles { web-browser-sso }
    sp-connectors {
        /Common/sp.example.com
    }
    subject-value "%{session.logon.last.logonname}"
}
apm sso saml-sp-connector /Common/sp.example.com {
    assertion-consumer-services {
        {
            is-default true
            uri https://sp.example.com/saml/acs
        }
    }
    entity-id https://sp.example.com/saml-sp
    is-authn-request-signed true
    single-logout-response-uri https://sp.example.com/saml/sls
    single-logout-uri https://sp.example.com/saml/sls
    sp-certificate /Common/sp.example.com.crt
    want-response-signed true
}

ltm virtual /Common/vs_88 {
    destination /Common/10.10.10.88:443
    ip-protocol tcp
    mask 255.255.255.255
    profiles {
        /Common/clientssl-insecure-compatible {
            context clientside
        }
        /Common/http { }
        /Common/psp-saml-demo { }
        /Common/rba { }
        /Common/tcp { }
        /Common/websso { }
    }
    serverssl-use-sni disabled
    source 0.0.0.0/0
    source-address-translation {
        type automap
    }
    translate-address enabled
    translate-port enabled
}
ltm virtual-address /Common/10.10.10.88 {
    address 10.10.10.88
    arp enabled
    icmp-echo enabled
    mask 255.255.255.255
    traffic-group /Common/traffic-group-1
}
ltm profile client-ssl /Common/clissl_idp.example.com {
    app-service none
    cert-key-chain {
        idp.example.com_0 {
            cert /Common/idp.example.com
            key /Common/idp.example.com.key
        }
    }
    defaults-from /Common/clientssl-insecure-compatible
    inherit-ca-certkeychain true
    inherit-certkeychain false
}
sys file ssl-cert /Common/idp.example.com {
    cache-path /config/filestore/files_d/Common_d/certificate_d/:Common:idp.example.com_100321_1
    revision 1
}
sys file ssl-cert /Common/sp.example.com.crt {
    cache-path /config/filestore/files_d/Common_d/certificate_d/:Common:sp.example.com.crt_100327_1
    revision 1
}
sys file ssl-key /Common/idp.example.com.key {
    cache-path /config/filestore/files_d/Common_d/certificate_key_d/:Common:idp.example.com.key_100318_1
    revision 1
}
```