/*
 * JavaScript functions for providing SAML SP with NGINX Plus
 * 
 * Copyright (C) 2023 Nginx, Inc.
 */

// Note:
// For now all communications with IdP performed via user-agent/browser, they all are not reliable
// we keep all state in static config data -- maps      -- at bootstrap loaded from config file
//                     and in dynamic data -- keyvals   -- at bootstap loading from local files (zones)

export default {send_saml_request_to_idp, process_idp_response};


const xml = require("xml");
const querystring = require("querystring");
const fs = require("fs");

function get_escapeXML() {
    const fpc = Function.prototype.call;
    const _replace = fpc.bind(fpc, String.prototype.replace);

    const tbl = {
        '<': '&lt;',
        '>': '&gt;',
        "'": '&apos;',
        '"': '&quot;',
        '&': '&amp;',
    };
    tbl.__proto__ = null;

    return function (str) {
        return _replace(str, /[<>'"&]/g, c => tbl[c]);
    }
};

const escapeXML = get_escapeXML();

function createAuthnRequest_saml2_0(
    id,
    issueInstant,
    destination,
    protocolBinding,
    assertionConsumerServiceUrl,
    forceAuthn,
    issuer
) {

    /* Apply escapeXML to all arguments, as they all are going to xml. */
        
    id = escapeXML(id);
    issueInstant = escapeXML(issueInstant);
    destination = escapeXML(destination);
    protocolBinding = escapeXML(protocolBinding);
    assertionConsumerServiceUrl = escapeXML(assertionConsumerServiceUrl);
    forceAuthn = escapeXML(forceAuthn);
    issuer = escapeXML(issuer);
    
    // if (assertionConsumerServiceUrl !== '') {
    //     assertionConsumerServiceUrl = ' AssertionConsumerServiceURL="'+assertionConsumerServiceUrl+'"'
    // }

    let xml = 
        '<samlp:AuthnRequest' +
            ' xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"' +
            ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"' +
            ` ID="${id}"` +
            ' Version="2.0"' +
            ` IssueInstant="${issueInstant}"` +
            ` Destination="${destination}"` +
            ` ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:${protocolBinding}"` +
            ` AssertionConsumerServiceURL="${assertionConsumerServiceUrl}"` +
            ` ForceAuthn="${forceAuthn}"` +
        '>' +
            `<saml:Issuer>${issuer}</saml:Issuer>` +
            '<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>' +
        '</samlp:AuthnRequest>';

    return xml;
}

function generateID() {
    let buf = Buffer.alloc(20);
    return (crypto.getRandomValues(buf)).toString('hex');
}


function send_saml_request_to_idp (r) {
    try {
        // send redirect with autosubmit POST:
        // 0) check if we are configured for IdP, so we can request metadata from IdP here (see response)
        // 1) create saml request to IdP ( uniq_ID, target->process_IdP_response);
        // 2) sign it if required

        function doAuthnRequest() {
            var relayState = r.variables.saml_sp_relay_state;
            var destination = r.variables.saml_idp_sso_url;

            r.variables.saml_request_id = "nginx_" + generateID();

            r.variables.saml_have_session = "1";

            var authnRequest_saml_text = createAuthnRequest_saml2_0(
                r.variables.saml_request_id,      // ID
                new Date().toISOString(),         // IssueInstant
                destination,                      // Destination
                r.variables.saml_request_binding, // ProtocolBinding
                r.variables.saml_sp_acs_url,      // AssertionConsumerServiceURL
                r.variables.saml_sp_force_authn,  // ForceAuthn
                r.variables.saml_sp_entity_id     // Issuer
            );

            var xml_tree = xml.parse(authnRequest_saml_text);

            let dec = new TextDecoder();

            if (r.variables.saml_idp_sign_authn === "true") {
                // TBD:
                //var c14n = dec.decode(dec.AuthnRequest.exclusiveC14n());
                //<* sign c14n (use cert, and purivate_key) *>
                //var xml_norm_signed_text = dec.decode(xml.parse(<* inject signature to xml_tree *>).exclusiveC14n())
                saml_error(r, 500, "Request Signing not supported yet");
                return;
            } else {
                // just normalize it. May be omitted for not signed request?
                var xml_norm_authn = dec.decode(xml.exclusiveC14n(xml_tree));
            }
            var encodedRequest = xml_norm_authn.toString("base64");

            if (r.variables.saml_request_binding === 'HTTP-POST') {
                var form = `<form method="post" action="${destination}">` +
                `<input type="hidden" name="SAMLRequest" value="${encodedRequest}"/>` +
                `<input type="hidden" name="RelayState" value="${relayState}"/>` +
                '</form>';
                var autoSubmit = '<script>document.getElementsByTagName("form")[0].submit();</script>';

                r.headersOut['Content-Type'] = "text/html";
                r.return(200, form + autoSubmit);
            } else {
                r.return(302, r.variables.redirect_base + 'SAMLRequest=' + encodedRequest + relayState?'&RelayState='+relayState:'');
            }
        }

        doAuthnRequest();

    } catch (e) {
        saml_error(r, 500, "send_saml_request_to_idp internal error e.message="+e.message)
    }
}


/////////////////////////////////////////////////////////////// 

function saml_error(r, http_code, msg) {
    r.error("SAMLSP " + msg);
    r.return(http_code, "SAMLSP " + msg);
}


async function process_idp_response (r) {
    try {
        let reqBody = (r.requestText).toString();
        let postResponse = querystring.parse(reqBody);
        let SAMLResponseRaw = postResponse.SAMLResponse;

        // Base64 decode of SAML Response
        //let SAMLResponseDec = querystring.unescape(SAMLResponseRaw); POST body cannot be URL encoded
        var SAMLResponse = Buffer.from(SAMLResponseRaw, 'base64');

        var xmlDoc;
        try { 
            xmlDoc = xml.parse(SAMLResponse);
        }catch(e) {
            saml_error(r, 500, "XML parsing failed: "+e.message);
            return;
        }

        if (!xmlDoc) {
            saml_error(r, 500, "no XML found in Response");
            return;
        }

        /*
         * series of check ups, part of them are general, part custom;
         */


        /*
         * perform general sanity check
         */


        if (xmlDoc.Response.EncryptedAssertion) {
            saml_error(r, 500, "Encrypted Response not supported yet -- failed");
            return;

           //tbd <* decrypt xml *>
        }

        if (r.variables.saml_sp_want_signed_assertion === "true") {
            if (!xmlDoc.Response.Signature) {
                saml_error(r, 500, "NGINX SAML requires signed assertion -- failed");
            }
            let key_data = fs.readFileSync(`conf/${r.variables.saml_idp_verification_certificate}`);
            let signed_assertion = await verifySAMLSignature(xmlDoc, key_data);
        }


        /*
         * check response correctness: is it response to sent request, is  timeouts ok, config/auth response, and so on
         */
    

        // Responce is single document root -- sanity check
        if (!xmlDoc.Response) {
           saml_error(r, 500, "No Response tag");
           return;
        }

        // single Response attrinute InResponseTo value is present in state cache, it can be used as session later
        if (xmlDoc.Response.$attr$InResponseTo) {
            r.variables.saml_request_id = xmlDoc.Response.$attr$InResponseTo;
            if (r.variables.saml_have_session != '1') {
                saml_error(r, 500, "Wrong InResponseTo " + xmlDoc.Response.$attr$InResponseTo);
                return;
            }
            r.variables.saml_have_session = '0';
        } else {
            saml_error(r, 500, "Response tag has no InResponseTo attribute, or has more than 1");
            return;
        }
    
        /*
         * perform any other general check up
         */

        // response example from data provided by customer.

        // do we need check namespaces?

        // Response.$attr$consent == "urn:oasis:names:tc:SAML:2.0:consent:obtained"
        // Response.$attr$Destination == "xxx"
        // Response.$attr$ID --> use for logging
        // Response.$attr$IssueInstant --> check if it is in the past, and use it later

        // Response.Issuer.$attr$Format == "urn:oasis:names:tc:SAML:2.0:nameid-format:entity" and
        // Response.Issuer.$text  == https://ecas.cc.cec.eu.int:7002/cas/login --> some expected value

        // ===> Probably most important test:
        // Response.Status.StatusCode.$attr$Value === "urn:oasis:names:tc:SAML:2.0:status:Success"
        // Response.Status.StatusMessage.$text$ === "successful EU Login authentication"

        // Response.Assertion.$attr$ID --> save for logging issues with Assertions
        // Response.Assertion.$attr$IssueInstant --> check if this is not from future, can be used to check time range in Assertion.Conditions  later?
        // Response.Assertion.Issuer
        // Response.Assertion.Subject
        // Response.Assertion.Conditions  --> general check time range (audience check?), oneTimeUse, ProxyRestriction
        // Response.AuthnStatement
        // Response.AttributeStatement.$tags$Attribute[i].$tags$AttributeValue[j].$text -->
        //                                            name                     N

                  // $name
                  // $name$N?  --> for example $groups$1, etc


        /*
         * end of general check up
         */


        /*
         *  application level action need to be placed here.
         *     either simple or customized
         *  (for now we are ok with Response, keep stringified saml in keyval, create session and redirect back to protected root url)
         */

        // generate cookie_auth_token
        r.variables.cookie_auth_token = "nginx_" + generateID();

        // simple_action()
        //r.variables.response_xml_json = JSON.stringify(xml);

        // custom_action()
              // var policy_result = {}
              // eval_policy(r.variables, policy, xml.Response);
              //   it will set r.variables.$location_N_granted in keyvals for later use


        // grant access
        r.variables.location_root_granted = '1';

        r.headersOut["Set-Cookie"] = "auth_token=" + r.variables.cookie_auth_token + "; " + r.variables.saml_cookie_flags;
        // redirect back to root
        r.return(302, "/"); // should be relay state or landing page
    } catch(e) {
        saml_error(r, 500, "process_idp_response internal error e.message="+e.message)
    }
}

/*
 * verifySAMLSignature() implements a verify clause
 * from Profiles for the OASIS SAML V2.0
 * 4.1.4.3 <Response> Message Processing Rules
 *  Verify any signatures present on the assertion(s) or the response
 *
 * verification is done in accordance with
 * Assertions and Protocols for the OASIS SAML V2.0
 * 5.4 XML Signature Profile
 *
 * The following signature algorithms are supported:
 * - http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
 * - http://www.w3.org/2000/09/xmldsig#rsa-sha1
 *
 * The following digest algorithms are supported:
 * - http://www.w3.org/2000/09/xmldsig#sha1
 * - http://www.w3.org/2001/04/xmlenc#sha256
 *
 * @param doc an XMLDoc object returned by xml.parse().
 * @param key_data is SubjectPublicKeyInfo in PEM format.
 */

async function verifySAMLSignature(saml, key_data) {
    const root = saml.$root;
    const rootSignature = root.Signature;

    if (!rootSignature) {
        throw Error(`SAML message is unsigned`);
    }

    const assertion = root.Assertion;
    const assertionSignature = assertion ? assertion.Signature : null;

    if (assertionSignature) {
        if (!await verifyDigest(assertionSignature)) {
            return false;
        }

        if (!await verifySignature(assertionSignature, key_data)) {
            return false;
        }
    }

    if (rootSignature) {
        if (!await verifyDigest(rootSignature)) {
            return false;
        }

        if (!await verifySignature(rootSignature, key_data)) {
            return false;
        }
    }

    return true;
}

async function verifyDigest(signature) {
    const parent = signature.$parent;
    const signedInfo = signature.SignedInfo;
    const reference = signedInfo.Reference;

    /* Sanity check. */

    const URI = reference.$attr$URI;
    const ID = parent.$attr$ID;

    if (URI != `#${ID}`) {
        throw Error(`signed reference URI ${URI} does not point to the parent ${ID}`);
    }

    /*
     * Assertions and Protocols for the OASIS SAML V2.0
     * 5.4.4 Transforms
     *
     * Signatures in SAML messages SHOULD NOT contain transforms other than
     * the http://www.w3.org/2000/09/xmldsig#enveloped-signature and
     * canonicalization transforms http://www.w3.org/2001/10/xml-exc-c14n# or
     * http://www.w3.org/2001/10/xml-exc-c14n#WithComments.
     */

    const transforms = reference.Transforms.$tags$Transform;
    const transformAlgs = transforms.map(t => t.$attr$Algorithm);

    if (transformAlgs[0] != 'http://www.w3.org/2000/09/xmldsig#enveloped-signature') {
        throw Error(`unexpected digest transform ${transforms[0]}`);
    }

    if (!transformAlgs[1].startsWith('http://www.w3.org/2001/10/xml-exc-c14n#')) {
        throw Error(`unexpected digest transform ${transforms[1]}`);
    }

    const namespaces = transformAlgs[1].InclusiveNamespaces;
    const prefixList = namespaces ? namespaces.$attr$PrefixList: null;

    const withComments = transformAlgs[1].slice(39) == 'WithComments';

    let hash;
    const alg = reference.DigestMethod.$attr$Algorithm;

    switch (alg) {
    case "http://www.w3.org/2000/09/xmldsig#sha1":
        hash = "SHA-1";
        break;
    case "http://www.w3.org/2001/04/xmlenc#sha256":
        hash = "SHA-256";
        break;
    case "http://www.w3.org/2001/04/xmlenc#sha512":
        hash = "SHA-512";
        break;
    default:
        throw Error(`unexpected digest Algorithm ${alg}`);
    }

    const expectedDigest = signedInfo.Reference.DigestValue.$text;

    const c14n = xml.exclusiveC14n(parent, signature, withComments, prefixList);
    const dgst = await crypto.subtle.digest(hash, c14n);
    const b64dgst = Buffer.from(dgst).toString('base64');

    return expectedDigest === b64dgst;
}

function keyPem2Der(pem, type) {
    const pemJoined = pem.toString().split('\n').join('');
    const pemHeader = `-----BEGIN ${type} KEY-----`;
    const pemFooter = `-----END ${type} KEY-----`;
    const pemContents = pemJoined.substring(pemHeader.length, pemJoined.length - pemFooter.length);
    return Buffer.from(pemContents, 'base64');
}

function base64decode(b64) {
    const joined = b64.toString().split('\n').join('');
    return Buffer.from(joined, 'base64');
}

async function verifySignature(signature, key_data) {
    const der = keyPem2Der(key_data, "PUBLIC");

    let method, hash;
    const signedInfo = signature.SignedInfo;
    const alg = signedInfo.SignatureMethod.$attr$Algorithm;

    switch (alg) {
    case "http://www.w3.org/2000/09/xmldsig#rsa-sha1":
        method = "RSASSA-PKCS1-v1_5";
        hash = "SHA-1";
        break;
    case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":
        method = "RSASSA-PKCS1-v1_5";
        hash = "SHA-256";
        break;
    case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512":
        method = "RSASSA-PKCS1-v1_5";
        hash = "SHA-512";
        break;
    default:
        throw Error(`unexpected signature Algorithm ${alg}`);
    }

    const expectedValue = base64decode(signature.SignatureValue.$text);
    const withComments = signedInfo.CanonicalizationMethod
                         .$attr$Algorithm.slice(39) == 'WithComments';

    const signedInfoC14n = xml.exclusiveC14n(signedInfo, null, withComments);

    const key = await crypto.subtle.importKey("spki", der, { name: method, hash },
                                            false, [ "verify" ]);

    return await crypto.subtle.verify({ name: method }, key, expectedValue,
                                      signedInfoC14n);
}

function p(args, default_opts) {
    let params = merge({}, default_opts);
    params = merge(params, args);

    return params;
}
