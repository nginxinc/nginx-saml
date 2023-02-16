/*
 * JavaScript functions for providing SAML SP with NGINX Plus
 * 
 * Copyright (C) 2023 Nginx, Inc.
 */

export default {doAuthnRequest, processIdpResponse};

const xml = require("xml");
const querystring = require("querystring");
const fs = require("fs");

function doAuthnRequest(r) {
    /* Generate authentication request ID with 160 bits of entropy */
    const requestID = "_" + generateID(20);
    r.variables.saml_request_id = requestID;

    /* Create authentication request XML payload */
    const escapeXML = getEscapeXML();
    const ssoUrl = escapeXML(r.variables.saml_idp_sso_url);
    const acsUrl = escapeXML(r.variables.saml_sp_acs_url);
    const forceAuthn = escapeXML(r.variables.saml_sp_force_authn);
    const issuer = escapeXML(r.variables.saml_sp_entity_id);
    const nameidFormat = escapeXML(r.variables.saml_sp_nameid_format);
    let xmlData = createAuthnRequest(requestID, ssoUrl, acsUrl, forceAuthn, issuer, nameidFormat);

    xmlData = normalizeXml(xmlData);

    if (r.variables.saml_idp_sign_authn === "true") {
        samlError(r, 500, "doAuthnRequest: AuthN Request Signing not supported yet.");
        return;
    }

    /* Send AuthN request to the IdP using POST or Redirect method */
    const relayState = r.variables.saml_sp_relay_state;
    const spRequestBinding = r.variables.saml_sp_request_binding;
    if (spRequestBinding === 'HTTP-POST') {
        r.headersOut['Content-Type'] = "text/html";
        r.return(200, postAuthnRequest(xmlData, ssoUrl, relayState));
    } else if (spRequestBinding === 'HTTP-Redirect') {
        r.return(302, redirectAuthnRequest(xmlData, ssoUrl, relayState));
    } else {
        samlError(r, 500, `doAuthnRequest: ${spRequestBinding} is an unsupported AuthN Request ` +
                           "binding method.");
    }

    /* Map AuthN request ID to a pending SP-initiated session */
    r.variables.saml_have_session = "1";
}

async function processIdpResponse (r) {
    /* Extract SAML parameters from the POST body */
    let postParams, samlResponse, relayState;
    try {
        postParams = parsePostPayload(r.requestText);
        samlResponse = postParams[0];
        relayState = postParams[1];
    } catch (e) {
        samlError(r, 500, "processIdpResponse: Failed to extract SAMLResponse parameter " +
                          `from the POST body. ${e.message}`);
    }

    /* Parse SAML response for an XML document */
    let xmlDoc;
    try { 
        xmlDoc = xml.parse(samlResponse);
    } catch (e) {
        samlError(r, 500, "processIdpResponse: Failed to parse SAMLResponse for an XML " +
                          `document. ${e.message}`);
        return;
    }

    /* Verify SAML response header */
    try {
        verifySAMLResponse(r, xmlDoc);
    } catch (e) {
        samlError(r, 500, "processIdpResponse: Failed to parse SAML Response header. " +
                           e.message);
    }

    /* Verify SAML response signature */
    const wantSignedAssertion = r.variables.saml_sp_want_signed_assertion;
    const idpCertificate = r.variables.saml_idp_verification_certificate;
    if (wantSignedAssertion === "true") {
        let keyData;
        try {
            keyData = fs.readFileSync(idpCertificate);
        } catch (e) {
            samlError(r, 500, "processIdpResponse: Failed to read IdP verification certificate " +
                              `from file "${idpCertificate}". ${e.message}`);
        }

        try {
            if (!await verifySAMLSignature(xmlDoc, keyData)) {
                throw new Error(`Certificate "${idpCertificate}" may be invalid.`);
            }
        } catch (e) {
            samlError(r, 500, "processIdpResponse: SAML Assertion signature check failed. " +
                               e.message);
        }
    }

    /* Verify SAML Response status */
    try {
        verifyResponseStatus(xmlDoc);
    } catch (e) {
        samlError(r, 403, `processIdpResponse: SAML status not successful: ${e.message}`);
    }

    /* Verify SAML Assertion */
    const idpEntityID = r.variables.saml_idp_entity_id;
    try {
        verifySAMLAssertion(xmlDoc, idpEntityID);
    } catch (e) {
        samlError(r, 500, `processIdpResponse: Invalid SAML Assertion. ${e.message}`);
    }

    /* Parse Assertion Subject */
    let nameID;
    try {
        nameID = parseAssertionSubject(xmlDoc);
    } catch (e) {
        samlError(r, 500, `processIdpResponse: Invalid SAML Assertion Subject. ${e.message}`);
    }

    /* Verify SAML conditions */
    const spEntityId = r.variables.saml_sp_entity_id;
    try {
        verifySAMLConditions(xmlDoc, spEntityId);
    } catch (e) {
        samlError(r, 500, "processIdpResponse: Failed to verify SAML Response conditions. " +
                           e.message);
    }

    /* Generate cookie_auth_token */
    const authToken =  "_" + generateID();

    /* Save cookie_auth_token to keyval to store SAML session data */
    r.variables.cookie_auth_token = authToken;
    r.variables.location_root_granted = '1';

    /* Save NameID to keyval */
    r.variables.nameid = nameID;

    /* Get SAML Attributes */
    let xmlRoot = xmlDoc.Response.Assertion.AttributeStatement.$tags$Attribute;
    let attrs = getAttributes(xmlRoot);
    for (var attributeName in attrs) {
        if (attrs.hasOwnProperty(attributeName)) {
            var attributeValue = attrs[attributeName];
            
            /* Save attributeName and value to the key-value store */
            try {
                r.variables[attributeName] = attributeValue;
            } catch(e) {}
        }
    }

    r.log("SAML SP success, creating session " + authToken);

    r.headersOut["Set-Cookie"] = "auth_token=" + r.variables.cookie_auth_token + "; " + r.variables.saml_cookie_flags;
    r.return(302, "/");
}

function samlError(r, http_code, msg) {
    r.error("samlsp." + msg);
    r.return(http_code, "samlsp." + msg);
}

function generateID(keyLength) {
    keyLength = keyLength > 20 ? keyLength : 20;
    let buf = Buffer.alloc(keyLength);
    return (crypto.getRandomValues(buf)).toString('hex');
}

function getEscapeXML() {
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

function createAuthnRequest(requestID, ssoUrl, acsUrl, forceAuthn, issuer, nameidFormat) {
    /*
     * Identifies a SAML protocol binding to be used when returning the Response message.
     * Only HTTP-POST method is supported for now.
     */
    let protocolBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

    if (nameidFormat === '') {
        nameidFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
    }

    let xml = 
        '<samlp:AuthnRequest' +
            ' xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"' +
            ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"' +
            ' Version="2.0"' +
            ` ID="${requestID}"` +
            ` IssueInstant="${new Date().toISOString()}"` +
            ` Destination="${ssoUrl}"` +
            ` AssertionConsumerServiceURL="${acsUrl}"` +
            ` ProtocolBinding="${protocolBinding}"` +
            ` ForceAuthn="${forceAuthn}"` +
        '>' +
            `<saml:Issuer>${issuer}</saml:Issuer>` +
            '<samlp:NameIDPolicy' +
                ` Format="${nameidFormat}"` +
                ' AllowCreate="true"/>' +
        '</samlp:AuthnRequest>';

    return xml;
}

function normalizeXml(xmlData) {
    let dec = new TextDecoder();
    let xmlDoc = xml.parse(xmlData);
    return dec.decode(xml.exclusiveC14n(xmlDoc));
}

function postAuthnRequest(xmlData, ssoUrl, relayState) {
    let samlRequest = xmlData.toString('base64');
    let form = `<form method="post" action="${ssoUrl}">` +
    `<input type="hidden" name="SAMLRequest" value="${samlRequest}"/>` +
    `<input type="hidden" name="RelayState" value="${relayState}"/>` +
    '</form>';
    let autoSubmit = '<script>document.getElementsByTagName("form")[0].submit();</script>';
    return(form + autoSubmit);
}

function redirectAuthnRequest(xmlData, ssoUrl, relayState) {
    let samlRequest = pako.deflateRaw(xmlData);
    samlRequest = Buffer.from(samlRequest).toString('base64');
    samlRequest = encodeURIComponent(samlRequest);
    let url = ssoUrl + '?SAMLRequest=' + samlRequest;

    if (relayState) {
        url += '&RelayState=' + encodeURIComponent(relayState);
    }

    return(url);
}

function parsePostPayload (payload) {
    let response = payload.toString();
    response = querystring.parse(response);
    let samlResponse = Buffer.from((response.SAMLResponse), 'base64').toString();

    let relayState;
    if (response.RelayState) {
        relayState = Buffer.from((response.RelayState), 'base64').toString();
    }

    return [samlResponse, relayState];
}

function verifySAMLResponse (r, xmlDoc) {
    if (!xmlDoc.Response) {
        throw Error("No Response tag found!");
    }

    const version = xmlDoc.Response.$attr$Version;
    if (version !== "2.0") {
        throw Error (`Invalid SAML Version "${version}".`);
    }

    const acsUrl = r.variables.saml_sp_acs_url;
    const destination = xmlDoc.Response.$attr$Destination;
    if (destination !== acsUrl) {
        throw Error (`The SAML Destination "${destination}" does not match ` +
                     `SP ACS URL "${acsUrl}".`);
    }

    /* const ID = xmlDoc.Response.$attr$ID;
       Need to verify the ID attribute in the SAML response for IDP-initiated SSO. Used for message
       replay protection and for correlating the response with a previous SAML request.
    */

    const inResponseTo = xmlDoc.Response.$attr$InResponseTo;
    if (inResponseTo) {
        r.variables.saml_request_id = inResponseTo;
        if (r.variables.saml_have_session != '1') {
            throw Error (`InResponseTo attribute value "${inResponseTo}" does not match ` +
                         "expected value.");
        }
        r.variables.saml_have_session = '0';
    } else {
        throw Error ("IdP-initiated SSO does not supported yet.");
    }

    return true;
}

function verifyResponseStatus (xmlDoc) {
    const success = "urn:oasis:names:tc:SAML:2.0:status:Success";
    const status = xmlDoc.Response.Status.StatusCode.$attr$Value;

    if (status !== success) {

        let message;
        if (xmlDoc.Response.Status.StatusMessage.$text) {
            message = xmlDoc.Response.Status.StatusMessage.$text;
        }

        throw Error(`status code = "${status}", message = "${message}".`);
    }

    return true;
}

function verifySAMLAssertion (xmlDoc, idpEntityID) {
    const assertion = xmlDoc.Response.Assertion;
    if (!assertion) {
        throw Error("Assertion element is missing in the SAML response.");
    }

    const version = assertion.$attr$Version;
    if (version !== "2.0") {
        throw Error (`Version "${version}" is not supported.`);
    }

    const issuer = assertion.Issuer.$text;
    if (issuer !== idpEntityID) {
        throw Error (`Issuer "${issuer}" does not match IdP EntityID "${idpEntityID}".`);
    }

    const currentTime = new Date();
    const issueInstant = new Date(assertion.IssueInstant);
    if (issueInstant > currentTime) {
        throw new Error('IssueInstant is in the future, which is invalid.');
    }
}

function parseAssertionSubject(xmlDoc, spEntityId) {
    let root = xmlDoc.Response.Assertion.Subject;
    if (!root) {
        throw new Error("Subject element is missing in the SAML Assertion.");
    }

    /* Extract the NameID and NameID Format */
    if (!root.NameID) {
        throw new Error("NameID not found in Subject.");
    }
    const nameID = root.NameID.$text;
    const nameIdFormat = root.NameID.$attr$Format;

    /* Check SubjectConfirmation */
    if (!root.SubjectConfirmation) {
        throw new Error("SubjectConfirmation element is missing in the SAML Subject.");
    }

    /* Needs to be revised because the core spec is not very clear in this */
    root = root.SubjectConfirmation;
    const methodBearer = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
    if (root.$attr$Method === methodBearer) {

        root = root.SubjectConfirmationData;
        if (!root) {
            throw new Error("SubjectConfirmationData element is missing in the SAML SubjectConfirmation.");
        }

        const now = new Date();
        let notOnOrAfter = root.NotOnOrAfter ? new Date(root.NotOnOrAfter) : now;
        if (notOnOrAfter < now) {
            throw new Error(`The Subject has expired. Current time is ${now} and NotOnOrAfter is ${notOnOrAfter}`);
        }

        /* Need to add verification for InResponseTo */

    }

    return nameID;
}

function verifySAMLConditions(xmlDoc, spEntityId) {
    const conditions = xmlDoc.Response.Assertion.Conditions;
    if (!conditions) {
        throw new Error("Conditions element is missing in the SAML response");
    }

    const now = new Date();
    let notBefore = conditions.NotBefore ? new Date(conditions.NotBefore) : now;
    let notOnOrAfter = conditions.NotOnOrAfter ? new Date(conditions.NotOnOrAfter) : now;

    if (notBefore > now) {
        throw new Error(`SAML response is not yet valid. Current time is ${now} and NotBefore is ${notBefore}`);
    }

    if (notOnOrAfter < now) {
        throw new Error(`SAML response has expired. Current time is ${now} and NotOnOrAfter is ${notOnOrAfter}`);
    }

    /* Check the audience restriction */
    if (conditions.AudienceRestriction && conditions.AudienceRestriction.Audience) {
        let audience = conditions.AudienceRestriction.Audience.$text;
        if (!Array.isArray(audience)) {
            audience = [audience];
        }

        const spFound = audience.indexOf(spEntityId) !== -1;
        if (!spFound) {
            throw new Error("The SAML response was not intended for this Service Provider. " + 
                            `Expected audience: ${spEntityId}, received: ${audience}`);
        }
    }

    return true;
}

function getAttributes(xmlRoot) {
    return xmlRoot.reduce((a, v) => {
        a[v.$attr$Name] = v.$tags$AttributeValue.reduce((a, v) => {a.push(v.$text); return a}, []);
        return a
    }, {})
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
