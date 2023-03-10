/*
 * JavaScript functions for providing SAML SP with NGINX Plus
 * 
 * Copyright (C) 2023 Nginx, Inc.
 */

export default {sendAuthnRequest, processIdpResponse, sendSloRequest};

const xml = require("xml");
const querystring = require("querystring");
const fs = require("fs");


async function sendAuthnRequest(r) {
    /* Parse SAML configuration options */
    let opt;
    try {
        opt = parseConfParams(r, 'AuthnRequest');
    } catch (e) {
        samlError(r, 500, `Failed to parse SAML SSO configuration options. ${e.message}`);
        return;
    }

    /* Generate authentication request ID with 160 bits of entropy */
    const requestID = "_" + generateID(20);
    r.variables.saml_request_id = requestID;

    /* Create authentication request XML payload */
    let xmlData;
    try {
        xmlData = await createAuthnRequest(requestID, opt.idpServiceUrl, opt.spServiceUrl, opt.forceAuthn,
                                           opt.spEntityId, opt.nameidFormat, opt.requestSigned,
                                           opt.spPrivKey);
    } catch (e) {
        samlError(r, 500, "Failed to create AuthN request. " + e.message);
    }

    /* Send AuthN request to the IdP using POST or Redirect method */
    if (opt.spBind === 'HTTP-POST') {
        r.headersOut['Content-Type'] = "text/html";
        r.return(200, postSAMLRequest(xmlData, opt.idpServiceUrl, opt.relayState));
    } else {
        r.return(302, redirectSAMLRequest(xmlData, opt.idpServiceUrl, opt.relayState));
    }

    /* Map AuthN request ID to a pending SP-initiated session */
    r.variables.saml_request_inuse = "1";
}

async function sendSloRequest(r) {
    const nameid = r.variables.nameid;
    if (!nameid) {
        samlError(r, 401, 'No SAML SSO session found.');
        return;
    }

    /* Parse SAML configuration options */
    const messageType = "LogoutRequest";
    let opt;
    try {
        opt = parseConfParams(r, messageType);
    } catch (e) {
        samlError(r, 500, `Failed to parse SAML SSO configuration options. ${e.message}`);
        return;
    }

    /* Generate LogoutRequest ID with 160 bits of entropy */
    const requestID = "_" + generateID(20);
    r.variables.saml_request_id = requestID;

    /* Create LogoutRequest XML payload */
    let xmlData;
    try {
        xmlData = await createLogoutRequest(requestID, opt.idpServiceUrl, opt.spEntityId, nameid,
                                            opt.requestSigned, opt.spPrivKey);
    } catch (e) {
        samlError(r, 500, `Failed to create SLO request. ${e.message}`);
    }

    if (opt.requestBinding === 'HTTP-POST') {
        r.headersOut['Content-Type'] = "text/html";
        r.return(200, postSAMLRequest(xmlData, opt.idpServiceUrl, opt.relayState));
    } else {
        r.return(302, redirectSAMLRequest(xmlData, opt.idpServiceUrl, opt.relayState));
    }

    /* Map SLO request ID to a pending SP-initiated Single Logout */
    r.variables.saml_request_inuse = "1";
}

async function sendSloResponse(r, opt) {
    r.error("SAML: sendSloResponse: " + JSON.stringify(opt));
    const statusCode = opt.nameid !== r.variables.nameid ?
                                      'urn:oasis:names:tc:SAML:2.0:status:Responder' :
                                      'urn:oasis:names:tc:SAML:2.0:status:Success';

    const requestID = "_" + generateID(20);
    r.variables.saml_request_id = requestID;

    let xmlData;
    try {
        xmlData = await createLogoutResponse(requestID, opt.inResponseTo, opt.idpServiceUrl,
                                             opt.spEntityId, statusCode, opt.requestSigned,
                                             opt.spPrivKey);
    } catch (e) {
        samlError(r, 500, `Failed to create LogoutResponse message: ${e.message}`);
        return;
    }

    r.log("SAML logout for " + r.variables.nameid);
    r.variables.location_root_granted = "-";
    r.variables.nameid  = "-";
    r.headersOut["Set-Cookie"] = "auth_token=" + "; " + r.variables.saml_cookie_flags;
    if (opt.requestBinding === 'HTTP-POST') {
        r.headersOut['Content-Type'] = "text/html";
        r.return(200, postSAMLRequest(xmlData, opt.idpServiceUrl, opt.relayState));
    } else {
        r.return(302, redirectSAMLRequest(xmlData, opt.idpServiceUrl, opt.relayState));
    }
}

async function processIdpResponse(r) {
    let payload;
    switch (r.method) {
    case 'GET':
        if (!r.variables.arg_SAMLResponse && !r.variables.arg_SAMLRequest) {
            r.return(401, "Unsupported method\n");
            return;
        }
        payload = r.variables.args;
        break;

    case 'POST':
        payload  = r.requestText;
        if (r.headersIn['Content-Type'] != 'application/x-www-form-urlencoded'
            || !payload.length)
        {
            r.return(401, "Unsupported method\n");
            return;
        }
        break;

    default:
        r.return(401, "Unsupported method\n");
        return;
    }

    const method = r.method;
    let samlParams;
    try {
        samlParams = extractSamlParams(payload, method);
    } catch (e) {
        samlError(r, 500, `Failed to extract SAMLResponse parameter from the ${method} request: ` +
                           e.message);
        return;
    }

    /* Parse SAML response for an XML document */
    let xmlDoc;
    try { 
        xmlDoc = xml.parse(samlParams.SAMLResponse);
    } catch (e) {
        samlError(r, 500, "Failed to parse SAMLResponse for an XML document: " +
                           e.message);
        return;
    }

    /* Extract SAML message type from XML */
    let messageType;
    try {
        messageType = getMessageType(xmlDoc);
    } catch (e) {
        samlError(r, 500, e.message);
        return;
    }

    /* Parse SAML configuration parameters */
    let opt;
    try {
        opt = parseConfParams(r, messageType);
    } catch (e) {
        samlError(r, 500, `Failed to parse SAML SSO configuration parameters: ${e.message}`);
        return;
    }

    /* Verify SAML response header */
    let id;
    try {
        let root = xmlDoc[messageType];
        id = await verifyBasicRequirements(r, root, opt);
    } catch (e) {
        samlError(r, 500, `Failed to process ${messageType}: ${e.message}`);
        return;
    }

    if (messageType === "LogoutRequest") {
        const root = xmlDoc[messageType];
        opt.nameid = root.NameID ? root.NameID.$text : undefined;
        opt.inResponseTo = id;
        opt.relayState = samlParams.RelayState;
        sendSloResponse(r, opt);
        return;
    }

    /* Verify Response or LogoutResponse status */
    try {
        verifyStatus(xmlDoc);
    } catch (e) {
        samlError(r, 403, `${messageType} status not successful: ${e.message}`);
        return;
    }

    if (messageType === "LogoutResponse") {
        processLogout(r, samlParams.RelayState);
        return;
    }

    /* Verify SAML Assertion     r.error("processSLO part done: " + JSON.stringify(root));*/
    if (xmlDoc[messageType].EncryptedAssertion) {
        samlError(r, 500, "Failed to process Assertion: Assertion is encrypted");
    }

    try {
        let root = xmlDoc[messageType].Assertion;
        await verifyBasicRequirements(r, root, opt);
    } catch (e) {
        samlError(r, 500, `Failed to process Assertion: ${e.message}`);
        return;
    }

    /* Verify Assertion Subject */
    let subject;
    try {
        subject = parseSubject(xmlDoc);
    } catch (e) {
        samlError(r, 500, `Invalid SAML Assertion Subject: ${e.message}`);
        return;
    }

    /* Verify Assertion conditions */
    try {
        verifyConditions(xmlDoc, opt.spEntityId);
    } catch (e) {
        samlError(r, 500, `Failed to verify Assertion Conditions element: ${e.message}`);
        return;
    }

    /* Verify Assertion AuthnStatement */
    let authnStatement;
    try {
        authnStatement = parseAuthnStatement(xmlDoc);
    } catch (e) {
        samlError(r, 500, `Failed to verify Assertion AuthnStatement element: ${e.message}`);
        return;
    }

    /* Generate cookie_auth_token */
    const authToken =  "_" + generateID();

    /* Save cookie_auth_token to keyval to store SAML session data */
    r.variables.cookie_auth_token = authToken;
    r.variables.location_root_granted = '1';

    /* Save SAML-related variables to keyval */
    r.variables.nameid = subject.nameID;

    if (authnStatement.SessionIndex) {
        try {
            r.variables.sessionindex = authnStatement.SessionIndex;
        } catch(e) {}
    }

    if (authnStatement.AuthnContextClassRef) {
        try {
            r.variables.authncontextclassref = authnStatement.AuthnContextClassRef;
        } catch(e) {}
    }

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

    r.variables.saml_response_used = '1';
    r.headersOut["Set-Cookie"] = "auth_token=" + r.variables.cookie_auth_token + "; " + r.variables.saml_cookie_flags;
    r.return(302, "/");
}

function samlError(r, http_code, msg) {
    r.error("SAML SSO: " + msg);
    r.return(http_code, "SAML SSO: " + msg);
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

function parseConfParams(r, messageType) {
    const escapeXML = getEscapeXML();
    let opt = {};

    /* SP Entity ID */
    opt.spEntityId = escapeXML(r.variables.saml_sp_entity_id);
    if (!isUrlOrUrn(opt.spEntityId)) {
        throw Error(`Invalid "saml_sp_entity_id": "${opt.spEntityId}", must be URI.`);
    }

    /* IDP Entity ID */
    opt.idpEntityId = escapeXML(r.variables.saml_idp_entity_id);
    if (!isUrlOrUrn(opt.idpEntityId)) {
        throw Error(`Invalid "saml_idp_entity_id": "${opt.idpEntityId}", must be URI.`);
    }

    if (messageType == 'Response') {
        /* SP requires SAML Response to be signed */
        opt.wantSignedResponse = r.variables.saml_sp_want_signed_response.toLowerCase();
        if (opt.wantSignedResponse !== 'true' && opt.wantSignedResponse !== 'false') {
            throw Error(`Invalid "saml_sp_want_signed_response": "${opt.wantSignedResponse}", ` +
                        `must be "true" or "false".`);
        }
        opt.wantSignedResponse = (opt.wantSignedResponse === 'true');

        /* SP requires SAML Assertion to be signed */
        opt.wantSignedAssert = r.variables.saml_sp_want_signed_assertion.toLowerCase();
        if (opt.wantSignedAssert !== 'true' && opt.wantSignedAssert !== 'false') {
            throw Error(`Invalid "saml_sp_want_signed_assertion": "${opt.wantSignedAssert}", ` +
                        `must be "true" or "false".`);
        }
        opt.wantSignedAssert = (opt.wantSignedAssert === 'true');
    }

    if (messageType == "AuthnRequest") {
        /* SP AuthnRequest binding method */
        opt.requestBinding = r.variables.saml_sp_request_binding;
        if (opt.requestBinding !== "HTTP-POST" && opt.requestBinding !== "HTTP-Redirect") {
            throw Error(`Invalid "saml_sp_request_binding": "${opt.requestBinding}", ` +
                        `must be "HTTP-POST" or "HTTP-Redirect".`);
        }

        /* IDP requires SAML AuthnRequest to be signed */
        opt.requestSigned = r.variables.saml_idp_sign_authn.toLowerCase();
        if (opt.requestSigned !== "true" && opt.requestSigned !== "false") {
            throw Error(`Invalid "saml_idp_sign_authn": "${opt.requestSigned}", ` +
                        `must be "true" or "false".`);
        }
        opt.requestSigned = (opt.requestSigned === 'true');

        /* SP ForceAuthn */
        opt.forceAuthn = r.variables.saml_sp_force_authn.toLowerCase();
        if (opt.forceAuthn !== 'true' && opt.forceAuthn !== 'false') {
            throw Error(`Invalid "saml_sp_force_authn": "${opt.forceAuthn}", ` +
                        `must be "true" or "false".`);
        }
        opt.forceAuthn = (opt.forceAuthn === 'true');

        /* SP NameID Format */
        opt.nameidFormat = r.variables.saml_sp_nameid_format;
        if (!isValidNameIdFormat(opt.nameidFormat)) {
            throw Error(`Invalid "saml_sp_nameid_format": "${opt.nameidFormat}".`);
        }

        /* SP Relay State */
        opt.relayState = r.variables.saml_sp_relay_state;
    }

    if (messageType == 'Response' || messageType == 'AuthnRequest') {
        /* SP ACS URL */
        opt.spServiceUrl = escapeXML(r.variables.saml_sp_acs_url);
        if (isUrlOrUrn(opt.spServiceUrl) !== "URL") {
            throw Error(`Invalid "saml_sp_acs_url": "${opt.spServiceUrl}", must be URL.`);
        }

        /* IDP SSO URL */
        opt.idpServiceUrl = escapeXML(r.variables.saml_idp_sso_url);
        if (isUrlOrUrn(opt.idpServiceUrl) !== "URL") {
            throw Error(`Invalid "saml_idp_sso_url": "${opt.idpServiceUrl}", must be URL.`);
        }
    }

    if (messageType == 'LogoutRequest') {
        /* SP SLO Request binding method */
        opt.requestBinding = r.variables.saml_sp_slo_binding;
        if (opt.requestBinding !== "HTTP-POST" && opt.requestBinding !== "HTTP-Redirect") {
            throw Error(`Invalid "saml_sp_slo_binding": "${opt.requestBinding}", ` +
                        `must be "HTTP-POST" or "HTTP-Redirect".`);
        }

        /* IDP requires SAML LogoutRequest or LogoutResponse to be signed */
        opt.requestSigned = r.variables.saml_idp_sign_slo;
        if (opt.requestSigned !== "true" && opt.requestSigned !== "false") {
            throw Error(`Invalid "saml_idp_sign_slo": "${opt.requestSigned}", ` +
                        `must be "true" or "false".`);
        }
        opt.requestSigned = (opt.requestSigned === 'true');

        /* SP Relay State */
        opt.relayState = r.variables.saml_logout_landing_page;
    }

    if (messageType == 'LogoutResponse') {
        /* SP requires SAML LogoutRequest or LogoutResponse to be signed */
        opt.wantSignedResponse = r.variables.saml_sp_want_signed_slo.toLowerCase();
        if (opt.wantSignedResponse !== 'true' && opt.wantSignedResponse !== 'false') {
            throw Error(`Invalid "saml_sp_want_signed_response": "${opt.wantSignedResponse}", ` +
                        `must be "true" or "false".`);
        }
        opt.wantSignedResponse = (opt.wantSignedResponse === 'true');
    }

    if (messageType == 'LogoutResponse' || messageType == 'LogoutRequest') {
        /* IDP SLO URL */
        opt.idpServiceUrl = escapeXML(r.variables.saml_idp_slo_url);
        if (isUrlOrUrn(opt.idpServiceUrl) !== "URL") {
            throw Error(`Invalid "saml_idp_slo_url": "${opt.idpServiceUrl}", must be URL.`);
        }

        /* SP SLO URL */
        opt.spServiceUrl = escapeXML(r.variables.saml_sp_slo_url);
        if (isUrlOrUrn(opt.spServiceUrl) !== "URL") {
            throw Error(`Invalid "saml_sp_slo_url": "${opt.spServiceUrl}", must be URL.`);
        }
    }

    if ( opt.wantSignedResponse ||  opt.wantSignedAssert || opt.verifySlo) {
        /* IDP Response or Assertion verification certificate */
        opt.idpPubKey = r.variables.saml_idp_verification_certificate;
    }

    if (opt.requestSigned || opt.requestSigned) {
        /* SP Authentication request signing private key */
        opt.spPrivKey = r.variables.saml_sp_signing_key;
    }

    if (opt.wantSignedResponse || opt.wantSignedAssert) {
        try {
            opt.keyData = fs.readFileSync(opt.idpPubKey);
        } catch (e) {
            throw Error("Failed to read IDP verification public key from file " +
                        `"${opt.idpPubKey}": ${e.message}`);
        }
    }

    return opt;
}

function isUrlOrUrn(str) {
    var urlRegEx = /^(?:https?:\/\/)?[\w.-]+(?:\.[\w.-]+)+[\w\-._~:/?#[\]@!$&'()*+,;=]*$/i;
    var urnRegEx = /^urn:[a-z0-9][a-z0-9-]{1,31}:[a-z0-9()+,\-.:=@;$_!*'%/?#]+$/i;
  
    if (urlRegEx.test(str)) {
      return "URL";
    } else if (urnRegEx.test(str)) {
      return "URN";
    } else {
      return false;
    }
}

function isValidNameIdFormat(nameIdFormat) {
    const allowedFormats = [
        "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
        "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName",
        "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName",
        "urn:oasis:names:tc:SAML:1.1:nameid-format:kerberos",
        "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
        "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
        "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
        "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted",
    ];
    return allowedFormats.includes(nameIdFormat);
}

async function createAuthnRequest(requestID, idpServiceUrl, spServiceUrl, forceAuthn, issuer, nameidFormat,
                                  sign, key) {
    /*
     * Identifies a SAML protocol binding to be used when returning the Response message.
     * Only HTTP-POST method is supported for now.
     */
    let protocolBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

    let authn = 
        '<samlp:AuthnRequest' +
            ' xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"' +
            ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"' +
            ' Version="2.0"' +
            ` ID="${requestID}"` +
            ` IssueInstant="${new Date().toISOString()}"` +
            ` Destination="${idpServiceUrl}"` +
            ` AssertionConsumerServiceURL="${spServiceUrl}"` +
            ` ProtocolBinding="${protocolBinding}"` +
        '>' +
            `<saml:Issuer>${issuer}</saml:Issuer>` +
            '<samlp:NameIDPolicy' +
                ` Format="${nameidFormat}"` +
                ' AllowCreate="true"/>' +
            `${attachSignTemplate(requestID)}` +
        '</samlp:AuthnRequest>';

    const root = (xml.parse(authn)).$root;
    const rootSignature = root.Signature;

    if (forceAuthn) {
        root.setAttribute('ForceAuthn', forceAuthn);
    }

    if (sign) {
        let keyData;
        try {
            keyData = fs.readFileSync(key);
        } catch (e) {
            throw Error(`Failed to read SP private key from file "${key}". ${e.message}`);
        }

        try {
            await digestSAML(rootSignature, true);
            await signatureSAML(rootSignature, keyData, true);
        } catch (e) {
            throw Error(`Failed to sign AuthN request. ${e.message}`);
        }
    } else {
        rootSignature.removeChildren();
    }

    let dec = new TextDecoder();
    return dec.decode(xml.c14n(root));
}

async function createLogoutRequest(requestID, idpServiceUrl, issuer, nameid, sign, key) {
    let slo = 
        '<samlp:LogoutRequest' +
            ' xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"' +
            ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"' +
            ' Version="2.0"' +
            ` ID="${requestID}"` +
            ` IssueInstant="${new Date().toISOString()}"` +
            ` Destination="${idpServiceUrl}"` +
        '>' +
            `<saml:Issuer>${issuer}</saml:Issuer>` +
            `<saml:NameID>${nameid}</saml:NameID>` +
            `${attachSignTemplate(requestID)}` +
        '</samlp:LogoutRequest>';

    const root = (xml.parse(slo)).$root;
    const rootSignature = root.Signature;

    if (sign) {
        let keyData;
        try {
            keyData = fs.readFileSync(key);
        } catch (e) {
            throw Error(`Failed to read SP private key from file "${key}". ${e.message}`);
        }

        try {
            await digestSAML(rootSignature, true);
            await signatureSAML(rootSignature, keyData, true);
        } catch (e) {
            throw Error(`Failed to sign Logout request: ${e.message}`);
        }
    } else {
        rootSignature.removeChildren();
    }

    let dec = new TextDecoder();
    return dec.decode(xml.c14n(root));
}

async function createLogoutResponse(id, inResponseTo, destination, issuer, statusCode, sign, key) {
    let slo = 
        '<samlp:LogoutResponse' +
            ' xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"' +
            ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"' +
            ' Version="2.0"' +
            ` ID="${id}"` +
            ` IssueInstant="${new Date().toISOString()}"` +
            ` InResponseTo="${inResponseTo}"` +
            ` Destination="${destination}"` +
        '>' +
            `<saml:Issuer>${issuer}</saml:Issuer>` +
            `${attachSignTemplate(id)}` +
            '<samlp:Status>' +
                `<samlp:StatusCode Value="${statusCode}"/>` +
            '</samlp:Status>' +
        '</samlp:LogoutResponse>';

    const root = (xml.parse(slo)).$root;
    const rootSignature = root.Signature;

    if (sign) {
        let keyData;
        try {
            keyData = fs.readFileSync(key);
        } catch (e) {
            throw Error(`Failed to read SP private key from file "${key}". ${e.message}`);
        }

        try {
            await digestSAML(rootSignature, true);
            await signatureSAML(rootSignature, keyData, true);
        } catch (e) {
            throw Error(`Failed to sign Logout request: ${e.message}`);
        }
    } else {
        rootSignature.removeChildren();
    }

    let dec = new TextDecoder();
    return dec.decode(xml.c14n(root));
}

function postSAMLRequest(xmlData, idpServiceUrl, relayState) {
    const samlRequest = xmlData.toString('base64');

    if (relayState) {
        relayState = `<input type="hidden" name="RelayState" value="${relayState}"/>`;
    }

    const form = 
    `<form method="post" action="${idpServiceUrl}">` +
        `<input type="hidden" name="SAMLRequest" value="${samlRequest}"/>` +
        relayState +
    '</form>';

    const autoSubmit = '<script>document.getElementsByTagName("form")[0].submit();</script>';

    return(form + autoSubmit);
}

function redirectSAMLRequest(xmlData, idpServiceUrl, relayState) {
    let samlRequest = pako.deflateRaw(xmlData);
    samlRequest = Buffer.from(samlRequest).toString('base64');
    samlRequest = encodeURIComponent(samlRequest);
    let url = idpServiceUrl + '?SAMLRequest=' + samlRequest;

    if (relayState) {
        url += '&RelayState=' + encodeURIComponent(relayState);
    }

    return(url);
}

function extractSamlParams(payload, method) {
    const params = querystring.parse(payload);
    let samlResponse = Buffer.from(decodeURIComponent(params.SAMLResponse ||
                                                      params.SAMLRequest), 'base64');
    const relayState = params.RelayState ? Buffer.from(params.RelayState, 'base64').toString()
                                         : undefined;

    if (method === "GET") {
        samlResponse = pako.inflateRaw(samlResponse);
    }

    return {SAMLResponse: samlResponse, RelayState: relayState};
}

function getMessageType(xmlDoc) {
    const allowedRoots = [
        "Response",
        "LogoutResponse",
        "LogoutRequest",
    ];
    const root = xmlDoc.$root;
    const messageType = root.$name;

    if (!allowedRoots.includes(messageType)) {
        throw Error(`Unsupported SAML message type: "${messageType}"`);
    }

    return messageType;
}

async function verifyBasicRequirements (r, root, opt) {
    const type = root.$name;
    
    /* Check XML namespace for SAML message (Required) */
    const expectedNs = type === 'Assertion'
        ? 'urn:oasis:names:tc:SAML:2.0:assertion'
        : 'urn:oasis:names:tc:SAML:2.0:protocol';

    if (root.$ns !== expectedNs) {
        throw new Error(`Unsupported XML namespace: "${root.$ns}" for ${type}`);
    }

    /* Check SAML message version (Required) */
    if (root.$attr$Version !== "2.0") {
        throw Error (`Unsupported SAML Version: "${root.$attr$Version}"`);
    }

    /* Check the date and time when the SAML message was issued (Required) */
    const currentTime = new Date();
    const issueInstant = new Date(root.$attr$issueInstant);
    if (issueInstant > currentTime) {
        throw Error(`"IssueInstant" is in the future. Check clock skew of SP and IdP`);
    }

    /* Check SAML message ID (Required)  */
    const id = root.$attr$ID;
    if (!id) {
        throw Error (`ID not found in "${type}" message`);
    }

    const inResponseTo = root.$attr$InResponseTo;
    if (inResponseTo) {
        /* SP-initiated SSO or SLO */
        r.variables.saml_request_id = inResponseTo;
        if (r.variables.saml_request_inuse != '1') {
            throw Error (`InResponseTo attribute value "${inResponseTo}" ` +
                         `not found in key-value storage for ${type} message`);
        }
        if (type !== "Response") {
            /* In the case of Response message it will be freed during Assertion processing */
            r.variables.saml_request_inuse = '0';
        }
    }

    /* Check Destination if present (Optional) */
    const destination = root.$attr$Destination;
    if (destination && destination !== opt.spServiceUrl) {
        throw Error (`The SAML Destination "${destination}" does not match ` +
                     `SP ACS URL "${opt.spServiceUrl}"`);
    }

    /* Check Issuer if present (Optional) */
    const issuer = root.Issuer.$text;
    if (issuer && issuer !== opt.idpEntityId) {
        throw Error (`Issuer "${root.Issuer.$text}" does not match IdP EntityID ` +
                     `"${opt.idpEntityId}"`);
    }

    /* Verify SAML Response signature if required */
    if ( (opt.wantSignedResponse && type === 'Response') || 
         (opt.wantSignedAssert && type === 'Assertion') ) {
        try {
            const rootSignature = root.Signature;
            await verifySAMLSignature(rootSignature, opt.keyData);
        } catch (e) {
            throw Error (`Error verifying SAML ${type} message signature: ${e.message}`);
        }
    }

    /* Protection against SAML replay attacks */
    r.variables.saml_response_id = id;
    if (r.variables.saml_response_used == '1') {
        throw Error (`An attempt to reuse a ${type} ID was detected: ` +
                     `ID "${id}" has already been redeemed`);
    }

    return id;
}

function verifyStatus (xmlDoc) {
    const root = xmlDoc.$root.Status;
    const statusCode = root.StatusCode.$attr$Value;

    const success = "urn:oasis:names:tc:SAML:2.0:status:Success";
    if (statusCode !== success) {
        let message = "StatusCode: " + statusCode;
        if (root.statusMessage) {
            message += ", SatusMessage: " + root.statusMessage.$text;
        }

        if (root.statusDetail) {
            message += ", StatusDetail: " + JSON.stringify(root.statusDetail);
        }

        throw Error(message);
    }
}

function parseSubject(xmlDoc) {
    let root = xmlDoc.Response.Assertion.Subject;
    if (!root) {
        throw new Error("Subject element is missing in the SAML Assertion");
    }

    /* Extract the NameID and NameID Format */
    if (!root.NameID) {
        throw new Error("NameID not found in Subject");
    }
    const nameID = root.NameID.$text;

    const nameIdFormat = root.NameID.$attr$Format && root.NameID.$attr$Format;

    /* Check SubjectConfirmation */
    if (root.SubjectConfirmation) {
        root = root.SubjectConfirmation;
        const methodBearer = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
        if (root.$attr$Method === methodBearer) {
            root = root.SubjectConfirmationData;
            if (!root) {
                throw new Error('SubjectConfirmationData element is missing in SAML ' +
                                'SubjectConfirmation');
            }

            const now = new Date();
            let notOnOrAfter = root.NotOnOrAfter ? new Date(root.NotOnOrAfter) : now;
            if (notOnOrAfter < now) {
                throw new Error(`The Subject has expired. Current time is ${now} ` +
                                `and NotOnOrAfter is ${notOnOrAfter}`);
            }
        }
    }

    return {nameID: nameID, nameIdFormat: nameIdFormat};
}

function verifyConditions(xmlDoc, spEntityId) {
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
            throw new Error("The SAML Assertion is not intended for this Service Provider. " + 
                            `Expected audience: ${spEntityId}, received: ${audience}`);
        }
    }

    return true;
}

function parseAuthnStatement(xmlDoc, maxAuthenticationAge) {
    let root = xmlDoc.Response.Assertion.AuthnStatement;
    if (!root) {
        return;
    }

    const authnInstant = root.$attr$AuthnInstant;
    if (!authnInstant) {
        throw Error("AuthnInstant attribute not found");
    }

    /* Placeholder for future maxAuthenticationAge conf option */
    if (maxAuthenticationAge) {
        const authnInstantDate = new Date(authnInstant);
        const now = new Date();
        if (now.getTime() - authnInstantDate.getTime() > maxAuthenticationAge*1000) {
            return false;
        }
    }

    const sessionIndex = root.$attr$SessionIndex;

    const sessionNotOnOrAfter = root.$attr$sessionNotOnOrAfter;
    if (sessionNotOnOrAfter) {
        var sessionNotOnOrAfterDate = new Date(sessionNotOnOrAfter);
        var now = new Date();
        if (sessionNotOnOrAfterDate.getTime() < now.getTime()) {
            throw Error('Session expired');
        }
    }

    root = root.AuthnContext;

    if (!root) {
        throw Error('AuthnContext element not found');
    }
    
    const authnContextClassRef = root.AuthnContextClassRef.$text;

    return {SessionIndex: sessionIndex, AuthnContextClassRef: authnContextClassRef};
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

async function verifySAMLSignature(rootSignature, key_data) {
    if (!rootSignature) {
        throw Error(`Message is unsigned`);
    }

    if (rootSignature) {
        if (!await digestSAML(rootSignature)) {
            return false;
        }

        if (!await signatureSAML(rootSignature, key_data)) {
            return false;
        }
    }

    return true;
}

async function digestSAML(signature, produce) {
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
    default:
        throw Error(`unexpected digest Algorithm ${alg}`);
    }

    const c14n = xml.exclusiveC14n(parent, signature, withComments, prefixList);
    const dgst = await crypto.subtle.digest(hash, c14n);
    const b64dgst = Buffer.from(dgst).toString('base64');

    if (produce) {
        signedInfo.Reference.DigestValue.$text = b64dgst;
        return b64dgst;
    }

    const expectedDigest = signedInfo.Reference.DigestValue.$text;

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

async function signatureSAML(signature, key_data, produce) {
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
    default:
        throw Error(`unexpected signature Algorithm ${alg}`);
    }

    const withComments = signedInfo.CanonicalizationMethod
                         .$attr$Algorithm.slice(39) == 'WithComments';

    const signedInfoC14n = xml.exclusiveC14n(signedInfo, null, withComments);

    if (produce) {
        const der = keyPem2Der(key_data, "PRIVATE");
        const key = await crypto.subtle.importKey("pkcs8", der, { name: method, hash },
                                                  false, [ "sign" ]);

        let sig =  await crypto.subtle.sign({ name: method }, key, signedInfoC14n);

        signature.SignatureValue.$text = Buffer.from(sig).toString('base64');
        return signature;
    }

    const der = keyPem2Der(key_data, "PUBLIC");
    const key = await crypto.subtle.importKey("spki", der, { name: method, hash },
                                              false, [ "verify" ]);

    const expectedValue = base64decode(signature.SignatureValue.$text);
    return await crypto.subtle.verify({ name: method }, key, expectedValue,
                                      signedInfoC14n);
}

function attachSignTemplate(ID) {
    const signTemplate =
        '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">' +
            '<ds:SignedInfo>' +
                '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />' +
                '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />' +
                `<ds:Reference URI="#${ID}">` +
                    '<ds:Transforms>' +
                        '<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />' +
                        '<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />' +
                    '</ds:Transforms>' +
                    '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />' +
                    '<ds:DigestValue></ds:DigestValue>' +
                '</ds:Reference>' +
            '</ds:SignedInfo>' +
            '<ds:SignatureValue></ds:SignatureValue>' +
        '</ds:Signature>';

    return signTemplate;
}

function processLogout(r, relayState) {
    if (!relayState) {
        relayState = '/';
    }
    r.log("SAML logout for " + r.variables.cookie_auth_token);
    r.variables.location_root_granted = "-";
    r.variables.nameid  = "-";
    r.headersOut["Set-Cookie"] = "auth_token=" + "; " + r.variables.saml_cookie_flags;
    r.return(302, relayState);
}