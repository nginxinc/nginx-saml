/*
 * JavaScript functions for providing SAML SP with NGINX Plus
 * 
 * Copyright (C) 2023 Nginx, Inc.
 */

export default {
    handleSingleSignOn,     // Process SAML Response form IdP
    handleSingleLogout,     // Process SAML LogoutRequest and LogoutResponse from IdP
    handleAllMessages,      // Process all SAML messages from IdP
    initiateSingleSignOn,   // Initiate SAML SSO by redirecting to IdP
    initiateSingleLogout    // Initiate SAML SLO by redirecting to IdP
};

const xml = require("xml");
const zlib = require("zlib");
const querystring = require("querystring");
const fs = require("fs");

const initiateSingleSignOn = produceSAMLMessage.bind(null, "AuthnRequest");
const initiateSingleLogout = produceSAMLMessage.bind(null, "LogoutRequest");
const handleSingleSignOn = handleSAMLMessage.bind(null, ["Response"]);
const handleSingleLogout = handleSAMLMessage.bind(null, ["LogoutRequest", "LogoutResponse"]);
const handleAllMessages = handleSAMLMessage.bind(null, ["Response", "LogoutRequest", "LogoutResponse"]);

/**
 * Processing incoming SAML messages (Response, LogoutResponse, LogoutRequest).
 * @param {Array} messageType - Array of expected SAML message types.
 * @param {object} r - The request object.
 */
async function handleSAMLMessage(messageType, r) {
    let id;
    try {
        let nameID, node;

        /* Extract SAML parameters from the HTTP request */
        const params = extractSAMLParameters(r);

        /* Parse the SAML message for an XML document */
        let root = xml.parse(params.SAMLResponse).$root;

        /* Check the message type and validate the configuration */
        messageType = checkSAMLMessageType(root, messageType);
        const opt = parseConfigurationOptions(r, messageType);

        /* Process the message header and verify the issuer */
        id = processSAMLMessageHeader(r, opt, root);
        checkIssuer(root.Issuer, opt.idpEntityID);

        /* Verify the SAML signature if required */
        opt.wantSignedResponse && await verifySAMLSignature(root, opt.verifyKeys);

        /* Check for SAML replay attacks */
        checkReplayAttack(r, id, messageType);

        /* Handle different SAML message types */
        switch (messageType) {
            case 'Response':
                /* Verify the SAML Response status */
                verifyResponseStatus(root.Status);

                /* Decrypt the Encrypted Assertion if present */
                if (root.EncryptedAssertion) {
                    root = await decryptSAML(root.EncryptedAssertion, opt.decryptKey);
                }

                /* Process the Assertion header and verify the issuer */
                opt.assertionId = processSAMLMessageHeader(r, opt, root.Assertion);
                checkIssuer(root.Assertion.Issuer, opt.idpEntityID);

                /* Verify the SAML Assertion signature if required */
                opt.wantSignedAssertion && await verifySAMLSignature(root.Assertion, opt.verifyKeys);

                /* Exctract NameID, NameIDFormat and check the SubjectConfirmation if present */
                node = root.Assertion.Subject.NameID ? root.Assertion.Subject.NameID
                                                     : root.Assertion.Subject.EncryptedID || null;
                nameID = await extractNameID(node, opt.decryptKey);
                checkSubjectConfirmation(root.Assertion.Subject.SubjectConfirmation);

                /* Parse the Asserttion Conditions and Authentication Statement */
                checkConditions(root.Assertion.Conditions, opt.spEntityID);
                const authnStatement = parseAuthnStatement(root.Assertion.AuthnStatement);

                /* Set session cookie and save SAML variables and attributes */
                const sessionCookie = setSessionCookie(r);
                saveSAMLVariables(r, nameID, authnStatement);
                saveSAMLAttributes(r, root.Assertion.AttributeStatement);

                /* Redirect the user after successful login */
                postLoginRedirect(r, params.RelayState || opt.relayState);
                r.variables.location_root_granted = '1';
                r.log("SAML SP success, creating session " + sessionCookie);
                return;
            case 'LogoutRequest':
                /* Exctract NameID and NameIDFormat */
                node = root.NameID ? root.NameID : root.EncryptedID || null;
                nameID = await extractNameID(node, opt.decryptKey);

                /* Define necessary parameters needed to create a SAML LogoutResponse */
                opt.nameID = nameID[0];
                opt.inResponseTo = id;
                opt.relayState = params.RelayState;

                /* Rewrite the LogoutResponse URL if configured */
                opt.idpServiceURL = opt.logoutResponseURL || opt.idpServiceURL;

                /* Issue a SAML LogoutResponse */
                await produceSAMLMessage('LogoutResponse', r, opt);
                return;
            case 'LogoutResponse':
                /* Verify the SAML LogoutResponse status */
                verifyResponseStatus(root.Status);

                /* Clear the session cookie and redirect the user */
                clearSession(r);
                postLogoutRedirect(r, params.RelayState);
                return;
        }
    } catch (e) {
        samlError(r, 500, id, e);
    }
}

function samlError(r, http_code, id, e) {
    let msg = r.variables.saml_debug ? e.stack : "ReferenceError: " + e.message;    
    r.error(`SAML SSO Error: ReferenceID: ${id} ${msg}`);

    r.variables.internal_error_message += `ReferenceID: ${id}`;
    r.variables.internal_error_details = msg;

    r.return(http_code);
}

/**
 * Processes the SAML message header, validating the required fields and checking optional
 * fields, such as Destination, according to the SAML 2.0 Core specification:
 * https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
 *
 * - ID attribute (Required, see section 1.3.4): A unique identifier for the SAML message.
 * - InResponseTo attribute (Optional, see section 3.2.2 for SSO and 3.7.3.1 for SLO):
 *   Indicates that the SAML message is a response to a previous request.
 * - IssueInstant attribute (Required, see section 1.3.4): The timestamp when the SAML message
 *   was issued.
 * - Destination attribute (Optional, see section 3.2.2 for SSO and 3.7.3.1 for SLO):
 *   The intended recipient of the SAML message.
 *
 * @param {Object} r - The incoming request object.
 * @param {Object} opt - An object containing the SP options, including the SP Service URL.
 * @param {Object} root - The SAML root element containing the message header.
 * @returns {string} - The SAML message ID attribute.
 * @throws {Error} - If the SAML message header contains invalid or unsupported values.
 */
function processSAMLMessageHeader(r, opt, root) {
    const type = root.$name;
    
    /* Check XML namespace for SAML message (Required) */
    const expectedNs = type === 'Assertion'
        ? 'urn:oasis:names:tc:SAML:2.0:assertion'
        : 'urn:oasis:names:tc:SAML:2.0:protocol';

    if (root.$ns !== expectedNs) {
        throw Error(`Unsupported XML namespace: "${root.$ns}" for ${type}`);
    }

    /* Check SAML message version (Required) */
    if (root.$attr$Version !== "2.0") {
        throw Error (`Unsupported SAML Version: "${root.$attr$Version}"`);
    }

    /* Check the date and time when the SAML message was issued (Required) */
    const currentTime = new Date();
    const issueInstant = new Date(root.$attr$issueInstant);
    if (issueInstant > currentTime) {
        throw Error(`IssueInstant is in the future. Check clock skew of SP and IdP`);
    }

    /* Check SAML message ID (Required)  */
    const id = root.$attr$ID;
    if (!id) {
        throw Error (`ID attribute is missing in the ${type} element`);
    }

    const inResponseTo = root.$attr$InResponseTo;
    if (inResponseTo) {
        /* SP-initiated SSO or SLO */
        r.variables.saml_request_id = inResponseTo;
        if (r.variables.saml_request_redeemed != '1') {
            throw Error (`InResponseTo attribute value "${inResponseTo}" ` +
                         `not found in key-value storage for ${type} message`);
        }
    }

    /* Check Destination if present (Optional) */
    const destination = root.$attr$Destination;
    if (destination && destination !== opt.spServiceURL) {
        throw Error (`The SAML Destination "${destination}" does not match ` +
                     `SP ACS URL "${opt.spServiceURL}"`);
    }

    return id;
}

/**
 * Checks the Issuer element in the SAML message according to the SAML 2.0 Core specification:
 * https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
 *
 * The Issuer element (section 2.2.5) contains the SAML authority's unique identifier.
 * This function checks if the issuer in the SAML message matches the expected IdP EntityID.
 *
 * @param {Object} root - The SAML Issuer element.
 * @param {string} idpEntityId - The expected IdP EntityID.
 * @throws {Error} - If the Issuer in the SAML message does not match the expected IdP EntityID.
 */
function checkIssuer(root, idpEntityId) {
    const issuer = root.$text;
    if (issuer && issuer !== idpEntityId) {
        throw Error (`Issuer "${issuer}" does not match IdP EntityID "${idpEntityId}"`);
    }
}

/**
 * Verifies the SAML response status.
 * 
 * According to SAML 2.0 Core specification (section 3.2.2.2):
 * https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
 * The <StatusCode> element contains the primary status code indicating the 
 * success or failure of the corresponding request. The <StatusMessage> and
 * <StatusDetail> elements provide additional information.
 *
 * @param {Object} root - A SAML status XMLDoc object returned by xml.parse().
 * @throws {Error} - If the SAML status is not "Success".
 */
function verifyResponseStatus (root) {
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

/**
 * Extracts the NameID value and format from the given SAML root element, optionally
 * decrypting it if it's encrypted.
 *
 * @param {Object} root - The SAML root element containing the NameID or EncryptedID.
 * @param {string} keyData - The private key to decrypt the EncryptedID, if present.
 * @returns {Promise<[string, string]>} - A promise that resolves to a tuple containing the
 *                                       NameID value and format.
 * @throws {Error} - If the NameID element is missing in the Subject.
 */
async function extractNameID(root, keyData) {
    if (!root) {
        throw Error("NameID element is missing in the Subject");
    }

    const isEncrypted = root.$name === 'EncryptedID';
    if (isEncrypted) {
        root = (await decryptSAML(root, keyData)).NameID;
    }

    return [root.$text, root.$attr$Format];
}

/**
 * Checks the SubjectConfirmation element in the SAML response.
 * 
 * According to SAML 2.0 Core specification (section 2.4.1.1 and 2.4.1.2):
 * https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
 * The <SubjectConfirmation> element is used to provide additional
 * information required to confirm the subject. The most common method is
 * "urn:oasis:names:tc:SAML:2.0:cm:bearer".
 * 
 * @param {Object} root - A SAML SubjectConfirmation XMLDoc object returned by xml.parse().
 * @throws {Error} - If the SubjectConfirmationData is missing or the subject has expired.
 */
function checkSubjectConfirmation(root) {
    if (!root) {
        return;
    }

    if (root.$attr$Method === "urn:oasis:names:tc:SAML:2.0:cm:bearer") {
        root = root.SubjectConfirmationData;
        if (!root) {
            throw new Error('SubjectConfirmationData element is missing in the ' +
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

/**
 * Checks the Conditions element in the SAML Assertion.
 * 
 * According to SAML 2.0 Core specification (section 2.5.1.1):
 * https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
 * The <Conditions> element is used to specify conditions that must be evaluated
 * when assessing the validity of and/or evaluating an assertion.
 * 
 * @param {Object} root - A SAML Conditions XMLDoc object returned by xml.parse().
 * @param {string} spEntityId - The EntityID of the Service Provider (SP).
 * @throws {Error} - If Conditions element is missing or the assertion is not valid or expired.
 *                   Also throws an error if the audience restriction is not satisfied.
 */
function checkConditions(root, spEntityId) {
    if (!root) {
        throw Error("Conditions element is missing in the Assertion");
    }

    const now = new Date();
    const notBefore = root.NotBefore ? new Date(root.NotBefore) : now;
    const notOnOrAfter = root.NotOnOrAfter ? new Date(root.NotOnOrAfter) : now;

    if (notBefore > now) {
        throw Error(`The Assertion is not yet valid. Current time is ${now} and ` +
                    `NotBefore is ${notBefore}`);
    }

    if (notOnOrAfter < now) {
        throw Error(`The Assertion has expired. Current time is ${now} and ` +
                    `NotOnOrAfter is ${notOnOrAfter}`);
    }

    /* Check the audience restriction */
    if (root.AudienceRestriction && root.AudienceRestriction.Audience) {
        let audience = root.AudienceRestriction.Audience.$text;
        if (!Array.isArray(audience)) {
            audience = [audience];
        }

        const spFound = audience.indexOf(spEntityId) !== -1;
        if (!spFound) {
            throw Error("The Assertion is not intended for this Service Provider. " + 
                        `Expected audience: ${spEntityId}, received: ${audience}`);
        }
    }
}

/**
 * Parses the AuthnStatement element in the SAML Assertion.
 * 
 * According to SAML 2.0 Core specification (section 2.7.2):
 * https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
 * The <AuthnStatement> element describes the act of authentication performed
 * on the principal by the identity provider (IdP).
 * 
 * @param {Object} root - A SAML AuthnStatement XMLDoc object returned by xml.parse().
 * @param {number} [maxAuthenticationAge] - The maximum age (in seconds) of the authentication
 *                                          statement. If provided, the function will check
 *                                          if the AuthnInstant is within the allowed age.
 * @throws {Error} - If AuthnInstant, SessionNotOnOrAfter, or AuthnContext elements are missing,
 *                   invalid, or expired.
 * @returns {Object} - An object with SessionIndex and AuthnContextClassRef properties.
 */
function parseAuthnStatement(root, maxAuthenticationAge) {
    /* AuthnStatement element is optional */
    if (!root) {
        return;
    }

    const authnInstant = root.$attr$AuthnInstant;
    if (!authnInstant) {
        throw Error("The AuthnInstant attribute is missing in the AuthnStatement");
    }

    /* Placeholder for future maxAuthenticationAge conf option */
    if (maxAuthenticationAge) {
        const authnInstantDate = new Date(authnInstant);
        const now = new Date();
        if (now.getTime() - authnInstantDate.getTime() > maxAuthenticationAge*1000) {
            return false;
        }
    }

    const sessionIndex = root.$attr$SessionIndex || null;

    const sessionNotOnOrAfter = root.$attr$SessionNotOnOrAfter;
    if (sessionNotOnOrAfter) {
        const sessionNotOnOrAfterDate = new Date(sessionNotOnOrAfter);
        const now = new Date();
        if (sessionNotOnOrAfterDate.getTime() < now.getTime()) {
            throw Error(`The Assertion Session has expired. Current time is ${now} and ` +
                        `SessionNotOnOrAfter is ${sessionNotOnOrAfterDate}`);
        }
    }

    root = root.AuthnContext;

    if (!root) {
        throw Error('The AuthnContext element is missing in the AuthnStatement');
    }
    
    const authnContextClassRef = root.AuthnContextClassRef.$text;

    return [sessionIndex, authnContextClassRef];
}

function saveSAMLVariables(r, nameID, authnStatement) {
    r.variables.saml_name_id = nameID[0];
    r.variables.saml_name_id_format = nameID[1];

    if (authnStatement[0]) {
        try {
            r.variables.saml_session_index = authnStatement[0];
        } catch(e) {}
    }

    if (authnStatement[1]) {
        try {
            r.variables.saml_authn_context_class_ref = authnStatement[1];
        } catch(e) {}
    }
}

/**
 * Extracts attributes from a SAML attribute statement and returns them as an object.
 *
 * @param {Object} root - A SAML attribute statement XMLDoc object returned by xml.parse().
 * @returns {Object} - An object containing the attributes, with the attribute names as keys and
 *                     attribute values as arrays of values.
 */
function getAttributes(root) {
    return root.reduce((a, v) => {
        a[v.$attr$Name] = v.$tags$AttributeValue.reduce((a, v) => {
            a.push(v.$text);
            return a;
        }, []);
        return a;
    }, {});
}

function saveSAMLAttributes(r, root) {
    let attrs = getAttributes(root.$tags$Attribute);
    for (var attributeName in attrs) {
        if (attrs.hasOwnProperty(attributeName)) {
            var attributeValue = attrs[attributeName];

            /* Save attributeName and value to the key-value store */
            try {
                r.variables['saml_attrib_' + attributeName] = attributeValue;
            } catch(e) {}
        }
    }
}

function extractSAMLParameters(r) {
    try {
        const payload = getPayload(r);
        if (!payload) {
            throw Error("Unsupported HTTP method");
        }
        return parsePayload(payload, r.method);
    } catch (e) {
        throw Error(`Failed to extract SAMLRequest or SAMLResponse parameter ` +
                    `from the ${r.method} request: ${e.message}`);
    }
}

function getPayload(r) {
    switch (r.method) {
        case 'GET':
            return r.variables.arg_SAMLResponse || r.variables.arg_SAMLRequest ? r.variables.args
                                                                               : null;
        case 'POST':
            return r.headersIn['Content-Type'] === 'application/x-www-form-urlencoded'
                                               && r.requestText.length ? r.requestText : null;
        default:
            return null;
    }
}

function parsePayload(payload, method) {
    const params = querystring.parse(payload);
    let samlResponse = Buffer.from(decodeURIComponent(params.SAMLResponse || params.SAMLRequest),
                               'base64');
    let relayState = decodeURIComponent(params.RelayState || "")

    if (method === "GET") {
        samlResponse = zlib.inflateRawSync(samlResponse);
    }

    return {SAMLResponse: samlResponse, RelayState: relayState};
}

function checkSAMLMessageType(root, messageType) {
    const type = root.$name;
    if (!messageType.includes(type)) {
        throw Error(`Unsupported SAML message type: "${messageType}"`);
    }

    return type;
}

/**
 * Generates a random string ID with a specified length.
 *
 * @param {number} keyLength - Length of the generated ID. If it's less than 20,
 * the default value of 20 will be used.
 * @returns {string} - A randomly generated string ID in hexadecimal format.
 */
function generateID(keyLength) {
    keyLength = keyLength > 20 ? keyLength : 20;
    let buf = Buffer.alloc(keyLength);
    return (crypto.getRandomValues(buf)).toString('hex');
}

function setSessionCookie(r) {
    /* Generate cookie_auth_token */
    const authToken =  "_" + generateID();

    /* Save cookie_auth_token to keyval to store SAML session data */
    r.variables.cookie_auth_token = authToken;

    /* Set cookie_auth_token in the cookie */
    r.headersOut["Set-Cookie"] = `auth_token=${authToken}; ${r.variables.saml_cookie_flags}`;

    return authToken;
}

/**
 * Checks for potential replay attacks by verifying if a SAML message ID has already been used.
 * 
 * According to SAML 2.0 Core specification (section 1.3.4):
 * https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
 * Replay attacks can be prevented by ensuring that each SAML message ID is unique and
 * is not reused within a reasonable time frame.
 *
 * @param {Object} r - The request object.
 * @param {string} id - The SAML message ID.
 * @param {string} type - The SAML message type (e.g., 'Response' or 'LogoutResponse').
 * @throws {Error} - If a replay attack is detected (the SAML message ID has already been used).
 */
function checkReplayAttack(r, id, type) {
    r.variables.saml_response_id = id;
    if (r.variables.saml_response_redeemed === '1') {
        throw Error (`An attempt to reuse a ${type} ID was detected: ` +
                     `ID "${id}" has already been redeemed`);
    }
    r.variables.saml_response_redeemed = '1';
}

function postLoginRedirect(r, relayState) {
    /* If RelayState is not set in the case of IDP-initiated SSO, redirect to the root */
    relayState = relayState || r.variables.cookie_auth_redir || '/';

    const redirectUrl = (r.variables.redirect_base || '') + relayState;

    r.return(302, redirectUrl);
}

function postLogoutRedirect(r, relayState) {
    let redirectUrl = r.variables.redirect_base || '';
    redirectUrl += relayState;
    r.return(302, redirectUrl);
}

function clearSession(r) {
    r.log("SAML logout for " + r.variables.saml_name_id);
    r.variables.location_root_granted = "-";
    r.variables.saml_name_id = "-";

    const cookieFlags = r.variables.saml_cookie_flags;
    const expired = 'Expires=Thu, 01 Jan 1970 00:00:00 GMT; ';
    r.headersOut['Set-Cookie'] = [
        "auth_token=; " + expired + cookieFlags,
        "auth_redir=; " + expired + cookieFlags
    ];
}

/**
 * Generates an outgoing SAML message based on the messageType parameter.
 * @param {string} messageType - The type of the SAML message (AuthnRequest, LogoutRequest, or LogoutResponse).
 * @param {object} r - The NGINX request object.
 * @param {object} opt - Optional object containing configuration options.
 * @returns {Promise<void>}
 * @throws {Error} - If there is an issue processing the SAML request.
 */
async function produceSAMLMessage(messageType, r, opt) {
    let id;
    try {
        /* Validate SAML message type */
        validateMessageType(messageType);

        /** 
         * Parse configuration options based on messageType. For the case of the LogoutResponse,
         * we reuse the 'opt' object, since it defines by the LogoutRequest.
         */
        opt = opt || parseConfigurationOptions(r, messageType);

        /* Generate a unique ID for the SAML message */
        id = "_" + generateID(20);

        /* Handle messageType actions */
        switch (messageType) {
            case "AuthnRequest":
                /* Save the original request uri to the "auth_redir" cookie */
                setAuthRedirCookie(r);
                break;
            case "LogoutRequest":
                /**
                 * Perform simple session termination if SAML SLO is disabled or if the
                 * session has already expired or not found.
                 */
                if (!opt.nameID || opt.isSLODisabled) {
                    clearSession(r)
                    postLogoutRedirect(r, opt.relayState);
                    return;
                }
                break;
            case "LogoutResponse":
                /* Obtain the status code for the LogoutResponse message */
                opt.statusCode = getLogoutStatusCode(r.variables.saml_name_id, opt.nameID)
                break;
        }

        /* Create the SAML message based on messageType */
        const xmlDoc = await createSAMLMessage(opt, id, messageType);

        /* Clear session if LogoutResponse StatusCode is Success */
        (opt.statusCode === 'urn:oasis:names:tc:SAML:2.0:status:Success') && clearSession(r);

        /* Determine whether the HTTP response should be sent via POST or GET and dispatch */
        const isPost = opt.requestBinding === 'HTTP-POST';
        const postParam = messageType === 'LogoutResponse' ? 'SAMLResponse' : 'SAMLRequest';
        dispatchResponse(r, xmlDoc, opt.idpServiceURL, opt.relayState, postParam, isPost);

        /* Set SAML request ID and redeemed flag */
        r.variables.saml_request_id = id;
        r.variables.saml_request_redeemed = "1";
    } catch (e) {
        samlError(r, 500, id, e);
    }
}

/**
 * Validates the messageType, ensuring that it is one of the allowed values.
 * @param {string} messageType - The type of the SAML message.
 * @throws {Error} - If the messageType is not one of the allowed values.
 */
function validateMessageType(messageType) {
    const allowedMessageTypes = ['AuthnRequest', 'LogoutRequest', 'LogoutResponse'];
    if (!allowedMessageTypes.includes(messageType)) {
        throw new Error(`Invalid messageType: ${messageType}. ` +
                        `Allowed values are: ${allowedMessageTypes.join(', ')}`);
    }
}

function setAuthRedirCookie(r) {
    r.headersOut['Set-Cookie'] = [
        "auth_redir=" + r.variables.request_uri + "; " + r.variables.saml_cookie_flags
    ];
}

function getLogoutStatusCode(sessionNameID, requestNameID) {
    /* If no session exists, return Logout Success */
    if (!sessionNameID || sessionNameID === '-') {
        return 'urn:oasis:names:tc:SAML:2.0:status:Success';
    }

    /* If session exists, return Logout Success if NameID matches */
    return requestNameID === sessionNameID
        ? 'urn:oasis:names:tc:SAML:2.0:status:Success'
        : 'urn:oasis:names:tc:SAML:2.0:status:Requester';
}

async function createSAMLMessage(opt, id, messageType) {
    const handlers = {
        AuthnRequest: () => ({
            assertionConsumerServiceURL: ` AssertionConsumerServiceURL="${opt.spServiceURL}"`,
            protocolBinding: ' ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"',
            forceAuthn: opt.forceAuthn ? ' ForceAuthn="true"' : null,
            nameIDPolicy: `<samlp:NameIDPolicy Format="${opt.nameIDFormat}" AllowCreate="true"/>`,
        }),
        LogoutRequest: () => ({
            nameID: `<saml:NameID>${opt.nameID}</saml:NameID>`,
        }),
        LogoutResponse: () => ({
            inResponseTo: ` InResponseTo="${opt.inResponseTo}"`,
            status: `<samlp:Status><samlp:StatusCode Value="${opt.statusCode}"/></samlp:Status>`,
        }),
    };

    const handlerResult = handlers[messageType]();
    const assertionConsumerServiceURL = handlerResult.assertionConsumerServiceURL || "";
    const protocolBinding = handlerResult.protocolBinding || "";
    const forceAuthn = handlerResult.forceAuthn || "";
    const nameIDPolicy = handlerResult.nameIDPolicy || "";
    const nameID = handlerResult.nameID || "";
    const inResponseTo = handlerResult.inResponseTo || "";
    const status = handlerResult.status || "";

    let message = 
        `<samlp:${messageType}` +
            ' xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"' +
            ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"' +
            ' Version="2.0"' +
            ` ID="${id}"` +
            ` IssueInstant="${new Date().toISOString()}"` +
            ` Destination="${opt.idpServiceURL}"` +
            inResponseTo +
            assertionConsumerServiceURL +
            protocolBinding +
            forceAuthn +
        '>' +
            `<saml:Issuer>${opt.spEntityID}</saml:Issuer>` +
            `${opt.isSigned ? samlSignatureTemplate(id) : ''}` +
            nameID +
            nameIDPolicy +
            status +
        `</samlp:${messageType}>`;

    let root;
    try {
        root = (xml.parse(message)).$root;
    } catch (e) {
        throw Error(`Failed to create ${messageType} from XML template: ${e.message}`);
    }

    if (opt.isSigned) {
        try {
            const rootSignature = root.Signature;
            await digestSAML(rootSignature, true);
            await signatureSAML(rootSignature, opt.signKey, true);
        } catch (e) {
            throw Error(`Failed to sign ${messageType}: ${e.message}`);
        }
    }

    return xml.serializeToString(root);
}

/**
 * Generates a SAML signature XML template with the provided ID.
 *
 * @param {string} id - The ID to use as a reference within the signature template.
 * @returns {string} - The SAML signature XML template with the specified ID.
 */
function samlSignatureTemplate(id) {
    const signTemplate =
        '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">' +
            '<ds:SignedInfo>' +
                '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />' +
                '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />' +
                `<ds:Reference URI="#${id}">` +
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

function postFormTemplate(samlMessage, idpServiceUrl, relayState, messageType ) {
    relayState = relayState ? `<input type="hidden" name="RelayState" value="${relayState}" />` : "";

    return `
    <!DOCTYPE html>
    <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
    <head>
        <meta http-equiv="content-type" content="text/html; charset=utf-8" />
        <title>NGINX SAML SSO</title>
    </head>
    <body>
        <script>
            window.onload = function() {
                document.getElementById("submitButton").style.display = "none";                
                document.forms[0].submit();
            };
        </script>
        <noscript>
            <p><strong>Note:</strong> 
            Since your browser does not support JavaScript, 
            you must press the button below once to proceed.</p> 
        </noscript> 
        <form method="post" action="${idpServiceUrl}">
            <input type="submit" id="submitButton"/>
            <input type="hidden" name="${messageType}" value="${samlMessage}" />
            ${relayState}
            <noscript>
                <button type="submit" class="btn">Continue Login</button>
            </noscript>
        </form>
    </body>
    </html>`;
}

/**
 * Dispatches a SAML response to the IdP service URL using either HTTP-POST or HTTP-Redirect binding.
 *
 * @param {object} r - The NJS HTTP request object.
 * @param {string} root - The SAML response XML string.
 * @param {string} idpServiceUrl - The IdP service URL where the response should be sent.
 * @param {string} relayState - The RelayState parameter value to include with the response.
 * @param {string} postParam - The name of the POST parameter to use for sending the encoded XML.
 * @param {boolean} isPost - If true, use HTTP-POST binding; otherwise, use HTTP-Redirect binding.
 * @returns {object} - The NJS HTTP response object with appropriate headers and content.
 */
function dispatchResponse(r, root, idpServiceUrl, relayState, postParam, isPost) {
    let encodedXml;

    // Set outgoing headers for the response
    r.headersOut['Content-Type'] = "text/html";

    if (isPost) {
        // Encode the XML string as base64 for the HTTP-POST binding
        encodedXml = Buffer.from(root).toString("base64");

        // Return the response with the POST form template
        return r.return(200, postFormTemplate(encodedXml, idpServiceUrl, relayState, postParam));
    } else {
        // Compress and encode the XML string as base64 for the HTTP-Redirect binding
        const compressedXml = zlib.deflateRawSync(root);
        encodedXml = Buffer.from(compressedXml).toString("base64");

        // Construct the IdP service URL with the encoded XML and RelayState (if provided)
        const url = `${idpServiceUrl}?${postParam}=${encodeURIComponent(encodedXml)}` +
                    `${relayState ? `&RelayState=${relayState}` : ""}`;

        // Return the response with a 302 redirect to the constructed URL
        return r.return(302, url);
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
 * @param root an XMLDoc object returned by xml.parse().
 * @param keyDataArray is array of SubjectPublicKeyInfo in PKCS#1 format.
 */
async function verifySAMLSignature(root, keyDataArray) {
    const type = root.$name;
    const rootSignature = root.Signature;

    if (!rootSignature) {
        throw Error(`Message is unsigned`);
    }

    const errors = [];
    for (let i = 0; i < keyDataArray.length; i++) {
        try {
            await digestSAML(rootSignature);
            await signatureSAML(rootSignature, keyDataArray[i]);
            return;
        } catch (e) {
            errors.push(e.message);
        }
    }

    throw Error(`Error verifying ${type} message signature: ${errors.join(', ')}`);
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

/**
 * Signs or verifies a SAML signature using the specified key data.
 *
 * @param {object} signature - The SAML signature XMLDoc object.
 * @param {string} key_data - The key data, either a private key for signing or a public key for verification.
 * @param {boolean} produce - If true, signs the SAML signature; if false, verifies the signature.
 * @returns {Promise<object|boolean>} - If produce is true, returns the updated signature object; 
 *                                      if produce is false, returns a boolean indicating the verification result.
 * @throws {Error} - If the signature algorithm is unexpected or unsupported.
 */
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

/**
 * decryptSAML() decrypts an EncryptedAssertion element of a SAML document.
 * It supports various key and data encryption algorithms as defined in the
 * XML Encryption Syntax and Processing Version 1.1 and 1.0 specifications.
 *
 * The following key encryption algorithms are supported:
 * - http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p
 * - http://www.w3.org/2009/xmlenc11#rsa-oaep
 * - http://www.w3.org/2001/04/xmlenc#rsa-1_5
 *
 * The following data encryption algorithms are supported:
 * - http://www.w3.org/2001/04/xmlenc#aes128-cbc
 * - http://www.w3.org/2001/04/xmlenc#aes192-cbc
 * - http://www.w3.org/2001/04/xmlenc#aes256-cbc
 * - http://www.w3.org/2009/xmlenc11#aes128-gcm
 * - http://www.w3.org/2009/xmlenc11#aes192-gcm
 * - http://www.w3.org/2009/xmlenc11#aes256-gcm
 *
 * @async
 * @function
 * @param {Object} root - The root object containing EncryptedData and KeyInfo elements.
 * @param {string} key_data - The private key in PEM format.
 * @returns {Promise<Object>} - The decrypted XML document.
 * @throws {Error} - If unsupported key or data encryption algorithm is encountered.
 */
async function decryptSAML(root, key_data) {
    /* Extract key encryption algorithm and data encryption algorithm */
    const keyAlg = root.EncryptedData.KeyInfo.EncryptedKey.EncryptionMethod.$attr$Algorithm;
    const dataAlg = root.EncryptedData.EncryptionMethod.$attr$Algorithm;

    /* Determine method and hash based on key encryption algorithm */
    let keyMethod, keyHash;
    switch (keyAlg) {
        case 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p':
            keyMethod = 'RSA-OAEP';
            keyHash = 'SHA-1';
            break;
        case 'http://www.w3.org/2009/xmlenc11#rsa-oaep':
            keyMethod = 'RSA-OAEP';
            keyHash = 'SHA-256';
            break;
        case 'http://www.w3.org/2001/04/xmlenc#rsa-1_5':
            keyMethod = 'RSASSA-PKCS1-v1_5';
            keyHash = 'SHA-256';
            break;
        default:
            throw new Error(`Unsupported key encryption algorithm: "${keyAlg}"`);
    }

    /* Determine cipher, mode, and IV length based on data encryption algorithm */
    let dataCipher, dataCipherMode, dataCipherIvLength;
    switch (dataAlg) {
        case 'http://www.w3.org/2001/04/xmlenc#aes128-cbc':
            dataCipher = 'aes';
            dataCipherMode = 'cbc';
            dataCipherIvLength = 16;
            break;
        case 'http://www.w3.org/2001/04/xmlenc#aes192-cbc':
            dataCipher = 'aes';
            dataCipherMode = 'cbc';
            dataCipherIvLength = 16;
            break;
        case 'http://www.w3.org/2001/04/xmlenc#aes256-cbc':
            dataCipher = 'aes';
            dataCipherMode = 'cbc';
            dataCipherIvLength = 16;
            break;
        case 'http://www.w3.org/2009/xmlenc11#aes128-gcm':
            dataCipher = 'aes';
            dataCipherMode = 'gcm';
            dataCipherIvLength = 12;
            break;
        case 'http://www.w3.org/2009/xmlenc11#aes192-gcm':
            dataCipher = 'aes';
            dataCipherMode = 'gcm';
            dataCipherIvLength = 12;
            break;
        case 'http://www.w3.org/2009/xmlenc11#aes256-gcm':
            dataCipher = 'aes';
            dataCipherMode = 'gcm';
            dataCipherIvLength = 12;
            break;
        default:
            throw new Error(`Unsupported data encryption algorithm: "${dataAlg}"`);
    }

    /* Load private key */
    const der = keyPem2Der(key_data, "PRIVATE");

    /* Import the private key */
    const importedKey = await crypto.subtle.importKey(
        'pkcs8',
        der,
        { name: keyMethod, hash: keyHash },
        false,
        ['decrypt']
    );

    /* Decrypt EncryptedKey */
    const encryptedKeyNode = root.EncryptedData.KeyInfo.EncryptedKey.CipherData.CipherValue;
    const encryptedKey = Buffer.from(encryptedKeyNode.$text, 'base64');
    const decryptedKey = await crypto.subtle.decrypt(
        { name: keyMethod },
        importedKey,
        encryptedKey
    );

    /* Import decrypted AES key */
    const aesKey = await crypto.subtle.importKey(
        'raw',
        decryptedKey,
        { name: `${dataCipher}-${dataCipherMode}` },
        false,
        ['decrypt']
    );

    /* Decrypt EncryptedData */
    const encryptedDataNode = root.EncryptedData.CipherData.CipherValue;
    const encryptedData = Buffer.from(encryptedDataNode.$text, 'base64');
    const iv = encryptedData.slice(0, dataCipherIvLength);
    const cipherText = encryptedData.slice(dataCipherIvLength);

    const decryptedData = await crypto.subtle.decrypt(
        {
            name: `${dataCipher}-${dataCipherMode}`,
            iv: iv,
        },
        aesKey,
        cipherText
    );

    /* Parse decryptedData for an XML document */
    return xml.parse(decryptedData);
}

function parseConfigurationOptions(r, messageType) {
    const escapeXML = getEscapeXML();
    let opt = {};
    var prefix = `Failed to parse configuration options for ${messageType}:`;

    opt.spEntityID = validateUrlOrUrn('saml_sp_entity_id');
    opt.idpEntityID = validateUrlOrUrn('saml_idp_entity_id');

    if (messageType === 'Response' || messageType === 'AuthnRequest') {
        opt.spServiceURL = validateUrlOrUrn('saml_sp_acs_url');
        opt.idpServiceURL = validateUrlOrUrn('saml_idp_sso_url');
        opt.relayState = r.variables.saml_sp_relay_state;
    }

    if (messageType === 'Response') {
        opt.wantSignedResponse = validateTrueOrFalse('saml_sp_want_signed_response');
        opt.wantSignedAssertion = validateTrueOrFalse('saml_sp_want_signed_assertion');
        opt.wantEncryptedAssertion = validateTrueOrFalse('saml_sp_want_encrypted_assertion');
    }

    if (messageType === 'AuthnRequest') {
        opt.requestBinding = validateHttpPostOrRedirect('saml_sp_request_binding');
        opt.isSigned = validateTrueOrFalse('saml_sp_sign_authn');
        opt.forceAuthn = validateTrueOrFalse('saml_sp_force_authn');
        opt.nameIDFormat = validateNameIdFormat('saml_sp_nameid_format');
    }

    if (messageType === 'LogoutResponse' || messageType === 'LogoutRequest') {
        opt.idpServiceURL = validateUrlOrUrn('saml_idp_slo_url', true);
        opt.isSLODisabled = !opt.idpServiceURL ? true : false;
        if (!opt.isSLODisabled) {
            opt.spServiceURL = validateUrlOrUrn('saml_sp_slo_url');
            opt.logoutResponseURL = validateUrlOrUrn('saml_idp_slo_response_url', true);
            opt.requestBinding = validateHttpPostOrRedirect('saml_sp_slo_binding');
            opt.isSigned = validateTrueOrFalse('saml_sp_sign_slo');
            opt.wantSignedResponse = validateTrueOrFalse('saml_sp_want_signed_slo');
        }
        opt.relayState = r.variables.saml_logout_landing_page;
        opt.nameID = r.variables.saml_name_id;
    }

    if (opt.wantSignedResponse || opt.wantSignedAssertion) {
        opt.verifyKeys = readKeysFromFile(r.variables.saml_idp_verification_certificate);
    }

    if (opt.isSigned) {
        opt.signKey = readKeysFromFile(r.variables.saml_sp_signing_key)[0];
    }

    if (r.variables.saml_sp_decryption_key) {
        opt.decryptKey = readKeysFromFile(r.variables.saml_sp_decryption_key)[0];
    }

    function validateUrlOrUrn(name, allowEmpty) {
        let value = r.variables[name];

        if (allowEmpty && (value === '' || value === undefined)) {
            return value;
        }

        if (!isUrlOrUrn(value)) {
            throw Error(`${prefix} Invalid "${name}": "${value}", must be URI.`);
        }

        return escapeXML(value);
    }

    function validateTrueOrFalse(name) {
        const value = (r.variables[name]).toLowerCase();
        if (value !== 'true' && value !== 'false') {
            throw Error(`${prefix} Invalid "${name}": "${value}", must be "true" or "false".`);
        }

        return value === 'true';
    }

    function validateHttpPostOrRedirect(name) {
        const value = r.variables[name];
        if (value !== "HTTP-POST" && value !== "HTTP-Redirect") {
            throw Error(`${prefix} Invalid "${name}": "${value}", ` +
                        `must be "HTTP-POST" or "HTTP-Redirect".`);
        }

        return value;
    }

    function validateNameIdFormat(name) {
        const value = r.variables[name];
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
    
        if (!allowedFormats.includes(value)) {
            throw Error(`${prefix} Invalid "${name}": "${value}"`);
        }

        return value;
    }

    return opt;
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

function isUrlOrUrn(str) {
    const urlRegEx = /^((?:(?:https?):)\/\/)?((?:(?:[^:@]+(?::[^:@]+)?|[^:@]+@[^:@]+)(?::\d+)?)|(?:\[[a-fA-F0-9:]+]))(\/(?:[^?#]*))?(\\?(?:[^#]*))?(#(?:.*))?$/;
    const urnRegEx = /^urn:[a-z0-9][a-z0-9-.]{1,31}:[a-z0-9()+,\-.:=@;$_!*'%/?#]+$/i;
  
    if (urlRegEx.test(str)) {
        return "URL";
    } else if (urnRegEx.test(str)) {
        return "URN";
    } else {
        return false;
    }
}

/**
 * Reads a file containing one or more keys (public or private) and returns an array of the keys.
 *
 * @param {string} keyFile - The path to the file containing the keys.
 * @returns {Array<string>} - An array of keys in PEM format.
 */
function readKeysFromFile(keyFile) {
    try {
        const pem = fs.readFileSync(keyFile, 'utf8');
        const regex = /-----BEGIN (PUBLIC|PRIVATE) KEY-----[\s\S]*?-----END (PUBLIC|PRIVATE) KEY-----/g;
        const matches = pem.match(regex);
        const pemList = [];

        for (var i = 0; i < matches.length; i++) {
            pemList.push(matches[i]);
        }

        return pemList;
    } catch (e) {
        throw Error(`Failed to read private or public key from file "${keyFile}": ${e.message}`);
    }
}
