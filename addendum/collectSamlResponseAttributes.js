/*
 * Example of how Attributes from SAML Rresponse can be collected into compact data structure
 * for saving into keyval, if necessary
 */


var tree = xml.parse(some_saml_text);

function get_Attributes($tags$Attribute) {
    return $tags$Attribute.reduce((a, v) => {
        a[v.$attr$Name] = v.$tags$AttributeValue.reduce((a, v) => {a.push(v.$text); return a}, []);
        return a
    }, {})
}

var attrs = get_Attributes(tree.Response.Assertion.AttributeStatement.$tags$Attribute);
