/*
 * It restores helper xml_tree properties after:
 *     xml_tree = xml.parse(xml_text);
 *     xml_minimal = JSON.parse(JSON.stringify(xml_tree)));
 *     xml_tree = enreechXmlTree(xml_minimal);
 *
 * It adds following properties properties in result tree:
 *
 * $parent     -- parent node
 * $attr$name  -- access to attributes by name
 * $tags$name  -- access to set of tags by name, or
 * name        -- access to tag by name
 *
 * Example 1:
 *
 *     var xml = require("xml");
 *     var tree = xml.parse("<a><b></b><c></c></a>");
 *         // we have here access to tree.a.c
 *     var stringified_tree = JSON.stringify(tree)
 *         // tree is serialized to minimal representation, and lost helper
 *         // properties. so after parsing:
 *     var parsed_tree = JSON.parse(stringified_tree);
 *         // we have no access to parsed_tree.a.c
 *         // we need restore all properties by:
 *     var enreeched_tree = enreechXmlTree(parsed_tree);
 *         // now we have access to enreeched_tree.a.c
 *
 * Example 2:
 *
 *    suppose you need obtain xml tree in one request, and share it with other requests.
 *
 *    so in one request processing you can obtain xml tree, stringify it and save it keyval:
 *        xml = require('xml');
 *        tree = xml.parse(some_source_xml_text);
 *        r.variables.keyval_key = JSON.stringify(tree);
 *
 *    to restore tree from keyval in other request you need:
 *        tree = enreechXmlTree(JSON.parse(r.variables.keyval_key));
 */

function enreechXmlTree(root) {
    var i, r;

    function set_once_not_enum_prop(r, name, value) {
        if ('undefined' == typeof r[name]){
            Object.defineProperty(r, name, {
                writable: true,
                value: value
            });

        }
    }

    function _enreechTree(tag, parent) {
        var i, child, shortcut, r;

        r = {};
        Object.assign(r, tag);

        /* $parent. */

        if (parent) {
            set_once_not_enum_prop(r, '$parent', parent);

        }

        /* $attrs$, $attr$name */

        if (tag.$attrs) {
            for (i in tag.$attrs) {
                set_once_not_enum_prop(r, '$attr$' + i, tag.$attrs[i]);

            }

        }

        /* $tags, $tags$, $tags$name */

        if (tag.$tags) {

            tag.$tags.forEach(t => {

                child = _enreechTree(t, r);

                /* 1st child */

                set_once_not_enum_prop(r, t.$name, child);

                /* all children */

                shortcut = '$tags$' + t.$name;
                set_once_not_enum_prop(r, shortcut, []);
                r[shortcut].push(child);
            });

        }
        return r;
    }
   
    r = {};
    for (i in root) {
        set_once_not_enum_prop(r, '$root', root[i]);
        r[i] = _enreechTree(root[i], null);
    }

    return r;

}
