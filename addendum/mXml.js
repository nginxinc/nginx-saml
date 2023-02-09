/*
 * mXml.js: mini xml parser.
 *
 * it is intended accept mostly valid/trusted xml and produce minimal parsing tree, like JSON.parse(JSON.stringify(native_xml.parse(source_xml_text)))
 *
 * Usage:
 *
 *    var xml = mXml();
 *    var tree = xml.parse(source_xml_text);
 *
 * Note:
 *
 *    if you need obtain Xml metadata properties, as after native_xml.parse(source_xml_tree), then use additionally:
 *
 *       tree = enreechXmlTree(tree);
 *
 */

function mXml () {

    return function (parser) {
        return {
            parse: function (a) {
                var t = parser(a);
                var r = {}
                r[t.$name] = t;
                return r;
            }
        }
    }(function () {

        var tagstart = /(<)(?:(?:([A-Z_][A-Z0-9_\.-]*):)?(?:([A-Z_][A-Z0-9_\.-]*)(\s*)(\/?>)?)|\/(?:([A-Z_][A-Z0-9_\.-]*):)?(?:([A-Z_][A-Z0-9_\.-]*)(\s*)(>))|(!--(?:-(?!-[^>])|[^-])*-->))/gi;

        var attr = /(\/?>)|(?:(?:([A-Z_][A-Z0-9_\.-]*):)?(?:([A-Z_][A-Z0-9_\.-]*)?)?)(?:\s*=\s*(?:"([^"]*)")?)?(\s*)/ig;


        function xml_unescape (s) {
            return s.replace(/\&(?:(quot|apos|lt|gt|amp)|#(\d+)|#x([a-fA-F0-9]+));/g, function (a, name, dec, hex){
                if (name) {
                    switch (name) {
                        case 'quot' : return '"';
                        case 'apos':  return "'";
                        case 'lt':    return '<';
                        case 'gt':    return '>';
                        case 'amp':   return '&';
                    }
                }
                if (dec) {
                    if (+dec > 0xFFFFF) throw new Error("xmlParseCharRef: character reference out of bounds");
                    return String.fromCharCode(dec)
                }
                if (hex) {
                    if (parseInt(hex,16) > 0xFFFFF) throw new Error("xmlParseCharRef: character reference out of bounds");
                    return String.fromCharCode(parseInt(hex,16))
                }
            })
        }


        function create_top_ns (old_top_ns) {
            stack_of_nss.push(old_top_ns);
            var new_top_ns = {}
            new_top_ns.__proto__ = old_top_ns;
            return new_top_ns;
        }

        var stack_of_nss = [];
        var top_ns = void 0;


        function resolve_tag_ns (tag, top_ns) {
            if (tag.$ns) {
                if (top_ns[tag.$ns]) {
                    tag.$ns = top_ns[tag.$ns];

                } else {
                    tag.$name = tag.$ns+':'+ tag.$name;
                    delete tag.$ns
     
                }
            }
            //tbd: it seems we need resolve attrs ns as well here
        }


        return function (buffer) {

            // skip leading spaces
            var re_skip = /\s*/g
            var res = re_skip.exec(buffer);

            var last_closed_tag = null;    // last closed tag;
            var parent = null;             // parent tag
            var stack_of_parents = [];     // stack of parent tags up to parent tag;

            // accept only single element with all children elements

            tagstart.lastIndex = re_skip.lastIndex;
            while (tagstart.lastIndex < buffer.length) { // loop over tags


                // add all text up to '<' to parent tag as text node
                var re_skip = /[^<]*/g

                re_skip.lastIndex = tagstart.lastIndex;
                var res = re_skip.exec(buffer);

                if (parent) {
                    if (tagstart.lastIndex != re_skip.lastIndex) {
                        parent.$text += xml_unescape(buffer.substring(tagstart.lastIndex, re_skip.lastIndex));
                    }
                } else {
                    if (tagstart.lastIndex != re_skip.lastIndex) {
                        throw new Error("garbage before root tag")
                    }
                }

                tagstart.lastIndex = re_skip.lastIndex;


                // try obtain tagstart
                var lastInput = tagstart.lastIndex;
                var t = tagstart.exec(buffer)

                if (t === null || t.index != lastInput) {
                    throw new Error("can't get tag at buffer position="+lastInput);
                }

                if (t[10] !== void(0)) {
                    // comment, skip it (or add to parent?)
                    continue;
                }


                if (t[7] !== void(0)) {
                    // close tag
                    var tag = {
                        //begin: t[1],
                        $ns: t[6],
                        $name: t[7],
                        //spaces: t[8],
                        //end: t[9],
                        $attrs:{},
                        $tags:[],
                        $text:''
                    }
                    var tag_end = t[9];
                } else {
                    // open tag or self closed tag;
                    var tag = {
                        //begin: t[1],
                        $ns: t[2],
                        $name: t[3],
                        //spaces: t[4],
                        //end: t[5],
                        $attrs:{},
                        $tags:[],
                        $text: ''
                    }
                    var tag_end = t[5];
                }

                if (t[7] !== void(0)) {
                    // close tag ("</...")

                    if (!parent) {
                        throw new Error ("wrong close tag "+tag.$name);
                    }

                    resolve_tag_ns(tag, top_ns);

                    if (tag.$name !== parent.$name) {
                        throw new Error("wrong close tag "+tag.$name);
                    }

                    if (stack_of_parents.length === 0) {
                        return parent;
                    }
                    parent = stack_of_parents.pop();

                    ns_top = stack_of_nss.pop();

                } else {
                    //open tag
                    if (tag_end == void(0)) {

                        top_ns = create_top_ns(top_ns);

                        // collect attributes to tag

                        attr.lastIndex = tagstart.lastIndex;                          
                        while (attr.lastIndex < buffer.length) {
                            lastInput = attr.lastIndex;

                            var a = attr.exec(buffer);
                            if (a == null || a.index != lastInput) {
                                throw new Error("can't get attribute at position "+attr.lastIndex);
                            }

                            if (a[1] !== void(0)) {
                                tag_end = a[1];  // ">" or "/>"
                                break;
                            }


                            // process xmlns scheme in attribute
                            if (a[2] === void(0)) { // attr_name w/o ns
                                tag.$attrs[a[3]] = xml_unescape(a[4]);
                            } else { // attr name with ns
                                if (a[2] === 'xmlns') { // definition of namespace
                                    top_ns[a[3]] = xml_unescape(a[4]);
                                } else {
                                    tag.$attrs[a[3]] = xml_unescape(a[4]);

                                    /*
                                     * Note: we lost attribute ns for compatibility
                                     * with native xml.parse()
                                     */
                                }
                            }

                        }
                        tagstart.lastIndex = attr.lastIndex;
                    }
                    if (tag_end == '/>') {
                        resolve_tag_ns(tag, top_ns);

                        ns_top = stack_of_nss.pop()

                        // self closed tag
                        if (!parent) {
                            return tag;
                        }
                        parent.$tags.push(tag);
                        continue;
                    }
                    if (tag_end == '>') {
                        resolve_tag_ns(tag, top_ns);

                        if (!parent) {
                            parent = tag;
                        } else {
                            parent.$tags.push(tag);
                            stack_of_parents.push(parent);
                            parent = tag;
                        }

                    }
                }  
            }

        } // function parser
    }());
}
