import re
import textwrap
# from fpkilint.profile_conformance import *

url_regex = re.compile(r"(?:http|ftp|ldap)s?://[A-Za-z0-9\-._~:/?#[\]@!$&'()*+,;%=]+(?<!')")
bold_regex = re.compile(r'\*\*.*\*\*')
oid_regex = re.compile(r'(?:[0-9]+\.){4,}[0-9]+')
long_hex_string = re.compile(r'[0-9a-fA-F]{30,}')
big_printable_string_sans_space_regex = re.compile(r"[0-9a-zA-Z.\\()+/:'=?,\-]{24,}")

html_escape_table = {
    '"': "&quot;",
    "'": "&apos;",
    "&": "&amp;",
    ">": "&gt;",
    "<": "&lt;",
}

markdown_escape_table = {
    "`": "&apos;",  # "&#96;",
    "'": "&apos;",
    "|": "&verbar;",
    "*": "&ast;",
}

printable_characters_to_break = [':', '.', '=', '+', ')', '\\']


def escape_text(text, escape_table):
    return "".join(escape_table.get(c, c) for c in text)


def text_to_html(text_string, text_indent=None, text_new_line=None):

    if not text_indent:
        text_indent = '    '
    if not text_new_line:
        text_new_line = '\n'

    html_new_line = '<br/>'
    html_indent = '&nbsp;&nbsp;&nbsp;&nbsp;'

    text_string = text_string.replace("\r", "")

    uris_to_replace = []
    for uri_match in url_regex.finditer(text_string):
        if uri_match.group(0).strip() not in uris_to_replace:
            uris_to_replace.append(uri_match.group(0).strip())

    for n, uri in enumerate(uris_to_replace):
        text_string = text_string.replace(uri, '\r' + str(n) + '\r')

    text_string = escape_text(text_string, html_escape_table)

    # this could match urls so it must in this spot
    printable_strings_to_break = big_printable_string_sans_space_regex.findall(text_string)
    for printable_str in printable_strings_to_break:
        for c in printable_characters_to_break:
            new_str = printable_str.replace(c, c + '<wbr>')
            text_string = text_string.replace(printable_str, new_str)

    hex_strings = long_hex_string.findall(text_string)
    for hex_string in hex_strings:
        new_hex_string = '<wbr>'.join(textwrap.wrap(hex_string, 8))
        text_string = text_string.replace(hex_string, new_hex_string)

    for n, uri in enumerate(uris_to_replace):
        display_uri = uri
        display_uri = display_uri.replace("/", "/<wbr>")
        display_uri = display_uri.replace(",", ",<wbr>")
        display_uri = display_uri.replace("%20", " ")
        display_uri = "<a href=\"{}\">{}</a>".format(uri, display_uri)
        text_string = text_string.replace('\r' + str(n) + '\r', display_uri)

    strings_to_bold = bold_regex.findall(text_string)
    for string_to_bold in strings_to_bold:
        text_string = text_string.replace(string_to_bold, "<strong>" + string_to_bold[2:-2] + "</strong>")

    oids_to_break = oid_regex.findall(text_string)
    for oid in oids_to_break:
        if len(oid) > 35:
            new_oid = oid[:34]
            new_oid += oid[34:].replace('.', '.<wbr>')
            text_string = text_string.replace(oid, new_oid)

    # this was original location of this code..
    # hex_strings = long_hex_string.findall(text_string)
    # for hex_string in hex_strings:
    #     new_hex_string = '<wbr>'.join(textwrap.wrap(hex_string, 8))
    #     text_string = text_string.replace(hex_string, new_hex_string)

    text_string = escape_text(text_string, markdown_escape_table)
    text_string = text_string.replace(text_indent, html_indent)
    text_string = text_string.replace(text_new_line, html_new_line)

    return text_string
