import html
import re
from profile_conformance import *


url_regex = re.compile(r'(?i)\b((?:(https?|s?ftp|ldaps?)://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:\'".,<>?\xab\xbb\u201c\u201d\u2018\u2019]))')
slash_regex = re.compile(r'\S/[^/ \t\n\r\f\v<]')

# ^/[a-z0-9]+$
# ^/\b([a-z0-9]+)\b(?<!ignoreme|ignoreme2|ignoreme3)

def text_to_html(text_string, text_indent=None, text_new_line=None):

    if not text_indent:
        text_indent = '    '
    if not text_new_line:
        text_new_line = '\n'

    html_new_line = '<br/>'
    html_indent = '&nbsp;&nbsp;&nbsp;&nbsp;'

    uris_to_replace = []

    # if text_string.find('[6 PRIMITIVE] {') is not -1:
    #     print(text_string)

    uri_match = True
    while uri_match:
        uri_match = url_regex.search(text_string)
        if uri_match:
            uris_to_replace.append(uri_match.group(0).strip())
            break

    # this was moved from above to between the uri match and replace due to &quot;
    # matching url_regex e.g. "http://stuff/" -> http://stuff/&quot
    # if this ends up causing problems will need to figure out a better fix
    text_string = html.escape(text_string)

    for original_uri in uris_to_replace:
        slash_match = True
        display_uri = original_uri
        while slash_match:
            slash_match = slash_regex.search(display_uri)
            if slash_match:
                display_uri = display_uri[:slash_match.regs[0][0]+2] + "<wbr>" + display_uri[slash_match.regs[0][0]+2:]
        display_uri = display_uri.replace("%20", " ")
        display_uri = "<a href=\"{}\">{}</a>".format(original_uri, display_uri)

        text_string = text_string.replace(original_uri, display_uri)


    text_string = text_string.replace("'", "&#39;")
    text_string = text_string.replace("`", "&#96;")
    text_string = text_string.replace("|", "&verbar;")  # &#124;
    text_string = text_string.replace("*", "&ast;")  # &#42;
    text_string = text_string.replace("&ast;&ast;", "**")
    text_string = text_string.replace("\r", "")
    text_string = text_string.replace(text_indent, html_indent)
    text_string = text_string.replace(text_new_line, html_new_line)

    return text_string

_header = "\n| **Field** | **Content** | **Analysis** |\n"
_cols = "|:-------- |: -------------------------------------- |:--------------------------------------------------- |\n"
_all_was_good = "<font color=\"green\">OK</font>"
_extension_is_critical = "Critical = TRUE<br/>"

def process_add_certificate(cert, profile_file, output_file):
    # could make these default params if desired
    _add_profile_url = True
    _add_profile_string = True

    output_rows, other_extensions_rows, profile_info = check_cert_conformance(cert, profile_file)

    output_file.write("\n<br/>\n")

    cert_type = None
    profile_string = None
    profile_url = None

    if profile_info is not None:
        if 'cert_type' in profile_info and len(profile_info['cert_type'].value) > 0:
            cert_type = profile_info['cert_type'].value
        if _add_profile_string and 'name' in profile_info and len(profile_info['name'].value) > 0:
            profile_string = profile_info['name'].value
            if 'version' in profile_info and len(profile_info['version'].value) > 0:
                profile_string += " v" + profile_info['version'].value
            if 'date' in profile_info and len(profile_info['date'].value) > 0:
                profile_string += " " + profile_info['date'].value
        if _add_profile_url and 'more_info_url' in profile_info and len(profile_info['more_info_url'].value) > 0:
            profile_url = profile_info['more_info_url'].value

    if cert_type is not None:
        output_file.write("\n## {}".format(cert_type))

    if profile_string is not None:
        output_file.write("\n##### {}".format(profile_string))

    if profile_url is not None:
        output_file.write("\n<a href=\"{}\">{}</a>".format(profile_url, profile_url))

    output_file.write("\n### {}\n".format(get_short_name_from_cert(cert)))
    output_file.write(_header)
    output_file.write(_cols)

    for i, (key, r) in enumerate(other_extensions_rows.items()):
        output_rows[key] = r

    for i, (key, r) in enumerate(output_rows.items()):

        # Field
        output_file.write("| **{}** ".format(r.row_name))

        # Content
        output_file.write("| ")
        if r.extension_is_critical:
            output_file.write(_extension_is_critical)
        output_file.write(text_to_html(r.content, lint_cert_indent, lint_cert_newline))

        # Analysis
        if r.analysis == "":
            output_file.write(" | {}&nbsp;|\n".format(_all_was_good))
        else:
            output_file.write(" | {}&nbsp;|\n".format(text_to_html(r.analysis, lint_cert_indent, lint_cert_newline)))

# amelia
# bootstrap
# bootstrap-responsive
# cerulean
# cyborg
# journal
# readable
# simplex
# slate
# spacelab
# spruce
# superhero
# united

_strap_start = "<!DOCTYPE html>\n<html>\n<title>{}</title>\n<xmp theme=\"spruce\" style=\"display:none;\"\n>"
_strap_end = "\n</xmp>\n<script src=\"strapdown.js\"></script>\n</html>\n"

def process_one_certificate(cert, profile_file, output_file_name, document_title):

    with open(output_file_name, 'w') as output_file:
        output_file.write(_strap_start.format(document_title))
        process_add_certificate(cert, profile_file, output_file)
        output_file.write(_strap_end)


# example input list
# filename, profile
# piv_test_certs = [
#     ["testcerts/piv/cardauth.cer", 'PIV_Card_Authentication'],
#     ["testcerts/piv/content_signing.cer", 'PIV_Content_Signer'],
#     ["testcerts/piv/pivauth.cer", "PIV_Identity"],
#     ]


def process_certificate_list(list_of_certs, output_file_name, doc_title):
    # strap_start = "<!DOCTYPE html>\n<html>\n<title>{}</title>\n<xmp theme=\"spruce\" style=\"display:none;\"\n>"
    # strap_end = "\n</xmp>\n<script src=\"strapdown.js\"></script>\n</html>\n"

    with open(output_file_name, 'w') as output_file:
        output_file.write(_strap_start.format(doc_title))

        for file_name, profile in list_of_certs:
            # print(file_name)
            if profile == "":
                profile = "template"
            with open(file_name, 'rb') as cert_file:
                encoded = cert_file.read()
                cert = parse_cert(encoded)
                if cert is None:
                    print('Failed to parse {}'.format(file_name))
                else:
                    output_file.write("\n<br/>" + file_name + "<br/>\n")
                    process_add_certificate(cert, profile, output_file)

        output_file.write(_strap_end)

