
from fpkilint.profile_conformance import *
from fpkilint.text2html import text_to_html
import json

# _header = "<thead><tr><th>Field</th><th>Content</th><th>Analysis</th></tr></thead>"
#_cols = "|:-------- |: -------------------------------------- |:--------------------------------------------------- |\n"
# _all_was_good = "<img class=ok-result src=/static/check-circle.svg border=0 width=20 />"
_extension_is_critical = "Critical = TRUE<br/>"

def analyze_certificate(cert, profile_file):

    _add_profile_url = True
    _add_profile_string = True

    with open('fpkilint/profiles/' + profile_file) as json_data:
        json_profile = json.load(json_data)

    output_rows, other_extensions_rows, profile_info = check_cert_conformance(cert, json_profile)

    cert_type = None
    profile_string = None
    profile_url = None
    short_name = get_short_name_from_cert(cert)

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

    rows = []
    for i, (key, r) in enumerate(other_extensions_rows.items()):
        output_rows[key] = r

    for key, r in output_rows.items():
        name = r.row_name

        if r.extension_is_critical:
            content = _extension_is_critical
        else:
            content = ""

        content += text_to_html(r.content, lint_cert_indent, lint_cert_newline)

        # Analysis
        if r.analysis:
            analysis = text_to_html(r.analysis, lint_cert_indent, lint_cert_newline)
        else:
            analysis = None

        rows.append({'name': name, 'content': content, 'analysis': analysis})

    return rows, cert_type, profile_string, profile_url, short_name



