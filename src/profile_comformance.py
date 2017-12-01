from cert_helpers import *
import json
import datetime
import pytz
import textwrap
from collections import OrderedDict
import subprocess
from certificate_policies import policies_display_map

_lint_cert_newline = '\n'
# _lint_cert_indent = '&nbsp;&nbsp;&nbsp;&nbsp;'
_lint_cert_indent = '    '
_lint_cert_add_wbr = True


class ConfigEntry:
    def __init__(self):
        self.value = ""
        self.oid = ""


LINT_CERT_NONE = 0
LINT_CERT_OPTIONAL = 0
LINT_CERT_DISALLOWED = 1
LINT_CERT_REQUIRED = 2


class OutputRow:
    def __init__(self, init_row_name=None, init_content=None, init_analysis=None, init_config_section=None):
        self.row_name = ""
        self.content = ""
        self.analysis = ""
        self.config_section = ""

        if init_row_name is not None:
            self.row_name = init_row_name
        if init_content is not None:
            self.content = init_content
        if init_analysis is not None:
            self.analysis = init_analysis
        if init_config_section is not None:
            self.config_section = init_config_section


def der2ascii(binary_der):
    completed_process = subprocess.run(["der2ascii.exe"], input=binary_der, stdout=subprocess.PIPE)
    # print(completed_process.stdout.decode("utf-8"))
    ascii_string = completed_process.stdout.decode("utf-8")
    ascii_string = ascii_string.replace("<", "\<")
    ascii_string = ascii_string.replace(">", "\>")
    ascii_string = ascii_string.replace("'", "\'")
    ascii_string = ascii_string.replace('`', "\`")
    ascii_string = ascii_string.replace('\n', _lint_cert_newline)
    ascii_string = ascii_string.replace('  ', _lint_cert_indent)
    return ascii_string


def _lint_cert_add_content_to_row(r, content_string):
    if len(r.content) > 0:
        r.content += _lint_cert_newline

    r.content += str(content_string)

    return


def _lint_cert_add_error_to_row(r, error_string, preface=None):
    if len(r.analysis) > 0:
        r.analysis += _lint_cert_newline

    if preface is None:
        preface = "**ERROR**"

    r.analysis += "{}: {}".format(preface, error_string)

    return


def _lint_get_extension_options(config_options):
    option_present = LINT_CERT_OPTIONAL
    option_is_critical = LINT_CERT_OPTIONAL

    if 'present' in config_options and len(config_options['present'].value) > 0:
        option_present = int(config_options['present'].value)

    if 'is_critical' in config_options and len(config_options['is_critical'].value) > 0:
        option_is_critical = int(config_options['is_critical'].value)

    return option_present, option_is_critical


def _process_common_extension_options(config_options, extension, extension_is_critical, r):
    option_present, option_is_critical = _lint_get_extension_options(config_options)

    if extension is None:
        if option_present is LINT_CERT_REQUIRED:
            _lint_cert_add_error_to_row(r, "{} is missing".format(r.row_name))
    else:
        if option_present is LINT_CERT_DISALLOWED:
            _lint_cert_add_error_to_row(r, "{} is not permitted".format(r.row_name))
        if option_is_critical is LINT_CERT_REQUIRED and extension_is_critical is False:
            _lint_cert_add_error_to_row(r, "{} must be marked critical".format(r.row_name))
        if option_is_critical is LINT_CERT_DISALLOWED and extension_is_critical is True:
            _lint_cert_add_error_to_row(r, "{} must not be marked critical".format(r.row_name))

        if extension_is_critical is True:
            _lint_cert_add_content_to_row(r, "Critical = TRUE")

    return


def get_der_display_string(byte_value, preface=None, multi_line=None):
    if not isinstance(byte_value, bytes):
        return "You must pass in bytes..."

    if preface is None:
        der_string = "DER: "
    else:
        der_string = preface

    if multi_line is not True:
        der_string += ''.join('%02X' % c for c in byte_value)
    else:
        der_string += '\n'
        der_string += textwrap.fill(' '.join('%02X' % c for c in byte_value), 43)
        der_string = der_string.replace('\n', _lint_cert_newline)

    return der_string


def _do_presence_test(r, config_options, cfg_str, display_str, is_present):
    error_string = None

    if cfg_str in config_options and len(config_options[cfg_str].value) > 0:
        if config_options[cfg_str].value == '1' and is_present is True:
            error_string = "is not permitted"
        if config_options[cfg_str].value == '2' and is_present is False:
            error_string = "is missing"

    if error_string is not None:
        _lint_cert_add_error_to_row(r, "{} {}".format(display_str, error_string))

    return


general_name_display_map = {
    'x400_address': 'X400 Address',
    'registered_id': 'Registered ID',
    'edi_party_name': 'EDI Party Name',
    'dns_name': 'DNS Name',
    'directory_name': 'Directory Name',
    'rfc822_name': 'Email',
    'ip_address': 'IP Address',
    'other_name': 'Other Name',
    'uniform_resource_identifier': 'URI',
    'other_name_upn': 'UPN',
    'other_name_piv_fasc_n': 'FASCN',
    'uniform_resource_identifier_chuid': 'CHUID',
}

other_name_display_map = {
    '1.3.6.1.4.1.311.20.2.3': 'UPN',
    '2.16.840.1.101.3.6.6': 'FASCN',
}

other_name_type_map = {
    '1.3.6.1.4.1.311.20.2.3': '_upn',
    '2.16.840.1.101.3.6.6': '_piv_fasc_n',
}


def get_general_name_string(general_name, multiline=None):
    if multiline is None:
        multiline = False

    general_name_string = "{}: ".format(general_name_display_map.get(general_name.name, "Unknown Name Type"))

    if general_name.name == 'uniform_resource_identifier':

        if general_name.native[0:9] == 'urn:uuid:':
            general_name_string += "(CHUID) "

        general_name_string += general_name.native

        if _lint_cert_add_wbr is True:
            general_name_string = general_name_string.replace("/", "/<wbr>")
            general_name_string = general_name_string.replace(",", ",<wbr>")

    elif general_name.name == 'directory_name':

        separator = ", "

        if multiline is True:
            general_name_string += _lint_cert_newline
            general_name_string += _lint_cert_indent
            separator = ",{}{}".format(_lint_cert_newline, _lint_cert_indent)

        general_name_string += get_pretty_dn(general_name.chosen, separator, " = ")

    elif general_name.name == 'other_name':
        other_oid = general_name.chosen['type_id'].dotted
        general_name_string += "{}: ".format(other_name_display_map.get(other_oid, other_oid))

        if isinstance(general_name.native['value'], str):
            general_name_string += general_name.native['value']
        elif isinstance(general_name.native['value'], bytes):
            general_name_string += get_der_display_string(general_name.native['value'], "", multiline)
        else:
            general_name_string += get_der_display_string(general_name.chosen.children[1].contents, "DER: ", multiline)

    elif general_name.name == 'dns_name':
        general_name_string += general_name.native
    else:
        if isinstance(general_name.native, str):
            general_name_string += general_name.native
        elif isinstance(general_name.native, bytes):
            general_name_string += get_der_display_string(general_name.native, "Binary:", multiline)
        else:
            general_name_string += get_der_display_string(general_name.contents, "DER: ", multiline)

    return general_name_string


def get_general_name_type(general_name):
    general_name_type = general_name.name

    if general_name.name == 'uniform_resource_identifier':

        if general_name.native[0:9] == 'urn:uuid:':
            general_name_type += "_chuid"
        elif general_name.native[0:7] == 'http://':
            general_name_type += "_http"
        elif general_name.native[0:7] == 'ldap://':
            general_name_type += "_ldap"
        elif general_name.native[0:7] == 'https://':
            general_name_type += "_https"
        elif general_name.native[0:7] == 'ldaps://':
            general_name_type += "_ldaps"

    elif general_name.name == 'directory_name':
        # nothing
        x = 0
    elif general_name.name == 'other_name':
        other_oid = general_name.chosen['type_id'].dotted
        general_name_type += other_name_type_map.get(other_oid, "")

    return general_name_type


def get_short_name_from_dn(name):
    rdns = [
        'common_name',
        '0.9.2342.19200300.100.1.1',
        'serial_number',
        'name',
        'given_name',
        'surname',
        'street_address',
        'organizational_unit_name',
        'organization_name',
        'locality_name'
    ]

    # d = name.native.last()

    if len(name.contents) <= 2:
        return "NULL"

    for rdn in rdns:
        if rdn in name.native:
            tmp_name = name.native[rdn]
            if isinstance(tmp_name, list):
                return tmp_name[len(tmp_name) - 1]
            else:
                return tmp_name

    return name[len(name) - 1]


def get_short_name_from_cert(cert, name_for_subject=None):
    if name_for_subject is None:
        name_for_subject = True

    if name_for_subject:
        name = cert.subject
        alt_name_value = cert.subject_alt_name_value
    else:
        name = cert.issuer
        alt_name_value = cert.issuer_alt_name_value

    if len(name.contents) > 2:
        return get_short_name_from_dn(name)

    # try the alt name...

    desired_alt_names = [
        'dns_name',
        'uniform_resource_identifier',
        'rfc822_name',
        'directory_name',
        'other_name_upn',
        'other_name_piv_fasc_n',
        'uniform_resource_identifier_chuid',
    ]

    alt_name_string = "NULL"

    if len(alt_name_value) > 0:
        general_name = alt_name_value[0]
        alt_name_string = get_general_name_type(general_name)

    if len(alt_name_value) is 1:
        return alt_name_value

    for desired_type in desired_alt_names:
        for general_name in alt_name_value:
            if desired_type == get_general_name_type(general_name):
                return get_general_name_string(general_name)

    return alt_name_string


def lint_policy_mappings(config_options, cert):
    r = OutputRow("Policy Mappings")

    _process_common_extension_options(config_options,
                                      cert.policy_mappings_value,
                                      'policy_mappings' in cert.critical_extensions, r)

    if cert.policy_mappings_value is not None:

        mapping_count = 0
        for mapping in cert.policy_mappings_value:
            mapping_count += 1
            policy_display_string = "[{}]{}{}".format(mapping_count, _lint_cert_indent,
                                                      mapping['issuer_domain_policy'].dotted)
            # if mapping['issuer_domain_policy'].dotted in policies_display_map:
            #     policy_display_string = "{}{}({})".format(policy_display_string, _lint_cert_indent,
            #                                              policies_display_map[mapping['issuer_domain_policy'].dotted])
            _lint_cert_add_content_to_row(r, policy_display_string)

            policy_display_string = "{}{}maps to {}".format(_lint_cert_indent, _lint_cert_indent,
                                                            mapping['subject_domain_policy'].dotted)
            if mapping['subject_domain_policy'].dotted in policies_display_map:
                policy_display_string = "{}{}({})".format(policy_display_string, _lint_cert_indent,
                                                          policies_display_map[mapping['subject_domain_policy'].dotted])
            _lint_cert_add_content_to_row(r, policy_display_string)

    # todo

    return r


# -- name constraints extension OID and syntax
#
# id-ce-nameConstraints OBJECT IDENTIFIER ::=  { id-ce 30 }
#
# NameConstraints ::= SEQUENCE {
#      permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
#      excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }
#
# GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
#
# GeneralSubtree ::= SEQUENCE {
#      base                    GeneralName,
#      minimum         [0]     BaseDistance DEFAULT 0,
#      maximum         [1]     BaseDistance OPTIONAL }
#
# BaseDistance ::= INTEGER (0..MAX)


def lint_name_constraints(config_options, cert):
    r = OutputRow("Name Constraints")

    _process_common_extension_options(config_options,
                                      cert.name_constraints_value,
                                      'name_constraints' in cert.critical_extensions, r)

    if cert.name_constraints_value is not None:
        # _lint_cert_add_content_to_row(r, der2ascii(cert.name_constraints_value.contents))

        found_set = {}

        perm = cert.name_constraints_value['permitted_subtrees']
        if perm:
            i = 1
            s = ""
            for item in perm:
                max = item[2].native
                if not max:
                    max = "Max"
                if item[0].name == 'directory_name':
                    v = "("
                    comma = ""
                    for rqn in item[0].chosen.chosen:
                        v += "{}{}={}".format(comma, rqn.native[0]['type'], rqn.native[0]['value'])
                        comma = ", "
                    v += ")"
                else:
                    v = item[0].native
                s += "<br>\t[{}]Subtree({}..{}): <br>\t\t{} Name={}".format(i, item[1].native, max, item[0].name, v)
                i += 1
            found_set.update({"permitted": s})
        else:
            found_set.update({"permitted": "None"})

        excl = cert.name_constraints_value['excluded_subtrees']
        if excl:
            i = 1
            s = ""
            for item in excl:
                max = item[2].native
                if not max:
                    max = "Max"
                if item[0].name == 'directory_name':
                    v = "("
                    comma = ""
                    for rqn in item[0].chosen.chosen:
                        v += "{}{}={}".format(comma, rqn.native[0]['type'], rqn.native[0]['value'])
                        comma = ", "
                    v += ")"
                else:
                    v = item[0].native
                s += "<br>\t[{}]Subtree({}..{}): <br>\t\t{} Name={}".format(i, item[1].native, max, item[0].name,
                                                                            v)
                i += 1
            found_set.update({"excluded": s})
        else:
            found_set.update({"excluded": "None"})

        _lint_cert_add_content_to_row(r, found_set['permitted'])
        _lint_cert_add_content_to_row(r, found_set['excluded'])

    # todo

    return r


def lint_piv_naci(config_options, cert):
    r = OutputRow("PIV NACI")

    pivnaci, is_critical = get_extension_from_certificate(cert, '2.16.840.1.101.3.6.9.1')

    _process_common_extension_options(config_options,
                                      pivnaci,
                                      is_critical, r)

    if pivnaci is not None:
        _lint_cert_add_content_to_row(r, der2ascii(pivnaci['extn_value'].contents))

    return r


key_usage_display_map = {
    'digital_signature': 'digitalSignature (0)',
    'non_repudiation': 'nonRepudiation (1)',
    'key_encipherment': 'keyEncipherment (2)',
    'data_encipherment': 'dataEncipherment (3)',
    'key_agreement': 'keyAgreement (4)',
    'key_cert_sign': 'keyCertSign (5)',
    'crl_sign': 'cRLSign (6)',
    'encipher_only': 'encipherOnly (7)',
    'decipher_only': ' decipherOnly (8)',
}


def lint_key_usage(config_options, cert):
    r = OutputRow("Key Usage")

    _process_common_extension_options(config_options,
                                      cert.key_usage_value,
                                      'key_usage' in cert.critical_extensions, r)

    if cert.key_usage_value is not None:

        for ku in cert.key_usage_value.native:
            _lint_cert_add_content_to_row(r, key_usage_display_map[ku])

            if ku in config_options and config_options[ku].value == '1':
                _lint_cert_add_error_to_row(r, "{} is not permitted".format(key_usage_display_map[ku]))

        for ku in key_usage_display_map.keys():
            if ku in config_options and config_options[ku].value == '2' and ku not in cert.key_usage_value.native:
                _lint_cert_add_error_to_row(r, "{} is required".format(key_usage_display_map[ku]))

    return r


def lint_akid(config_options, cert):
    r = OutputRow("Authority Key Identifier")

    _process_common_extension_options(config_options,
                                      cert.authority_key_identifier_value,
                                      'authority_key_identifier' in cert.critical_extensions, r)

    if cert.authority_key_identifier_value is not None:

        akid = cert.authority_key_identifier_value

        akid_has_keyid = False
        akid_has_issuer = False
        akid_has_serial = False

        if isinstance(akid['key_identifier'], x509.OctetString):
            akid_has_keyid = True
            _lint_cert_add_content_to_row(r, 'Key ID: {}'.format(
                ''.join('%02X' % c for c in akid['key_identifier'].contents)))

        if isinstance(akid['authority_cert_issuer'], x509.GeneralNames):

            akid_has_issuer = True

            if len(r.content) > 0:
                _lint_cert_add_content_to_row(r, "")

            if len(akid['authority_cert_issuer']) == 0:
                _lint_cert_add_content_to_row(r, "NULL")
                _lint_cert_add_error_to_row(r, "Authority cert issuer was present but contained no GeneralNames?")
            elif len(akid['authority_cert_issuer']) == 1 and akid['authority_cert_issuer'][0].name == 'directory_name':
                separator = "," + _lint_cert_newline + _lint_cert_indent
                issuer_name = get_pretty_dn(akid['authority_cert_issuer'][0].chosen, separator, " = ")
                _lint_cert_add_content_to_row(r, "Issuer DN:")
                _lint_cert_add_content_to_row(r, "{}{}".format(_lint_cert_indent, issuer_name))
            else:
                _lint_cert_add_content_to_row(r, "Issuer Names:")
                for general_name in akid['authority_cert_issuer']:
                    _lint_cert_add_content_to_row(r, "{}{}".format(_lint_cert_indent,
                                                                   get_general_name_string(general_name)))

        if isinstance(akid['authority_cert_serial_number'], x509.Integer):
            akid_has_serial = True
            serial_number = ' '.join('%02X' % c for c in akid['authority_cert_serial_number'].contents)
            _lint_cert_add_content_to_row(r, "Serial:")
            _lint_cert_add_content_to_row(r, "{}{}".format(_lint_cert_indent, serial_number))

        # process options
        _do_presence_test(r, config_options, 'key_id', 'Key ID', akid_has_keyid)
        _do_presence_test(r, config_options, 'name_and_serial', 'Name and serial number',
                          akid_has_issuer and akid_has_serial)

        if akid_has_issuer != akid_has_serial:
            _lint_cert_add_error_to_row(r, "Issuer and serial number must appear as a tuple")

    return r


def lint_skid(config_options, cert):
    r = OutputRow("Subject Key Identifier")

    _process_common_extension_options(config_options,
                                      cert.key_identifier_value,
                                      'key_identifier' in cert.critical_extensions, r)

    if cert.key_identifier_value is not None:
        skid = cert.key_identifier_value.native
        _lint_cert_add_content_to_row(r, 'Key ID: {}'.format(''.join('%02X' % c for c in skid)))

        require_method_one = '0'
        if 'require_method_one' in config_options and len(config_options['require_method_one'].value) > 0:
            require_method_one = config_options['require_method_one'].value

        match = skid == cert['tbs_certificate']['subject_public_key_info'].sha1

        if require_method_one == '1' and match is False:
            _lint_cert_add_error_to_row(r, "Was not generated using RFC5280 method 1 (SHA1 of subjectPublicKeyInfo)")

    return r


def lint_policy_constraints(config_options, cert):
    r = OutputRow("Policy Constraints")

    _process_common_extension_options(config_options,
                                      cert.policy_constraints_value,
                                      'policy_constraints' in cert.critical_extensions, r)

    if cert.policy_constraints_value is not None:

        policy_constraints_native = cert.policy_constraints_value.native

        if policy_constraints_native['require_explicit_policy'] is not None:
            _lint_cert_add_content_to_row(r, "Require Explicit Policy; skipCerts = {}".format(
                policy_constraints_native['require_explicit_policy']))

        if policy_constraints_native['inhibit_policy_mapping'] is not None:
            _lint_cert_add_content_to_row(r, "Inhibit Policy Mapping; skipCerts = {}".format(
                policy_constraints_native['inhibit_policy_mapping']))


        _do_presence_test(r, config_options, 'require_explicit_policy_present',
                          'Require explicit policy', policy_constraints_native['require_explicit_policy'] is not None)

        _do_presence_test(r, config_options, 'inhibit_policy_mapping_present',
                          'Inhibit policy mapping', policy_constraints_native['inhibit_policy_mapping'] is not None)

        if policy_constraints_native['require_explicit_policy'] is not None:
            # todo require_explicit_policy_max
            print("x")

        if policy_constraints_native['inhibit_policy_mapping'] is not None:
            # todo inhibit_policy_mapping_max
            print("x")

    return r


def lint_basic_constraints(config_options, cert):
    r = OutputRow("Basic Constraints")

    _process_common_extension_options(config_options,
                                      cert.basic_constraints_value,
                                      'basic_constraints' in cert.critical_extensions, r)

    if cert.basic_constraints_value is not None:

        bc = cert.basic_constraints_value

        _lint_cert_add_content_to_row(r, "CA = {}".format(bc.native['ca']))

        _do_presence_test(r, config_options, 'ca_true',
                          'CA flag', bc.native['ca'] is True)

        if bc.native['path_len_constraint'] is not None:
            _lint_cert_add_content_to_row(r, "Path Length Constraint = {}".format(bc.native['path_len_constraint']))

            path_length_constraint_max = 99
            if 'path_length_constraint_max' in config_options and len(
                    config_options['path_length_constraint_max'].value) > 0:
                path_length_constraint_max = int(config_options['path_length_constraint_max'].value)

            if bc.native['path_len_constraint'] > path_length_constraint_max:
                _lint_cert_add_error_to_row(r, "Maximum allowed path length is {}".format(path_length_constraint_max))

        if bc.native['ca'] is False and len(bc.contents) > 0:
            _lint_cert_add_error_to_row(r, "Basic Constraints default value (cA=FALSE) was encoded: {}".format(
                ''.join('%02X' % c for c in bc.contents)))

        _do_presence_test(r, config_options, 'path_length_constraint_req', 'Path Length Constraint',
                          bc.native['path_len_constraint'] is not None)

    return r


qualifiers_display_map = {
    'certification_practice_statement': 'CPS',
    'user_notice': 'User Notice',
    'notice_ref': 'Ref',
    'explicit_text': 'Text',
}


def lint_policies(config_options, cert):
    r = OutputRow("Certificate Policies")

    _process_common_extension_options(config_options,
                                      cert.certificate_policies_value,
                                      'certificate_policies' in cert.critical_extensions, r)

    permitted_policies = None

    if cert.certificate_policies_value is not None:

        if 'permitted' in config_options and len(config_options['permitted'].value) > 0:
            permitted_policies = config_options['permitted'].value.split()

        policy_count = 0
        for policy in cert.certificate_policies_value:

            policy_count += 1
            policy_display_string = "[{}]{}{}".format(policy_count, _lint_cert_indent,
                                                      policy['policy_identifier'].dotted)
            if policy['policy_identifier'].dotted in policies_display_map:
                policy_display_string = "{}{}({})".format(policy_display_string, _lint_cert_indent,
                                                          policies_display_map[policy['policy_identifier'].dotted])
            _lint_cert_add_content_to_row(r, policy_display_string)

            if policy.native['policy_qualifiers'] is not None:
                for qualifier in policy.native['policy_qualifiers']:

                    qualifier_type = qualifiers_display_map.get(qualifier['policy_qualifier_id'],
                                                                qualifier['policy_qualifier_id'])

                    qualifier_string = "{}{}".format(_lint_cert_indent, qualifier_type)

                    if qualifier['policy_qualifier_id'] == 'certification_practice_statement':

                        if qualifier['qualifier'] is not None:
                            qualifier_string += ": " + qualifier['qualifier']

                    elif qualifier['policy_qualifier_id'] == 'user_notice':

                        if qualifier['qualifier'] is not None:

                            if qualifier['qualifier']['notice_ref'] is not None:
                                qualifier_string += " " + qualifiers_display_map.get('notice_ref', "Ref") \
                                                    + ": " + qualifier['qualifier']['notice_ref']
                                if qualifier['qualifier']['explicit_text'] is not None:
                                    qualifier_string += _lint_cert_indent + _lint_cert_indent

                            if qualifier['qualifier']['explicit_text'] is not None:
                                qualifier_string += " " + qualifiers_display_map.get('explicit_text', "Text") \
                                                    + ": " + qualifier['qualifier']['explicit_text']

                    elif qualifier['qualifier'] is not None and isinstance(qualifier['qualifier'], str):
                        qualifier_string += ": " + qualifier['qualifier']

                    _lint_cert_add_content_to_row(r, qualifier_string)

            if permitted_policies is not None and \
                            policy['policy_identifier'].dotted not in permitted_policies:
                _lint_cert_add_error_to_row(r, "{} is not a permitted".format(policy['policy_identifier'].dotted))

    return r


def _lint_do_alt_name(r, config_options, alt_name_value):
    if alt_name_value is None:
        return

    types_found = []

    for general_name in alt_name_value:
        _lint_cert_add_content_to_row(r, get_general_name_string(general_name, True))
        types_found.append(get_general_name_type(general_name))
        if general_name.name == 'other_name' and 'other_name' not in types_found:
            types_found.append('other_name')
            # elif general_name.name == 'uniform_resource_identifier' and 'uniform_resource_identifier' not in types_found:
            #    types_found.append('uniform_resource_identifier')

    _do_presence_test(r, config_options, 'other_name',
                      general_name_display_map['other_name'],
                      'other_name' in types_found)

    _do_presence_test(r, config_options, 'rfc822_name',
                      general_name_display_map['rfc822_name'],
                      'rfc822_name' in types_found)

    _do_presence_test(r, config_options, 'dns_name',
                      general_name_display_map['dns_name'],
                      'dns_name' in types_found)

    _do_presence_test(r, config_options, 'x400_address',
                      general_name_display_map['x400_address'],
                      'x400_address' in types_found)

    _do_presence_test(r, config_options, 'directory_name',
                      general_name_display_map['directory_name'],
                      'directory_name' in types_found)

    _do_presence_test(r, config_options, 'edi_party_name',
                      general_name_display_map['edi_party_name'],
                      'edi_party_name' in types_found)

    _do_presence_test(r, config_options, 'uniform_resource_identifier',
                      general_name_display_map['uniform_resource_identifier'],
                      'uniform_resource_identifier' in types_found)

    _do_presence_test(r, config_options, 'ip_address',
                      general_name_display_map['ip_address'],
                      'ip_address' in types_found)

    _do_presence_test(r, config_options, 'registered_id',
                      general_name_display_map['registered_id'],
                      'registered_id' in types_found)

    _do_presence_test(r, config_options, 'other_name_upn',
                      general_name_display_map['other_name_upn'],
                      'other_name_upn' in types_found)

    _do_presence_test(r, config_options, 'other_name_piv_fasc_n',
                      general_name_display_map['other_name_piv_fasc_n'],
                      'other_name_piv_fasc_n' in types_found)

    _do_presence_test(r, config_options, 'uniform_resource_identifier_chuid',
                      general_name_display_map['uniform_resource_identifier_chuid'],
                      'uniform_resource_identifier_chuid' in types_found)

    return


def lint_san(config_options, cert):
    r = OutputRow("Subject Alternate Name")

    _process_common_extension_options(config_options,
                                      cert.subject_alt_name_value,
                                      'subject_alt_name' in cert.critical_extensions, r)

    _lint_do_alt_name(r, config_options, cert.subject_alt_name_value)

    return r


def lint_ian(config_options, cert):
    r = OutputRow("Issuer Alternate Name")

    _process_common_extension_options(config_options,
                                      cert.issuer_alt_name_value,
                                      'issuer_alt_name' in cert.critical_extensions, r)

    _lint_do_alt_name(r, config_options, cert.issuer_alt_name_value)

    return r


eku_display_map = {
    # https://tools.ietf.org/html/rfc5280#page-45
    '2.5.29.37.0': 'Any Extended Key Usage',
    '1.3.6.1.5.5.7.3.1': 'Server Authentication',
    '1.3.6.1.5.5.7.3.2': 'Client Authentication',
    '1.3.6.1.5.5.7.3.3': 'Code Signing',
    '1.3.6.1.5.5.7.3.4': 'Email Protection',
    '1.3.6.1.5.5.7.3.5': 'IPSEC End System',
    '1.3.6.1.5.5.7.3.6': 'IPSEC Tunnel',
    '1.3.6.1.5.5.7.3.7': 'IPSEC User',
    '1.3.6.1.5.5.7.3.8': 'Time Stamping',
    '1.3.6.1.5.5.7.3.9': 'OCSP Signing',
    # http://tools.ietf.org/html/rfc3029.html#page-9
    '1.3.6.1.5.5.7.3.10': 'DVCS',
    # http://tools.ietf.org/html/rfc6268.html#page-16
    '1.3.6.1.5.5.7.3.13': 'EAP over PPP',
    '1.3.6.1.5.5.7.3.14': 'EAP over LAN',
    # https://tools.ietf.org/html/rfc5055#page-76
    '1.3.6.1.5.5.7.3.15': 'SCVP Server',
    '1.3.6.1.5.5.7.3.16': 'SCVP Client',
    # https://tools.ietf.org/html/rfc4945#page-31
    '1.3.6.1.5.5.7.3.17': 'IPSEC IKE',
    # https://tools.ietf.org/html/rfc5415#page-38
    '1.3.6.1.5.5.7.3.18': 'CAPWAP ac',
    '1.3.6.1.5.5.7.3.19': 'CAPWAP wtp',
    # https://tools.ietf.org/html/rfc5924#page-8
    '1.3.6.1.5.5.7.3.20': 'SIP Domain',
    # https://tools.ietf.org/html/rfc6187#page-7
    '1.3.6.1.5.5.7.3.21': 'Secure Shell Client',
    '1.3.6.1.5.5.7.3.22': 'Secure Shell Server',
    # https://tools.ietf.org/html/rfc6494#page-7
    '1.3.6.1.5.5.7.3.23': 'send router',
    '1.3.6.1.5.5.7.3.24': 'send proxied router',
    '1.3.6.1.5.5.7.3.25': 'send owner',
    '1.3.6.1.5.5.7.3.26': 'send proxied owner',
    # https://tools.ietf.org/html/rfc6402#page-10
    '1.3.6.1.5.5.7.3.27': 'CMC CA',
    '1.3.6.1.5.5.7.3.28': 'CMC RA',
    '1.3.6.1.5.5.7.3.29': 'CMC Archive',
    # https://tools.ietf.org/html/draft-ietf-sidr-bgpsec-pki-profiles-15#page-6
    '1.3.6.1.5.5.7.3.30': 'bgpspec router',
    # https://msdn.Microsoft.com/en-us/library/windows/desktop/aa378132(v=vs.85).aspx
    # and https://support.Microsoft.com/en-us/kb/287547
    '1.3.6.1.4.1.311.10.3.1': 'Microsoft Trust List Signing',
    '1.3.6.1.4.1.311.10.3.2': 'Microsoft time stamp signing',
    '1.3.6.1.4.1.311.10.3.3': 'Microsoft server gated',
    '1.3.6.1.4.1.311.10.3.3.1': 'Microsoft serialized',
    '1.3.6.1.4.1.311.10.3.4': 'Microsoft EFS',
    '1.3.6.1.4.1.311.10.3.4.1': 'Microsoft EFS recovery',
    '1.3.6.1.4.1.311.10.3.5': 'Microsoft whql',
    '1.3.6.1.4.1.311.10.3.6': 'Microsoft nt5',
    '1.3.6.1.4.1.311.10.3.7': 'Microsoft oem whql',
    '1.3.6.1.4.1.311.10.3.8': 'Microsoft embedded nt',
    '1.3.6.1.4.1.311.10.3.9': 'Microsoft root list signer',
    '1.3.6.1.4.1.311.10.3.10': 'Microsoft qualified subordination',
    '1.3.6.1.4.1.311.10.3.11': 'Microsoft key recovery',
    '1.3.6.1.4.1.311.10.3.12': 'Microsoft Document Signing',
    '1.3.6.1.4.1.311.10.3.13': 'Microsoft Lifetime signing',
    '1.3.6.1.4.1.311.10.3.14': 'Microsoft mobile device software',
    # https://opensource.Apple.com/source
    #  - /Security/Security-57031.40.6/Security/libsecurity keychain/lib/SecPolicy.cpp
    #  - /libsecurity cssm/libsecurity cssm-36064/lib/oidsalg.c
    '1.2.840.113635.100.1.2': 'Apple x509 basic',
    '1.2.840.113635.100.1.3': 'Apple ssl',
    '1.2.840.113635.100.1.4': 'Apple local cert gen',
    '1.2.840.113635.100.1.5': 'Apple csr gen',
    '1.2.840.113635.100.1.6': 'Apple revocation crl',
    '1.2.840.113635.100.1.7': 'Apple revocation ocsp',
    '1.2.840.113635.100.1.8': 'Apple smime',
    '1.2.840.113635.100.1.9': 'Apple eap',
    '1.2.840.113635.100.1.10': 'Apple software update signing',
    '1.2.840.113635.100.1.11': 'Apple IPSEC',
    '1.2.840.113635.100.1.12': 'Apple ichat',
    '1.2.840.113635.100.1.13': 'Apple resource signing',
    '1.2.840.113635.100.1.14': 'Apple pkinit client',
    '1.2.840.113635.100.1.15': 'Apple pkinit server',
    '1.2.840.113635.100.1.16': 'Apple code signing',
    '1.2.840.113635.100.1.17': 'Apple package signing',
    '1.2.840.113635.100.1.18': 'Apple id validation',
    '1.2.840.113635.100.1.20': 'Apple time stamping',
    '1.2.840.113635.100.1.21': 'Apple revocation',
    '1.2.840.113635.100.1.22': 'Apple passbook signing',
    '1.2.840.113635.100.1.23': 'Apple mobile store',
    '1.2.840.113635.100.1.24': 'Apple escrow service',
    '1.2.840.113635.100.1.25': 'Apple profile signer',
    '1.2.840.113635.100.1.26': 'Apple qa profile signer',
    '1.2.840.113635.100.1.27': 'Apple test mobile store',
    '1.2.840.113635.100.1.28': 'Apple otapki signer',
    '1.2.840.113635.100.1.29': 'Apple test otapki signer',
    '1.2.840.113625.100.1.30': 'Apple id validation record signing policy',
    '1.2.840.113625.100.1.31': 'Apple smp encryption',
    '1.2.840.113625.100.1.32': 'Apple test smp encryption',
    '1.2.840.113635.100.1.33': 'Apple server authentication',
    '1.2.840.113635.100.1.34': 'Apple pcs escrow service',
    # missing from asn1crypto
    '1.3.6.1.4.1.311.20.2.2': 'Microsoft Smart Card Logon',
    '2.16.840.1.101.3.6.8': 'id-PIV-cardAuth',
    '2.16.840.1.101.3.6.7': 'id-PIV-content-signing',
    '2.16.840.1.101.3.8.7': 'id-fpki-pivi-content-signing',
    '1.3.6.1.5.2.3.4': 'id-pkinit-KPClientAuth',
    '1.3.6.1.5.2.3.5': 'id-pkinit-KPKdc',
    '1.2.840.113583.1.1.5': 'Adobe PDF Signing',
    '2.23.133.8.1': 'Endorsement Key Certificate',
}


def lint_eku(config_options, cert):
    r = OutputRow("Extended Key Usage")

    _process_common_extension_options(config_options,
                                      cert.extended_key_usage_value,
                                      'extended_key_usage' in cert.critical_extensions, r)

    if cert.extended_key_usage_value is not None:

        eku_oids = []
        for eku in cert.extended_key_usage_value:
            eku_oids.append(eku.dotted)
            _lint_cert_add_content_to_row(r,
                                          "{} ({})".format(eku_display_map.get(eku.dotted, "Unknown EKU"), eku.dotted))

        for ce in config_options:
            if "oid_" in ce:
                _do_presence_test(r, config_options, ce,
                                  eku_display_map.get(config_options[ce].oid, "Unknown EKU"),
                                  config_options[ce].oid in eku_oids)

    return r

# id-ce-cRLDistributionPoints OBJECT IDENTIFIER ::=  { id-ce 31 }
#
# CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
#
# DistributionPoint ::= SEQUENCE {
#      distributionPoint       [0]     DistributionPointName OPTIONAL,
#      reasons                 [1]     ReasonFlags OPTIONAL,
#      cRLIssuer               [2]     GeneralNames OPTIONAL }
#
# DistributionPointName ::= CHOICE {
#      fullName                [0]     GeneralNames,
#      nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
#
# If the distributionPoint field contains a directoryName, the entry
# for that directoryName contains the current CRL for the associated
# reasons and the CRL is issued by the associated cRLIssuer.
#
# If the DistributionPointName contains a general name of type URI, the
# following semantics MUST be assumed: the URI is a pointer to the
# current CRL for the associated reasons and will be issued by the
# associated cRLIssuer.
#
# If the DistributionPointName contains the single value
# nameRelativeToCRLIssuer, the value provides a distinguished name


crldp_display_map = {
    'full_name': 'Full Name',
    'name_relative_to_crl_issuer': 'Name Relative to Issuer',
}


def lint_crldp(config_options, cert):
    r = OutputRow("CRL Distribution Points")
    _process_common_extension_options(config_options,
                                      cert.crl_distribution_points_value,
                                      'crl_distribution_points' in cert.critical_extensions, r)

    if cert.crl_distribution_points_value is not None:

        crldp = cert.crl_distribution_points_value

        dp_num = 0
        first_http = 0
        first_ldap = 0
        first_directory_name = 0

        for dp in crldp:

            dpname = dp['distribution_point']
            dp_num += 1
            _lint_cert_add_content_to_row(r, "[{}] {}:".format(dp_num, crldp_display_map[dpname.name]))

            if dpname.name != 'full_name':
                # todo find a sample cert with nameRelativeToCRLIssuer, should be able to pass to pretty dn function
                _lint_cert_add_content_to_row(r, "{}{}".format(_lint_cert_indent, der2ascii(dpname.chosen.contents)))

            else:
                for general_name in dpname.chosen:

                    general_name_string = get_general_name_string(general_name, True)
                    indent_str = "{}{}".format(_lint_cert_newline, _lint_cert_indent)

                    if general_name.name == 'uniform_resource_identifier':

                        if general_name.native[0:7] == 'http://' and first_http == 0:
                            first_http = dp_num
                        if general_name.native[0:7] == 'ldap://' and first_ldap == 0:
                            first_ldap = dp_num

                    elif general_name.name == 'directory_name':
                        if first_directory_name == 0:
                            first_directory_name = dp_num

                        general_name_string = general_name_string.replace(_lint_cert_newline, indent_str)
                        # general_name_string = indent_str + general_name_string

                    _lint_cert_add_content_to_row(r, "{}{}".format(_lint_cert_indent, general_name_string))

        if first_http > 0 and first_ldap > 0:

            if 'http_before_ldap' in config_options and len(config_options['http_before_ldap'].value) > 0:

                http_before_ldap = int(config_options['http_before_ldap'].value)

                if http_before_ldap == '1' and first_http < first_ldap:
                    # require ldap first but http came first
                    _lint_cert_add_error_to_row(r, "LDAP URI must appear before the HTTP URI")
                elif http_before_ldap == '2' and first_ldap < first_http:
                    # require http first but ldap came first
                    _lint_cert_add_error_to_row(r, "HTTP URI must appear before the LDAP URI")

        _do_presence_test(r, config_options, 'http', 'HTTP', first_http > 0)
        _do_presence_test(r, config_options, 'ldap', 'LDAP', first_ldap > 0)
        _do_presence_test(r, config_options, 'directory_name', 'Directory Address', first_directory_name > 0)

    return r


access_method_display_map = {
    'time_stamping': 'Time STamping',
    'ca_issuers': 'Certification Authority Issuers',
    'ca_repository': 'CA Repository',
    'ocsp': 'On-line Certificate Status Protocol'
}


def lint_aia(config_options, cert):
    r = OutputRow("Authority Information Access")

    _process_common_extension_options(config_options,
                                      cert.authority_information_access_value,
                                      'authority_information_access' in cert.critical_extensions, r)

    if cert.authority_information_access_value is not None:

        aia = cert.authority_information_access_value

        dp_num = 0
        first_http = 0
        first_ldap = 0
        first_directory_name = 0
        ocsp_found = False
        ca_issuers_found = False
        ocsp_https = False
        aia_https = False
        aia_ldaps = False
        aia_not_p7c = 0

        for access_description in aia:
            access_method = access_description['access_method']  # AccessMethod
            access_location = access_description['access_location']  # GeneralName
            dp_num += 1

            method_display_string = access_method_display_map.get(access_method.native, "Unknown Access Method")
            _lint_cert_add_content_to_row(r, "[{}] {}:".format(dp_num, method_display_string))

            if access_method.native == 'ocsp':
                ocsp_found = True
            elif access_method.native == 'ca_issuers':
                ca_issuers_found = True

            general_name_string = get_general_name_string(access_location, True)
            indent_str = "{}{}".format(_lint_cert_newline, _lint_cert_indent)

            if access_location.name == 'uniform_resource_identifier':

                if access_method.native == 'ca_issuers':
                    # if access_location.native[0:4] == 'http':
                    if access_location.native.startswith('http'):
                        if first_http == 0:
                            first_http = dp_num
                        if not access_location.native.endswith('.p7c'):
                            aia_not_p7c += 1
                    if access_location.native[0:4] == 'ldap' and first_ldap == 0:
                        first_ldap = dp_num
                    if access_location.native[0:8] == 'https://':
                        aia_https = True
                    if access_location.native[0:8] == 'ldaps://':
                        aia_ldaps = True

                elif access_method.native == 'ocsp':
                    if access_location.native[0:8] == 'https://':
                        ocsp_https = True

            elif access_location.name == 'directory_name':
                if first_directory_name == 0:
                    first_directory_name = dp_num

                general_name_string = general_name_string.replace(_lint_cert_newline, indent_str)
                # general_name_string = indent_str + general_name_string

            _lint_cert_add_content_to_row(r, "{}{}".format(_lint_cert_indent, general_name_string))

        # linting
        if first_http > 0 and first_ldap > 0:

            if 'ca_issuers_http_before_ldap' in config_options and \
                            len(config_options['ca_issuers_http_before_ldap'].value) > 0:

                http_before_ldap = int(config_options['ca_issuers_http_before_ldap'].value)

                if http_before_ldap == '1' and first_http < first_ldap:
                    # require ldap first but http came first
                    _lint_cert_add_error_to_row(r, "LDAP URI must appear before the HTTP URI")
                elif http_before_ldap == '2' and first_ldap < first_http:
                    # require http first but ldap came first
                    _lint_cert_add_error_to_row(r, "HTTP URI must appear before the LDAP URI")

        _do_presence_test(r, config_options, 'ca_issuers_present', 'CA Issuer access method', ca_issuers_found)

        if ca_issuers_found is True:
            _do_presence_test(r, config_options, 'ca_issuers_http', 'HTTP caIssuers', first_http > 0)
            _do_presence_test(r, config_options, 'ca_issuers_ldap', 'LDAP caIssuers', first_ldap > 0)

            _do_presence_test(r, config_options, 'ca_issuers_https', 'HTTPS caIssuers (TLS)', aia_https)
            _do_presence_test(r, config_options, 'ca_issuers_ldaps', 'LDAPS caIssuers (TLS)', aia_ldaps)

            _do_presence_test(r, config_options, 'ca_issuers_directory_name', 'Directory Address AIA',
                              first_directory_name > 0)
            _do_presence_test(r, config_options, 'ca_issuers_http_p7c', 'caIssuers ending in .p7c', aia_not_p7c == 0)

        _do_presence_test(r, config_options, 'ocsp_present', 'OCSP', ocsp_found)

        if ocsp_found is True:
            _do_presence_test(r, config_options, 'ocsp_https', 'OCSP over HTTPS (TLS)', ocsp_https)

    return r


def lint_sia(config_options, cert):
    r = OutputRow("Subject Information Access")
    _process_common_extension_options(config_options,
                                      cert.subject_information_access_value,
                                      'subject_information_access' in cert.critical_extensions, r)

   # id-ad-caRepository OBJECT IDENTIFIER ::= { id-ad 5 }
   # id-ad-timeStamping OBJECT IDENTIFIER ::= { id-ad 3 }

    if cert.subject_information_access_value is not None:
        sia = cert.subject_information_access_value

        access_method_number = 0
        first_http = 0
        first_ldap = 0
        first_directory_name = 0
        ca_repository_found = False
        time_stamping_found = False
        sia_https = False
        sia_ldaps = False

        sia_not_p7c = 0

        for access_description in sia:
            access_method = access_description['access_method']  # AccessMethod
            access_location = access_description['access_location']  # GeneralName
            access_method_number += 1

            method_display_string = access_method_display_map.get(access_method.native, "Unknown Access Method")
            _lint_cert_add_content_to_row(r, "[{}] {}:".format(access_method_number, method_display_string))

            if access_method.native == 'ca_repository':
                ca_repository_found = True
            elif access_method.native == 'time_stamping':
                time_stamping_found = True

            general_name_string = get_general_name_string(access_location, True)
            indent_str = "{}{}".format(_lint_cert_newline, _lint_cert_indent)

            if access_location.name == 'uniform_resource_identifier':

                if access_method.native == 'ca_repository':
                    # if access_location.native[0:4] == 'http':
                    if access_location.native.startswith('http'):
                        if first_http == 0:
                            first_http = access_method_number
                        if not access_location.native.endswith('.p7c'):
                            sia_not_p7c += 1
                    if access_location.native[0:4] == 'ldap' and first_ldap == 0:
                        first_ldap = access_method_number
                    if access_location.native[0:8] == 'https://':
                        sia_https = True
                    if access_location.native[0:8] == 'ldap://':
                        sia_ldaps = True

            elif access_location.name == 'directory_name':
                if first_directory_name == 0:
                    first_directory_name = access_method_number

                general_name_string = general_name_string.replace(_lint_cert_newline, indent_str)
                # general_name_string = indent_str + general_name_string

            _lint_cert_add_content_to_row(r, "{}{}".format(_lint_cert_indent, general_name_string))

        # linting
        if first_http > 0 and first_ldap > 0:

            if 'ca_repository_http_before_ldap' in config_options and \
                            len(config_options['ca_repository_http_before_ldap'].value) > 0:

                http_before_ldap = int(config_options['ca_repository_http_before_ldap'].value)

                if http_before_ldap == '1' and first_http < first_ldap:
                    # require ldap first but http came first
                    _lint_cert_add_error_to_row(r, "LDAP URI must appear before the HTTP URI")
                elif http_before_ldap == '2' and first_ldap < first_http:
                    # require http first but ldap came first
                    _lint_cert_add_error_to_row(r, "HTTP URI must appear before the LDAP URI")

        _do_presence_test(r, config_options, 'ca_repository_present',
                          'CA Repository access method', ca_repository_found)

        if ca_repository_found is True:
            _do_presence_test(r, config_options, 'ca_repository_http', 'HTTP Repository', first_http > 0)
            _do_presence_test(r, config_options, 'ca_repository_ldap', 'LDAP Repository', first_ldap > 0)

            _do_presence_test(r, config_options, 'ca_repository_https', 'HTTPS Repository (TLS)', sia_https)
            _do_presence_test(r, config_options, 'ca_repository_ldaps', 'LDAPS Repository (TLS)', sia_ldaps)

            _do_presence_test(r, config_options, 'ca_repository_directory_name', 'Directory Address',
                              first_directory_name > 0)
            _do_presence_test(r, config_options, 'ca_repository_http_p7c',
                              'HTTP Repository ending in .p7c', sia_not_p7c == 0)

        _do_presence_test(r, config_options, 'time_stamping_present', 'Time Stamping', time_stamping_found)

    return r


# id-ce-privateKeyUsagePeriod OBJECT IDENTIFIER ::=  { id-ce 16 }
#
# PrivateKeyUsagePeriod ::= SEQUENCE {
#      notBefore       [0]     GeneralizedTime OPTIONAL,
#      notAfter        [1]     GeneralizedTime OPTIONAL }
#      -- either notBefore or notAfter MUST be present


def lint_pkup(config_options, cert):
    r = OutputRow("Private Key Usage Period")

    pkup, is_critical = get_extension_from_certificate(cert, '2.5.29.16')

    _process_common_extension_options(config_options,
                                      pkup,
                                      is_critical, r)

    if pkup is not None:
        _lint_cert_add_content_to_row(r, der2ascii(pkup['extn_value'].contents))

    return r


def lint_sub_dir_attr(config_options, cert):
    r = OutputRow("Subject Directory Attributes")

    subject_directory_attributes, is_critical = get_extension_from_certificate(cert, '2.5.29.9')

    _process_common_extension_options(config_options,
                                      subject_directory_attributes,
                                      is_critical, r)

    if subject_directory_attributes is not None:
        _lint_cert_add_content_to_row(r, der2ascii(subject_directory_attributes['extn_value'].contents))

    return r


def lint_ocsp_nocheck(config_options, cert):
    r = OutputRow("OCSP No Check")

    _process_common_extension_options(config_options,
                                      cert.ocsp_no_check_value,
                                      'ocsp_no_check' in cert.critical_extensions, r)

    if cert.ocsp_no_check_value is not None:
        # The value of the extension SHALL be NULL.
        if len(cert.ocsp_no_check_value.contents) is 0:
            _lint_cert_add_content_to_row(r, "NULL")
        else:
            _lint_cert_add_content_to_row(r, get_der_display_string(cert.ocsp_no_check_value.contents))
            _lint_cert_add_error_to_row(r, "Extension content is not NULL")

    return r


def lint_inhibit_any(config_options, cert):
    r = OutputRow("Inhibit Any Policy")

    _process_common_extension_options(config_options,
                                      cert.inhibit_any_policy_value,
                                      'inhibit_any_policy' in cert.critical_extensions, r)

    if cert.inhibit_any_policy_value is not None:
        _lint_cert_add_content_to_row(r, "SkipCerts = {}".format(cert.inhibit_any_policy_value.native))

    return r


# class TbsCertificate(Sequence):
#     _fields = [
#         ('version', Version, {'explicit': 0, 'default': 'v1'}),
#         ('serial_number', Integer),
#         ('signature', SignedDigestAlgorithm),
#         ('issuer', Name),
#         ('validity', Validity),
#         ('subject', Name),
#         ('subject_public_key_info', PublicKeyInfo),
#         ('issuer_unique_id', OctetBitString, {'implicit': 1, 'optional': True}),
#         ('subject_unique_id', OctetBitString, {'implicit': 2, 'optional': True}),
#         ('extensions', Extensions, {'explicit': 3, 'optional': True}),
#     ]
#
# class Certificate(Sequence):
#     _fields = [
#         ('tbs_certificate', TbsCertificate),
#         ('signature_algorithm', SignedDigestAlgorithm),
#         ('signature_value', OctetBitString),
#     ]


def lint_signature_algorithm(config_options, cert):
    r = OutputRow("Signature Algorithm")

    sig_alg = cert['signature_algorithm']['algorithm']
    tbs_alg = cert['tbs_certificate']['signature']['algorithm']

    _lint_cert_add_content_to_row(r, "{} ({})".format(sig_alg.native.replace('_', '-'), sig_alg.dotted))

    if sig_alg != tbs_alg:
        _lint_cert_add_error_to_row(r, "Signature algorithm ({}) does not match TBSCertificate::signature ({})".format(
            sig_alg.dotted, tbs_alg.dotted))

    found = False

    # iterate over all alg entries
    for ce in config_options:
        if "alg_" in ce:
            found = config_options[ce].oid == sig_alg.dotted
            if found:
                if config_options[ce].value == '1':
                    _lint_cert_add_error_to_row(r, "Signature algorithm not permitted")
                break

    if not found:
        _lint_cert_add_error_to_row(r, "Signature algorithm not included in option set", "WARN")

    return r


def lint_version(config_options, cert):
    r = OutputRow("Version", cert['tbs_certificate']['version'].native)

    if 'min_version' in config_options and len(config_options['min_version'].value) > 0:
        min_version_num = int(config_options['min_version'].value)

        if int(cert['tbs_certificate']['version']) < min_version_num:
            _lint_cert_add_error_to_row(r, "Minimum permitted version is v{}".format(str(min_version_num + 1)))

    return r


def lint_serial_number(config_options, cert):
    r = OutputRow("Serial Number")

    serial_number = cert['tbs_certificate']['serial_number'].contents
    _lint_cert_add_content_to_row(r, '{}{}({} octets)'.format(' '.join('%02X' % c for c in serial_number),
                                                              _lint_cert_newline,
                                                              len(serial_number)))

    min_length = 0
    max_length = 0

    if 'min_length' in config_options and len(config_options['min_length'].value) > 0:
        min_length = int(config_options['min_length'].value)

    if 'max_length' in config_options and len(config_options['max_length'].value) > 0:
        max_length = int(config_options['max_length'].value)

    if min_length is not 0 and len(serial_number) < min_length:
        _lint_cert_add_error_to_row(r, "Minimum permitted length is {} octets".format(str(min_length)))

    if max_length is not 0 and len(serial_number) > max_length:
        _lint_cert_add_error_to_row(r, "Maximum permitted length is {} octets".format(str(max_length)))

    return r


public_key_algorithm_display_map = {
    # https://tools.ietf.org/html/rfc8017
    '1.2.840.113549.1.1.1': 'RSA',
    '1.2.840.113549.1.1.7': 'RSAES-OAEP',
    '1.2.840.113549.1.1.10': 'RSASSA-PSS',
    # https://tools.ietf.org/html/rfc3279#page-18
    '1.2.840.10040.4.1': 'DSA',
    # https://tools.ietf.org/html/rfc3279#page-13
    '1.2.840.10045.2.1': 'EC',
    # https://tools.ietf.org/html/rfc3279#page-10
    '1.2.840.10046.2.1': 'DH',
}


# alg_rsa	INT	0, 1, 2	Optional, Disallowed, Required
# alg_ec	INT	0, 1, 2	Optional, Disallowed, Required
# alg_ec_named_curve	Multi-OID	Null, <OID>, …	Any | Permitted List
# alg_dsa	INT	0, 1, 2	Optional, Disallowed, Required
# min_size	INT	0, N	If non-zero, min key size (in bits)
# max_size	INT	0, N	If non-zero, max key size (in bits)


def lint_subject_public_key_info(config_options, cert):
    r = OutputRow("Subject Public Key")

    public_key_info = cert['tbs_certificate']['subject_public_key_info']
    public_key_alg = public_key_info['algorithm']['algorithm'].dotted

    _lint_cert_add_content_to_row(r,
                                  '{}-{} ({})'.format(public_key_algorithm_display_map.get(public_key_alg, "Unknown"),
                                                      public_key_info.bit_size,
                                                      public_key_alg))
    _lint_cert_add_content_to_row(r, "")
    pub_key_bytes = public_key_info['public_key'].contents
    # strip leading 00 so it matches microsoft cert viewer
    if pub_key_bytes[0] is 0:
        pub_key_bytes = pub_key_bytes[1:]
    # 43 chars to match ms cert viewer
    pub_key_text = textwrap.fill(' '.join('%02X' % c for c in pub_key_bytes), 43)
    _lint_cert_add_content_to_row(r, pub_key_text.replace('\n', _lint_cert_newline))

    if public_key_info.algorithm == 'rsa':
        if 'parameters' in public_key_info['algorithm']:
            if public_key_info['algorithm']['parameters'] is not None and len(
                    public_key_info['algorithm']['parameters'].contents) > 0:
                _lint_cert_add_content_to_row(r, "{}**Parameters**:{}".format(_lint_cert_newline, _lint_cert_newline))
                _lint_cert_add_content_to_row(r, der2ascii(public_key_info['algorithm']['parameters'].contents))

        pub_key = public_key_info.unwrap()
        modulus = pub_key.native['modulus']
        public_exponent = pub_key.native['public_exponent']

    # todo add parameters
    min_size = 0
    max_size = 0

    if 'min_size' in config_options and len(config_options['min_size'].value) > 0:
        min_size = int(config_options['min_size'].value)

    if 'max_size' in config_options and len(config_options['max_size'].value) > 0:
        max_size = int(config_options['max_size'].value)

    found = False

    # iterate over all alg entries
    for ce in config_options:
        if "alg_" in ce:
            found = config_options[ce].oid == public_key_alg
            if found:
                if config_options[ce].value == '1':
                    _lint_cert_add_error_to_row(r, "Algorithm not permitted")
                break

    # public_key_info = cert['tbs_certificate']['subject_public_key_info']
    # public_key_alg = public_key_info['algorithm']['algorithm'].dotted
    if public_key_info.algorithm == 'rsa':

        if min_size > public_key_info.bit_size:
            _lint_cert_add_error_to_row(r, "Smaller than minimum key size ({} bits)".format(min_size))
        if max_size != 0 and max_size < public_key_info.bit_size:
            _lint_cert_add_error_to_row(r, "Larger than maximum key size ({} bits)".format(max_size))

    if not found:
        _lint_cert_add_error_to_row(r, "Algorithm not included in option set", "WARN")

    return r


def _lint_format_time(x509_time, name_string):
    return "{}:  {}{}{}{}[{}] {}{}".format(name_string, x509_time.native, _lint_cert_newline,
                                           _lint_cert_indent, _lint_cert_indent,
                                           x509_time.name, x509_time.chosen, _lint_cert_newline)


# validity	validity_period_maximum
# validity	validity_period_generalized_time
def lint_validity(config_options, cert):
    r = OutputRow("Validity Period")
    validity_period_maximum = LINT_CERT_NONE
    validity_period_generalized_time = LINT_CERT_OPTIONAL

    nb = cert['tbs_certificate']['validity']['not_before']
    na = cert['tbs_certificate']['validity']['not_after']

    r.content = _lint_format_time(nb, 'Not Before')
    r.content += _lint_cert_newline
    r.content += _lint_format_time(na, 'Not After')

    lifespan = na.native - nb.native
    r.content += _lint_cert_newline
    r.content += "Valid for {}".format(lifespan)

    if 'validity_period_maximum' in config_options and len(config_options['validity_period_maximum'].value) > 0:
        validity_period_maximum = int(config_options['validity_period_maximum'].value)

    if 'validity_period_generalized_time' in config_options and len(
            config_options['validity_period_generalized_time'].value):
        validity_period_generalized_time = int(config_options['validity_period_generalized_time'].value)

    if validity_period_maximum > 0:
        # lifespan must be less than validity_period_maximum
        max_validity = datetime.timedelta(days=validity_period_maximum)
        if lifespan > max_validity:
            _lint_cert_add_error_to_row(r, "Validity period exceeds {} days".format(str(validity_period_maximum)))

    # below makes the assumption that if you put a date between 1950 and 1985 in a cert that you really meant
    # 2050 to 2085 and should have used generalized time instead of utc
    must_not_be_right = datetime.datetime(1985, 12, 31)
    must_not_be_right = must_not_be_right.replace(tzinfo=pytz.UTC)

    if nb.name == 'utc_time':
        if nb.native < must_not_be_right or validity_period_generalized_time is LINT_CERT_REQUIRED:
            _lint_cert_add_error_to_row(r, "notBefore is required to be GeneralizedTime")
    elif validity_period_generalized_time is LINT_CERT_DISALLOWED:
        _lint_cert_add_error_to_row(r, "notBefore is not permitted to be GeneralizedTime")

    if na.name == 'utc_time':
        if na.native < must_not_be_right or validity_period_generalized_time is LINT_CERT_REQUIRED:
            _lint_cert_add_error_to_row(r, "notAfter is required to be GeneralizedTime")
    elif validity_period_generalized_time is LINT_CERT_DISALLOWED:
        _lint_cert_add_error_to_row(r, "notAfter is not permitted to be GeneralizedTime")

    return r


printable_string_char_set = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
    'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
    's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '\'', '(', ')', '+',
    '-', '.', '/', ':', '=', '?', ' ', ','
}


def _lint_check_printable_strings(r, name):
    if not isinstance(name, x509.Name):
        raise TypeError("name must be an x509.Name")

    rdn_seq = name.chosen  # type = RDNSequence
    if len(rdn_seq):
        rdn_list = list()
        for rdn in rdn_seq:
            rdn_list.append(rdn)

        rdn_list.reverse()

        for rdn2 in rdn_list:
            for name2 in rdn2:
                if isinstance(name2['value'], x509.DirectoryString) and name2['value'].name == 'printable_string':
                    for c in name2.native['value']:
                        if c not in printable_string_char_set:
                            r = get_pretty_dn_name_component(name2['type'])
                            _lint_cert_add_error_to_row(r, "{}: \'{}\' is not permitted in PrintableString".format(r, c))

    return


def lint_dn(config_options, dn, row_name):
    separator = ",{}".format(_lint_cert_newline)
    pretty_name = get_pretty_dn(dn, separator, " = ", True)
    r = OutputRow(row_name, pretty_name)

    if 'base_dn' in config_options and len(config_options['base_dn'].value) > 0:
        # todo: check for base_dn match if base_dn has value
        print("fill in base dn check code")

    for ce in config_options:
        if "rdn_" in ce:
            # print(ce + " " + config_options[ce].oid)
            found = is_name_type_in_dn(config_options[ce].oid, dn)
            if found is True and config_options[ce].value is '1':
                _lint_cert_add_error_to_row(r, "{} is not permitted".format(ce))
            elif found is False and config_options[ce].value is '2':
                _lint_cert_add_error_to_row(r, "{} is missing".format(ce))

    _lint_check_printable_strings(r, dn)

    return r


def lint_subject(config_options, cert):
    return lint_dn(config_options, cert.subject, "Subject DN")


def lint_issuer(config_options, cert):
    return lint_dn(config_options, cert.issuer, "Issuer DN")


_lint_processed_extensions = {
    "processed extension oids go here"
}

_lint_cert_map_extension_to_display = {
    '2.5.29.9': 'Subject Directory Attributes',
    '2.5.29.14': 'Key Identifier',
    '2.5.29.15': 'Key Usage',
    '2.5.29.16': 'Private Key Usage Period',
    '2.5.29.17': 'Subject Alt Name',
    '2.5.29.18': 'Issuer Alt Name',
    '2.5.29.19': 'Basic Constraints',
    '2.5.29.30': 'Name Constraints',
    '2.5.29.31': 'CRL Distribution Points',
    '2.5.29.32': 'Certificate Policies',
    '2.5.29.33': 'Policy Mappings',
    '2.5.29.35': 'Authority Key Identifier',
    '2.5.29.36': 'Policy Constraints',
    '2.5.29.37': 'Extended Key Usage',
    '2.5.29.46': 'Freshest CRL',
    '2.5.29.54': 'Inhibit Any Policy',
    '1.3.6.1.5.5.7.1.1': 'Authority Information Access',
    '1.3.6.1.5.5.7.1.11': 'Subject Information Access',
    # Https://Tools.Ietf.Org/Html/Rfc7633
    '1.3.6.1.5.5.7.1.24': 'TLS Feature',
    '1.3.6.1.5.5.7.48.1.5': 'OCSP No Check',
    '1.2.840.113533.7.65.0': 'Entrust Version Extension',
    '2.16.840.1.113730.1.1': 'Netscape Certificate Type',
    # missing from asn1crypto
    '1.3.6.1.4.1.311.21.7': 'Microsoft Certificate Template Information',
    # Application Policies extension -- same encoding as szOID_CERT_POLICIES
    '1.3.6.1.4.1.311.21.10': 'Microsoft Application Policies',
    # Application Policy Mappings -- same encoding as szOID_POLICY_MAPPINGS
    '1.3.6.1.4.1.311.21.11': 'Microsoft Application Policy Mappings',
    # Application Policy Constraints -- same encoding as szOID_POLICY_CONSTRAINTS
    '1.3.6.1.4.1.311.21.12': 'Microsoft Application Policy Constraints',
    '1.3.6.1.4.1.311.21.1': 'Microsoft CA Version',
    '1.3.6.1.4.1.311.20.2': 'Microsoft Certificate Template Name',
    '1.2.840.113549.1.9.15': 'S/Mime capabilities',
    '1.3.6.1.4.1.311.21.2': 'Microsoft Previous CA Cert Hash'
}


# returns a list of rows
def lint_other_extensions(config_options, cert):
    rows = []

    extensions = cert['tbs_certificate']['extensions']

    if extensions is None:
        return rows

    others_non_critical = 0
    others_critical = 0

    for e in extensions:
        if e['extn_id'].dotted not in _lint_processed_extensions:
            # init_row_name = None, init_content = None, init_analysis = None, init_config_section = None):
            extension_name = _lint_cert_map_extension_to_display.get(e['extn_id'].dotted, "Unknown")
            if extension_name == 'Unknown':
                extension_name = "{} ({})".format(extension_name, e['extn_id'].dotted)

            r = OutputRow(extension_name, "", "", "other_extensions")
            if e['critical'].native is True:
                others_critical += 1
                _lint_cert_add_content_to_row(r, "Critical = TRUE")
                if 'other_critical_extensions_present' in config_options and \
                                config_options['other_critical_extensions_present'].value is '1':
                    _lint_cert_add_error_to_row(r, "Additional critical extensions are not permitted")
            else:
                others_non_critical += 1
                if 'other_non_critical_extensions_present' in config_options and \
                                config_options['other_non_critical_extensions_present'].value is '1':
                    _lint_cert_add_error_to_row(r, "Additional non-critical extensions are not permitted")

            if e.contents is not None:
                # der_string = 'DER:\n'
                # der_string += textwrap.fill(' '.join('%02X' % c for c in e.contents), 43)
                # der_string = der_string.replace('\n', _lint_cert_newline)
                der_string = der2ascii(e['extn_value'].contents)
                _lint_cert_add_content_to_row(r, der_string)

            rows.append(r)

    return rows


conformance_check_functions = OrderedDict([
    ('version', lint_version),
    ('serial_number', lint_serial_number),
    ('signature_algorithm', lint_signature_algorithm),
    ('issuer', lint_issuer),
    ('validity', lint_validity),
    ('subject', lint_subject),
    ('subject_public_key_info', lint_subject_public_key_info),

    ('key_usage', lint_key_usage),
    ('eku', lint_eku),
    ('basic_constraints', lint_basic_constraints),

    ('skid', lint_skid),
    ('akid', lint_akid),

    ('san', lint_san),
    ('sia', lint_sia),

    ('crldp', lint_crldp),
    ('ian', lint_ian),
    ('aia', lint_aia),

    ('cert_policies', lint_policies),
    ('policy_mappings', lint_policy_mappings),
    ('policy_constraints', lint_policy_constraints),
    ('inhibit_any', lint_inhibit_any),
    ('name_constraints', lint_name_constraints),

    ('piv_naci', lint_piv_naci),
    ('pkup', lint_pkup),
    ('sub_dir_attr', lint_sub_dir_attr),
    ('ocsp_nocheck', lint_ocsp_nocheck),
    # other extensions has to be handled separately
    #    ('other_extensions', lint_other_extensions)
])


def check_cert_conformance(input_cert, profile_file, end_of_line=None, indent=None):
    if not isinstance(input_cert, x509.Certificate):
        raise TypeError("input_cert must be an x509.Certificate")

    if not isinstance(profile_file, str):
        raise TypeError("profile_file must be str")

    global _lint_cert_newline
    lint_cert_newline_reset = _lint_cert_newline
    global _lint_cert_indent
    lint_cert_indent_reset = _lint_cert_indent
    global _lint_processed_extensions

    if end_of_line is not None:
        _lint_cert_newline = end_of_line

    if indent is not None:
        _lint_cert_indent = indent

    with open('profiles/{}.json'.format(profile_file)) as json_data:
        json_profile = json.load(json_data)

    cert_profile = {}

    for entry in json_profile:
        if entry['Section'] not in cert_profile:
            cert_profile[entry['Section']] = {}
        pce = ConfigEntry()
        pce.value = entry['Value']
        pce.oid = entry['OID']
        cert_profile[entry['Section']][entry['Item']] = pce

    # add the oids for all extensions we handle to _lint_processed_extensions list
    # at the end, use that list to add unprocessed extensions to the output
    for config_section in cert_profile:
        for ce in cert_profile[config_section]:
            if ce == 'present' and cert_profile[config_section][ce].oid != '':
                _lint_processed_extensions.add(cert_profile[config_section][ce].oid)

    output_rows = {}
    profile_info_section = None

    for config_section in cert_profile:
        # print(config_section)
        if config_section in conformance_check_functions:
            r = conformance_check_functions[config_section](cert_profile[config_section], input_cert)
            r.config_section = config_section
            if len(r.content) > 0 or len(r.analysis) > 0:
                # can add 'PASS' to r.analysis here if desired
                output_rows[config_section] = r
        elif config_section == 'other_extensions':
            other_extensions_section = cert_profile[config_section]
        elif config_section == 'profile':
            profile_info_section = cert_profile[config_section]
        else:
            print("ERROR - Unrecognized config section:  {}".format(config_section))

    # other_extensions_rows = []
    other_extensions_rows = lint_other_extensions(other_extensions_section, input_cert)

    _lint_cert_newline = lint_cert_newline_reset
    _lint_cert_indent = lint_cert_indent_reset

    return output_rows, other_extensions_rows, profile_info_section


def process_add_certificate(cert, profile_file, output_file):
    # could make these default params if desired
    _add_profile_url = True
    _add_profile_string = True

    output_rows, other_extensions_rows, profile_info = check_cert_conformance(cert, profile_file, "<br>",
                                                                              '&nbsp;&nbsp;&nbsp;&nbsp;')

    header = "\n| **Field** | **Content** | **Analysis** |\n"
    cols = "|:-------- |: ------------------------------------------- |:------------------------------------------------------ |\n"

    output_file.write("\n<br>\n")

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
    output_file.write(header)
    output_file.write(cols)

    final_sorted_rows = []
    for key, r in conformance_check_functions.items():
        if key in output_rows:
            final_sorted_rows.append(output_rows[key])
    for r in other_extensions_rows:
        final_sorted_rows.append(r)

    all_was_good = "<font color=\"green\">OK</font>"

    for r in final_sorted_rows:
        output_file.write("| **{}** ".format(r.row_name))
        output_file.write("| {} ".format(r.content))
        if r.analysis == "":
            r.analysis = all_was_good
        output_file.write("| {}&nbsp;|\n".format(r.analysis))


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

def process_one_certificate(cert, profile_file, output_file_name, document_title):
    strap_start = "<!DOCTYPE html>\n<html>\n<title>{}</title>\n<xmp theme=\"cyborg\" style=\"display:none;\"\n>"
    strap_end = "\n</xmp>\n<script src=\"strapdown.js\"></script>\n</html>\n"

    with open(output_file_name, 'w') as output_file:
        output_file.write(strap_start.format(document_title))
        process_add_certificate(cert, profile_file, output_file)
        output_file.write(strap_end)


# example input list
# filename, profile
# piv_test_certs = [
#     ["testcerts/piv/cardauth.cer", 'PIV_Card_Authentication'],
#     ["testcerts/piv/content_signing.cer", 'PIV_Content_Signer'],
#     ["testcerts/piv/pivauth.cer", "PIV_Identity"],
#     ]


def process_certificate_list(list_of_certs, output_file_name, doc_title):
    strap_start = "<!DOCTYPE html>\n<html>\n<title>{}</title>\n<xmp theme=\"cyborg\" style=\"display:none;\"\n>"
    strap_end = "\n</xmp>\n<script src=\"strapdown.js\"></script>\n</html>\n"

    with open(output_file_name, 'w') as output_file:
        output_file.write(strap_start.format(doc_title))

        for file_name, profile in list_of_certs:
            if profile == "":
                profile = "template"
            with open(file_name, 'rb') as cert_file:
                encoded = cert_file.read()
                cert = parse_cert(encoded)
                if cert is None:
                    print('Failed to parse {}'.format(file_name))
                else:
                    process_add_certificate(cert, profile, output_file)

        output_file.write(strap_end)


from cpct_test import *

if __name__ == "__main__":
    execute_tests()
