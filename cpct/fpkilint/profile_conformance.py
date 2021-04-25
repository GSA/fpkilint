from fpkilint.cert_utils import *
# import json
# import datetime
from datetime import datetime, timedelta, timezone
# import pytz
from collections import OrderedDict
from fpkilint.certificate_policies import policies_display_map
from fpkilint.binary_utils import *
from fpkilint.name_utils import *

# these are not all used, keeping them here as a matter of convenience
from asn1crypto.core import (
    AbstractString,
    Any,
    BitString,
    BMPString,
    Boolean,
    CharacterString,
    Choice,
    Concat,
    GeneralizedTime,
    GeneralString,
    GraphicString,
    IA5String,
    Integer,
    Null,
    NumericString,
    ObjectIdentifier,
    OctetBitString,
    OctetString,
    ParsableOctetString,
    PrintableString,
    Sequence,
    SequenceOf,
    Set,
    SetOf,
    TeletexString,
    UniversalString,
    UTCTime,
    UTF8String,
    VisibleString,
    VideotexString,
    VOID,
)

lint_cert_newline = '\n'
lint_cert_indent = '    '
lint_error_prefix = '**FAIL**'
lint_warning_prefix = '**WARN**'
lint_info_prefix = '**INFO**'


class ConfigEntry:
    def __init__(self):
        self.value = ""
        self.oid = ""


class OutputRow:
    def __init__(self, init_row_name=None, init_content=None, init_analysis=None, init_config_section=None):
        self.row_name = ""
        self.content = ""
        self.analysis = ""
        self.config_section = ""
        self.extension_oid = None
        self.extension_is_critical = False

        if init_row_name is not None:
            self.row_name = init_row_name
        if init_content is not None:
            self.content = init_content
        if init_analysis is not None:
            self.analysis = init_analysis
        if init_config_section is not None:
            self.config_section = init_config_section

    def add_content(self, content_string):
        if len(self.content) > 0:
            self.content += lint_cert_newline

        self.content += str(content_string)

        return

    def add_error(self, error_string, preface=None):
        if len(self.analysis) > 0:
            self.analysis += lint_cert_newline

        if preface is None:
            preface = lint_error_prefix

        if preface != "":
            self.analysis += "{}: {}".format(preface, error_string)
        else:
            self.analysis += error_string

        return


def der2asn(binary_der):
    ascii_string = der2ascii(binary_der)
    ascii_string = ascii_string.replace('\n', lint_cert_newline)
    ascii_string = ascii_string.replace('  ', lint_cert_indent)
    return ascii_string


def format_x509_time(x509_time, name_string):
    return "{}:  {}{}{}{}[{}] {}{}".format(name_string, x509_time.native, lint_cert_newline,
                                           lint_cert_indent, lint_cert_indent,
                                           x509_time.name, x509_time.chosen, lint_cert_newline)


# _utc_ref = "https://tools.ietf.org/html/rfc5280#section-4.1.2.5.1"
# _generalized_ref = "https://tools.ietf.org/html/rfc5280#section-4.1.2.5.2"

# below makes the assumption that if you put a date between 1950 and 1985 in a cert that you really meant
# 2050 to 2085 and should have used generalized time instead of utc
_must_not_be_right = datetime(1985, 12, 31)
_must_not_be_right = _must_not_be_right.replace(tzinfo=timezone.utc)


def lint_and_format_x509_time(x509_time, name_string, r):

    if not x509_time.chosen.contents.endswith(b'Z'):
        r.add_error("{} is not expressed in GMT (RFC5280).".format(name_string))
    else:
        if x509_time.name == 'utc_time':
            if len(x509_time.chosen.contents) == 11:
                r.add_error("{} does not include seconds. (RFC5280)".format(name_string))
            elif len(x509_time.chosen.contents) != 13:
                r.add_error("{} format is not YYMMDDHHMMSSZ. (RFC5280)".format(name_string))

            if x509_time.native < _must_not_be_right:
                r.add_error("notBefore is required to be GeneralizedTime for dates beyond 2049")

        elif x509_time.name == 'general_time':
            if len(x509_time.chosen.contents) == 13:
                r.add_error("{} does not include seconds. (RFC5280)".format(name_string))
            elif len(x509_time.chosen.contents) != 15:
                r.add_error("{} format is not YYYYMMDDHHMMSSZ. (RFC5280)".format(name_string))

    return format_x509_time(x509_time, name_string)


def _lint_get_extension_options(config_options):
    option_present = 0
    option_is_critical = 0
    option_extension_oid = None

    if 'present' in config_options and len(config_options['present'].value) > 0:
        option_present = int(config_options['present'].value)

        if len(config_options['present'].oid) > 0:
            option_extension_oid = config_options['present'].oid

    if 'is_critical' in config_options and len(config_options['is_critical'].value) > 0:
        option_is_critical = int(config_options['is_critical'].value)

    return option_present, option_is_critical, option_extension_oid


def _process_common_extension_options(config_options, cert, r):
    """
    :param config_options: config options for this extension
    :param cert: x509.Certificate
    :param r: output row object
    :return: None or the extension
    """
    option_present, option_is_critical, option_extension_oid = _lint_get_extension_options(config_options)

    if not option_extension_oid:
        r.add_error("Missing extension OID in config file!")
        return None

    r.extension_oid = option_extension_oid

    if isinstance(cert, x509.Certificate):
        cert = cert['tbs_certificate']

    extension_list = get_extension_list(cert, option_extension_oid)

    if len(extension_list) == 0:
        if option_present == 2:
            r.add_error("{} is missing".format(r.row_name))
    else:

        if len(extension_list) > 1:
            r.add_error("{} instances of {} found in certificate.".format(len(extension_list), r.row_name))
            r.add_error("Only the first instance is shown", lint_warning_prefix)

        r.extension_is_critical = extension_list[0][1]

        if option_present == 1:
            r.add_error("{} is not permitted".format(r.row_name))
        if option_is_critical == 2 and r.extension_is_critical is False:
            r.add_error("{} must be marked critical".format(r.row_name))
        if option_is_critical == 1 and r.extension_is_critical is True:
            r.add_error("{} must not be marked critical".format(r.row_name))

        # if r.extension_is_critical is True:
        #     r.add_content("Critical = TRUE")

        return extension_list[0][0]

    return None


def _do_presence_test(r, config_options, cfg_str, display_str, is_present):
    error_string = None

    if cfg_str in config_options and len(config_options[cfg_str].value) > 0:
        if config_options[cfg_str].value == '1' and is_present is True:
            error_string = "is not permitted"
        if config_options[cfg_str].value == '2' and is_present is False:
            error_string = "is missing"

    if error_string is not None:
        r.add_error("{} {}".format(display_str, error_string))

    return


def _get_mappings_config(config_string, config_options, r):

    mappings = None
    any_mapping_from = []
    any_mapping_to = []

    if config_string in config_options and len(config_options[config_string].value) > 0:
        mappings = config_options[config_string].value.split(" ")

    if mappings:
        any_mapping_from = []
        any_mapping_to = []
        for i, mapping in enumerate(mappings):
            mappings[i] = mapping.split(":")

            if not isinstance(mappings[i], list) or len(mappings[i]) != 2:
                r.add_error("Bad {} policy mapping configuration.".format(config_string))
                r.add_error("Configuration takes this form:", "")
                r.add_error("issuer:subject[space]issuer2:subject2[space]...", "")
                r.add_error("e.g. 1.2.3:2.3.4 1.2.4:2.3.5 ...", "")
                r.add_error("A wildcard may also be used.", "")
                r.add_error("e.g. 1.2.3:* 1.2.4:* ...", "")
                return r
            if mappings[i][0] == mappings[i][1]:
                r.add_error("Bad {} policy mapping configuration string in template.".format(config_string))
                r.add_error("subjectDomain and issuerDomain cannot be identical", "")
                return r

            if mappings[i][1] == '*':
                # issuer (mapping from) domain is specified, subject (mapped to) domain is *
                any_mapping_from.append(mappings[i][0])

            if mappings[i][0] == '*':
                # issuer (mapping from) domain is *, subject (mapped to) domain is specified
                any_mapping_to.append(mappings[i][1])

    return mappings, any_mapping_from, any_mapping_to


def lint_policy_mappings(config_options, cert):
    r = OutputRow("Policy Mappings")

    extension = _process_common_extension_options(config_options, cert, r)

    if extension is not None:

        if isinstance(cert, x509.Certificate):
            cert = cert['tbs_certificate']

        policy_set = set()
        policy_extensions = get_extension_list(cert, '2.5.29.32')
        # confirm policy extension is present if mappings are present

        if not policy_extensions:
            r.add_error('The Certificate Policies extension is not present - nothing to map!')
        else:
            certificate_policies = policy_extensions[0][0]['extn_value'].parsed
            for policy in certificate_policies:
                policy_set.add(policy['policy_identifier'].dotted)

        policy_mappings = extension['extn_value'].parsed
        found_mappings = []
        from_set = set()
        to_set = set()

        suppress_warning = 0
        if 'suppress_warning' in config_options and len(config_options['suppress_warning'].value) > 0:
            suppress_warning = int(config_options['suppress_warning'].value)

        mapping_count = 0
        for mapping in policy_mappings:
            mapping_count += 1
            policy_display_string = "[{}]{}{}".format(mapping_count, lint_cert_indent,
                                                      mapping['issuer_domain_policy'].dotted)
            r.add_content(policy_display_string)

            if mapping['issuer_domain_policy'].dotted in policies_display_map:
                policy_display_string = "{}{}({})".format(lint_cert_indent, lint_cert_indent,
                                                          policies_display_map[mapping['issuer_domain_policy'].dotted])
                r.add_content(policy_display_string)

            policy_display_string = "{}{}{}maps to {}".format(lint_cert_indent, lint_cert_indent, lint_cert_indent,
                                                            mapping['subject_domain_policy'].dotted)
            r.add_content(policy_display_string)

            if mapping['subject_domain_policy'].dotted in policies_display_map:
                policy_display_string = "{}{}{}({})".format(lint_cert_indent, lint_cert_indent, lint_cert_indent,
                                                          policies_display_map[mapping['subject_domain_policy'].dotted])
                r.add_content(policy_display_string)

            # confirm each issuer domain policy is actually in the policy extension
            if mapping['issuer_domain_policy'].dotted not in policy_set:
                r.add_error(mapping['issuer_domain_policy'].dotted + ' not present in Certificate Policies')

            if mapping['issuer_domain_policy'].dotted in from_set:
                # this is not the right one
                # r.add_error('Policy mapping [{}] may be ignored by Microsoft Windows'.format(mapping_count), lint_warning_prefix)
                pass
            else:
                from_set.add(mapping['issuer_domain_policy'].dotted)

            if mapping['subject_domain_policy'].dotted in to_set:
                if not suppress_warning:
                    r.add_error('Policy mapping [{}] may be ignored by Microsoft Windows'.format(mapping_count), lint_warning_prefix)
            else:
                to_set.add(mapping['subject_domain_policy'].dotted)

            found_mappings.append([mapping['issuer_domain_policy'].dotted, mapping['subject_domain_policy'].dotted])

        permitted_mappings, any_mapping_from, any_mapping_to = _get_mappings_config('permitted', config_options, r)

        if permitted_mappings:

            for i, found_mapping in enumerate(found_mappings):
                if found_mapping not in permitted_mappings:
                    if found_mapping[0] not in any_mapping_from and found_mapping[1] not in any_mapping_to:
                        r.add_error("Policy mapping [{}] is not permitted".format(i + 1))

        excluded_mappings, any_mapping_from, any_mapping_to = _get_mappings_config('excluded', config_options, r)

        if excluded_mappings:

            for i, found_mapping in enumerate(found_mappings):
                if found_mapping in excluded_mappings or \
                        found_mapping[0] in any_mapping_from or \
                        found_mapping[1] in any_mapping_to:

                        r.add_error("Policy mapping [{}] is not permitted".format(i + 1))

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

def output_name_constraints_subtrees(r, general_subtrees, subtree_type="Permitted or Excluded", indent=""):
    if general_subtrees and not isinstance(general_subtrees, x509.GeneralSubtrees):
        r.add_error("general_subtrees must be type x509.GeneralSubtrees")

    if not general_subtrees:
        r.add_content(subtree_type + " = None")
        return

    r.add_content(subtree_type)

    subtree_index = 0

    for general_subtree in general_subtrees:
        subtree_index += 1

        max_value = general_subtree[2].native
        if not max_value:
            max_value = "Max"

        r.add_content("{}[{}] Subtrees ({}..{})".format(indent, subtree_index, general_subtree[1].native, max_value))
        # def get_general_name_string(general_name, multiline=None, indent_string=None, type_separator=None, include_string_type=None):
        name = get_general_name_string(general_subtree['base'], False, None, '=', False)
        r.add_content("{}{}{}".format(indent, indent, name))

    return


def lint_name_constraints(config_options, cert):
    r = OutputRow("Name Constraints")

    extension = _process_common_extension_options(config_options, cert, r)

    if extension is not None:

        name_constraints = extension['extn_value'].parsed

        output_name_constraints_subtrees(r, name_constraints['permitted_subtrees'], "Permitted",
                                         lint_cert_indent)
        output_name_constraints_subtrees(r, name_constraints['excluded_subtrees'], "Excluded",
                                         lint_cert_indent)

        _do_presence_test(r, config_options, 'permitted', 'Permitted Subtrees',
                          not not name_constraints['permitted_subtrees'])

        _do_presence_test(r, config_options, 'excluded', 'Excluded Subtrees',
                          not not name_constraints['excluded_subtrees'])

        # todo MUST be used only in a CA certificate
        # todo 5280: Conforming CAs MUST mark this extension as critical
        # todo 5280 SHOULD NOT impose name constraints on the x400Address, ediPartyName, or registeredID name forms.
        # todo 5280 Conforming CAs MUST NOT	issue certificates where name constraints is an empty sequence.  That is, either the permittedSubtrees field or the excludedSubtrees MUST be present.
        # todo 5280 Within this profile, the minimum and maximum fields are not used with any name forms, thus, the minimum MUST be zero, and maximum MUST be absent.

    return r


def lint_piv_naci(config_options, cert):
    r = OutputRow("PIV NACI")

    # '2.16.840.1.101.3.6.9.1'
    pivnaci = _process_common_extension_options(config_options, cert, r)

    if pivnaci is not None:
        r.add_content(der2asn(pivnaci['extn_value'].contents))

    return r


def lint_key_usage(config_options, cert):
    r = OutputRow("Key Usage")

    extension = _process_common_extension_options(config_options, cert, r)

    if extension is not None:

        key_usage = extension['extn_value'].parsed

        for ku in key_usage_display_map.keys():
            if ku in key_usage.native:

                r.add_content(key_usage_display_map[ku])

                if ku in config_options and config_options[ku].value == '1':
                    r.add_error("{} is not permitted".format(key_usage_display_map[ku]))

            elif ku in config_options and config_options[ku].value == '2':
                r.add_error("{} is required".format(key_usage_display_map[ku]))

        for ku in key_usage.native:
            if ku not in key_usage_display_map:
                r.add_error("Unknown bit ({}) is not permitted.".format(ku))

        if 'key_encipherment' in key_usage.native:
            # error if key_encipherment and pub key is ec (should be key_agreement)
            public_key_info = cert['tbs_certificate']['subject_public_key_info']
            if public_key_info.algorithm == 'ec':
                r.add_error('keyEncipherment is not appropriate for ECC keys. keyAgreement should be used instead.')

    return r


def lint_akid(config_options, cert):
    r = OutputRow("Authority Key Identifier")

    extension = _process_common_extension_options(config_options, cert, r)
    # todo 5280: except for "self-signed", the keyIdentifier field of the authorityKeyIdentifier extension MUST be included in all certificates generated by conforming CAs

    if extension is not None:

        akid = extension['extn_value'].parsed

        akid_has_keyid = False
        akid_has_issuer = False
        akid_has_serial = False

        if isinstance(akid['key_identifier'], x509.OctetString):
            akid_has_keyid = True
            r.add_content('Key ID: {}'.format(
                ''.join('%02X' % c for c in akid['key_identifier'].contents)))

        if isinstance(akid['authority_cert_issuer'], x509.GeneralNames):

            akid_has_issuer = True

            if len(r.content) > 0:
                r.add_content("")

            if len(akid['authority_cert_issuer']) == 0:
                r.add_content("NULL")
                r.add_error("Authority cert issuer was present but contained no GeneralNames?")
            elif len(akid['authority_cert_issuer']) == 1 and akid['authority_cert_issuer'][0].name == 'directory_name':
                separator = "," + lint_cert_newline + lint_cert_indent
                issuer_name = get_pretty_dn(akid['authority_cert_issuer'][0].chosen, separator, " = ")
                r.add_content("Issuer DN:")
                r.add_content("{}{}".format(lint_cert_indent, issuer_name))
            else:
                r.add_content("Issuer Names:")
                for general_name in akid['authority_cert_issuer']:
                    r.add_content("{}{}".format(lint_cert_indent,
                                                get_general_name_string(general_name)))

        if isinstance(akid['authority_cert_serial_number'], x509.Integer):
            akid_has_serial = True
            serial_number = ' '.join('%02X' % c for c in akid['authority_cert_serial_number'].contents)
            r.add_content("Serial:")
            r.add_content("{}{}".format(lint_cert_indent, serial_number))

        # process options
        _do_presence_test(r, config_options, 'key_id', 'Key ID', akid_has_keyid)
        _do_presence_test(r, config_options, 'name_and_serial', 'Name and serial number',
                          akid_has_issuer and akid_has_serial)

        if akid_has_issuer != akid_has_serial:
            r.add_error("Issuer and serial number must appear as a tuple")

    return r


def lint_skid(config_options, cert):
    r = OutputRow("Subject Key Identifier")

    extension = _process_common_extension_options(config_options, cert, r)

    if extension is not None:

        skid = extension['extn_value'].parsed.native

        r.add_content('Key ID: {}'.format(''.join('%02X' % c for c in skid)))

        require_method_one = '0'
        if 'require_method_one' in config_options and len(config_options['require_method_one'].value) > 0:
            require_method_one = config_options['require_method_one'].value

        if require_method_one == '1':
            calculated_hash = get_5280_method_1_key_id(cert)
            match = (skid == calculated_hash)
            if not match:
                err_string = "Was not generated using RFC5280 method 1 (SHA1 of subjectPublicKeyInfo)"
                r.add_error(err_string)
                err_string = "Expected hash value was:" + lint_cert_newline + ''.join('%02X' % c for c in calculated_hash)
                r.add_error(err_string)

        if r.extension_is_critical:
            r.add_error('Conforming CAs MUST mark this extension as non-critical (RFC5280)', lint_warning_prefix)

    return r


def lint_policy_constraints(config_options, cert):
    r = OutputRow("Policy Constraints")

    extension = _process_common_extension_options(config_options, cert, r)

    if extension is not None:

        policy_constraints_native = extension['extn_value'].parsed.native

        if policy_constraints_native['require_explicit_policy'] is not None:
            r.add_content("Require Explicit Policy; skipCerts = {}".format(
                policy_constraints_native['require_explicit_policy']))

        if policy_constraints_native['inhibit_policy_mapping'] is not None:
            r.add_content("Inhibit Policy Mapping; skipCerts = {}".format(
                policy_constraints_native['inhibit_policy_mapping']))

        _do_presence_test(r, config_options, 'require_explicit_policy_present',
                          'Require explicit policy', policy_constraints_native['require_explicit_policy'] is not None)

        _do_presence_test(r, config_options, 'inhibit_policy_mapping_present',
                          'Inhibit policy mapping', policy_constraints_native['inhibit_policy_mapping'] is not None)

        if policy_constraints_native['require_explicit_policy'] is not None:

            if 'require_explicit_policy_max' in config_options and len(
                    config_options['require_explicit_policy_max'].value) > 0:
                require_explicit_policy_max = int(config_options['require_explicit_policy_max'].value)

                if policy_constraints_native['require_explicit_policy'] > require_explicit_policy_max:
                    r.add_error("Require explicit skip cert value exceeds permitted maximum of {}"
                                .format(require_explicit_policy_max))

        if policy_constraints_native['inhibit_policy_mapping'] is not None:

            if 'inhibit_policy_mapping_max' in config_options and len(
                    config_options['inhibit_policy_mapping_max'].value) > 0:
                inhibit_policy_mapping_max = int(config_options['inhibit_policy_mapping_max'].value)

                if policy_constraints_native['inhibit_policy_mapping'] > inhibit_policy_mapping_max:
                    r.add_error("Inhibit mapping skip cert value exceeds permitted maximum of {}"
                                .format(inhibit_policy_mapping_max))

    return r


def lint_basic_constraints(config_options, cert):
    r = OutputRow("Basic Constraints")

    extension = _process_common_extension_options(config_options, cert, r)

    if extension is not None:

        bc = extension['extn_value'].parsed

        r.add_content("CA = {}".format(bc.native['ca']))

        _do_presence_test(r, config_options, 'ca_true',
                          'CA flag', bc.native['ca'] is True)

        if bc.native['path_len_constraint'] is not None:
            r.add_content("Path Length Constraint = {}".format(bc.native['path_len_constraint']))

            path_length_constraint_max = 99
            if 'path_length_constraint_max' in config_options and len(
                    config_options['path_length_constraint_max'].value) > 0:
                path_length_constraint_max = int(config_options['path_length_constraint_max'].value)

            if bc.native['path_len_constraint'] > path_length_constraint_max:
                r.add_error("Maximum allowed path length is {}".format(path_length_constraint_max))

        if bc.native['ca'] is False and len(bc.contents) > 0:
            r.add_error("Basic Constraints default value (cA=FALSE) was encoded: {}".format(
                ''.join('%02X' % c for c in bc.contents)))

        _do_presence_test(r, config_options, 'path_length_constraint_req', 'Path Length Constraint',
                          bc.native['path_len_constraint'] is not None)

    return r


printable_string_char_set = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
    'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
    's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '\'', '(', ')', '+',
    '-', '.', '/', ':', '=', '?', ' ', ','
}

teletex_bad_character_set = {35, 36, 92, 94, 96, 123, 125, 126, 169, 170, 172, 173, 174, 175, 185, 186, 192, 201,
                             208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 229, 255}

# https://www.itu.int/ITU-T/studygroups/com17/languages/X.691-0207.pdf
# (For IA5String the range is 0 to 127, for VisibleString it is
# 32 to 126, for NumericString it is 32 to 57, and for PrintableString it is 32 to 122. For IA5String and
# VisibleString all values in the range are present, but for NumericString and PrintableString not all values in
# the range are in use.)

def find_illegal_characters(asn_string, string_type=None):

    if not asn_string or not isinstance(asn_string, AbstractString):
        print('not a string?')
        return None

    illegal_characters = []
    if not string_type:
        string_type = get_abstract_string_type(asn_string)

    if string_type == 'Printable':
        for c in asn_string.native:
            if c not in printable_string_char_set:
                illegal_characters.append(c)
    elif string_type == 'IA5':
        for c in asn_string.contents:
            if not 0x00 <= c <= 0x7f:
                illegal_characters.append(chr(c))
    elif string_type == 'Visible':
        # for c in asn_string.native:
        #     if not 0x20 <= ord(c) <= 0x7f:
        #         illegal_characters.append(c)
        for c in asn_string.contents:
            if not 0x20 <= c <= 0x7f:
                illegal_characters.append(chr(c))
    elif string_type == 'UTF8':
        pass
        # do illegal characters always generate exceptions?
        # print('utf8 string')
    elif string_type == 'Teletex':
        # https://www.itu.int/rec/T-REC-T.61-198811-S/en
        # Code page 1036, CP1036, or IBM 01036
        for c in asn_string.contents:
            # for c in asn_string.contents:
            #     if not teletex_character_table[(c & 0xF0) >> 4][c & 0x0F]:
            #         illegal_characters.append(chr(c))
            if c in teletex_bad_character_set:
                illegal_characters.append(chr(c))

    return illegal_characters


#  "Non IA5 character {} found in CPSuri ::= IA5String".format('0x%02X' % ord(c)))
def lint_asn_string(asn_string, string_description, r, string_type=None):

    bad_chars = find_illegal_characters(asn_string, string_type)

    if bad_chars:
        error_string = "Illegal {} character".format(asn_string.__class__.__name__)
        if len(bad_chars) > 1:
            error_string += 's'
        error_string += ' ('
        for i, c in enumerate(bad_chars):
            if i:
                error_string += ' '
            if 0x20 <= ord(c) <= 0x7f:
                error_string += c
            else:
                error_string += '0x%02X' % ord(c)

        error_string += ') found in {}'.format(string_description)
        r.add_error(error_string)
        print(error_string)


def lint_dn_strings(name, r):
    if not isinstance(name, x509.Name):
        raise TypeError("name must be an x509.Name")

    # todo dc must be ia5
    rdn_seq = name.chosen  # type = RDNSequence
    if len(rdn_seq):
        for rdn in rdn_seq:
            for name2 in rdn:
                string_type, value = split_name_type_and_value(name2)
                if isinstance(value, AbstractString):
                    lint_asn_string(value, get_pretty_dn_name_component(name2['type']), r, string_type)
                else:
                    pass  # what to do with this..

    return


def lint_policies(config_options, cert):
    r = OutputRow("Certificate Policies")

    extension = _process_common_extension_options(config_options, cert, r)

    if extension is None:
        return r

    certificate_policies = extension['extn_value'].parsed

    required_policy_list = None
    match_mode = 'any'  # one | any | all
    permit_others = 0  # 0=no, 1=yes
    found_policies = []

    if 'required_policy_list' in config_options and len(config_options['required_policy_list'].value) > 0:
        required_policy_list = config_options['required_policy_list'].value.split()
        if len(required_policy_list) == 0:  # maybe not possible
            required_policy_list = None

    if 'match_mode' in config_options and len(config_options['match_mode'].value) > 0:
        match_mode = config_options['match_mode'].value

    if 'permit_others' in config_options and len(config_options['permit_others'].value) > 0:
        permit_others = int(config_options['permit_others'].value)

    policy_count = 0
    for policy in certificate_policies:

        policy_count += 1
        policy_display_string = "[{}]{}{}".format(policy_count, lint_cert_indent,
                                                  policy['policy_identifier'].dotted)
        r.add_content(policy_display_string)

        if policy['policy_identifier'].dotted in policies_display_map:
            policy_display_string = "{}{}({})".format(lint_cert_indent, lint_cert_indent,
                                                      policies_display_map[policy['policy_identifier'].dotted])
            r.add_content(policy_display_string)

        # Qualifier ::= CHOICE {
        #      cPSuri           CPSuri,
        #      userNotice       UserNotice }
        #
        # CPSuri ::= IA5String
        #
        # UserNotice ::= SEQUENCE {
        #      noticeRef        NoticeReference OPTIONAL,
        #      explicitText     DisplayText OPTIONAL }

        if policy.native['policy_qualifiers'] is not None:

            # check qualifiers for invalid characters
            policy_qualifiers = policy['policy_qualifiers']
            for qual in policy_qualifiers:
                # {'1.3.6.1.5.5.7.2.1': 'certification_practice_statement', '1.3.6.1.5.5.7.2.2': 'user_notice'}
                qualifier_description = qualifiers_display_map.get(qual['policy_qualifier_id'].native,
                                                                   'Policy Qualifier Text')

                if qual['policy_qualifier_id'].native == 'certification_practice_statement':
                    lint_asn_string(qual['qualifier'], qualifier_description, r)

                elif qual['policy_qualifier_id'].native == 'user_notice':
                    # class NoticeReference(Sequence):
                    #     _fields = [
                    #         ('organization', DisplayText),
                    #         ('notice_numbers', NoticeNumbers),
                    #     ]
                    #
                    # class UserNotice(Sequence):
                    #     _fields = [
                    #         ('notice_ref', NoticeReference, {'optional': True}),
                    #         ('explicit_text', DisplayText, {'optional': True}),
                    #     ]
                    lint_asn_string(qual['qualifier']['explicit_text'].chosen, qualifier_description, r)

            for qualifier in policy.native['policy_qualifiers']:

                qualifier_type = qualifiers_display_map.get(qualifier['policy_qualifier_id'],
                                                            qualifier['policy_qualifier_id'])

                qualifier_string = "{}{}".format(lint_cert_indent, qualifier_type)

                if qualifier['policy_qualifier_id'] == 'certification_practice_statement':
                    if qualifier['qualifier'] is not None:
                        qualifier_string += ": " + qualifier['qualifier']

                elif qualifier['policy_qualifier_id'] == 'user_notice':
                    if qualifier['qualifier'] is not None:

                        if qualifier['qualifier']['notice_ref'] is not None:
                            qualifier_string += " " + qualifiers_display_map.get('notice_ref', "Ref") \
                                                + ": " + qualifier['qualifier']['notice_ref']
                            if qualifier['qualifier']['explicit_text'] is not None:
                                qualifier_string += lint_cert_indent + lint_cert_indent

                        if qualifier['qualifier']['explicit_text'] is not None:
                            qualifier_string += " " + qualifiers_display_map.get('explicit_text', "Text") \
                                                + ": " + qualifier['qualifier']['explicit_text']

                elif qualifier['qualifier'] is not None and isinstance(qualifier['qualifier'], str):
                    qualifier_string += ": " + qualifier['qualifier']

                r.add_content(qualifier_string)

        if required_policy_list is not None and permit_others == 0 and\
                policy['policy_identifier'].dotted not in required_policy_list:
            r.add_error("{} is not permitted".format(policy['policy_identifier'].dotted))

        if policy['policy_identifier'].dotted in found_policies:
            r.add_error("{} was repeated".format(policy['policy_identifier'].dotted))
        else:
            found_policies.append(policy['policy_identifier'].dotted)

    if required_policy_list is not None:
        policy_intersection_count = len(set(required_policy_list).intersection(found_policies))

        if match_mode == 'any' and policy_intersection_count == 0:
            r.add_error("This profile requires inclusion of one or more of"
                        " the following policies but none were included:\n")
            r.add_error(lint_cert_newline.join(required_policy_list), '')
        elif match_mode == 'one':
            if policy_intersection_count == 0:
                r.add_error("This profile requires inclusion of one of the following policies:\n")
                r.add_error(lint_cert_newline.join(required_policy_list), '')
            elif policy_intersection_count > 1:
                r.add_error("Too many matches. This profile requires inclusion of only one of the below policies "
                            "but {} matches were found:\n".format(policy_intersection_count))
                r.add_error(lint_cert_newline.join(required_policy_list), '')
        elif match_mode == 'all' and policy_intersection_count != len(required_policy_list):
            all_match_str = "This profile requires the inclusion of {} policies of which {} were included:\n"
            r.add_error(all_match_str.format(len(required_policy_list), policy_intersection_count))
            r.add_error(lint_cert_newline.join(required_policy_list), '')

    return r


def _lint_do_alt_name(r, config_options, alt_name_value):
    if alt_name_value is None:
        return

    # todo dnsname must be ia5
    # todo dnsname validation (i.e. not a url, valid dns name)
    # todo Common CP - The hostname of every URI must be specified as a fully qualified domain name.

    types_found = []

    for general_name in alt_name_value:
        r.add_content(get_general_name_string(general_name, True))
        name_type = get_general_name_type(general_name)
        types_found.append(name_type)

        if general_name.name == 'other_name' and 'other_name' not in types_found:
            types_found.append('other_name')
        elif name_type != 'uniform_resource_identifier_chuid' and \
                general_name.name == 'uniform_resource_identifier' and \
                'uniform_resource_identifier' not in types_found:
            # get_general_name_type tags uniform_resource_identifier with http/ldap on the end,
            # this is needed for the presence test below
            types_found.append('uniform_resource_identifier')

        if general_name.name == 'directory_name':
            lint_dn_strings(general_name.chosen, r)
        elif isinstance(general_name.chosen, AbstractString):
            lint_asn_string(general_name.chosen, general_name_display_map.get(name_type, 'Alternate Name'), r)
        # else:
        #     print(general_name.chosen.__class__.__name__)

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

    if len(cert.subject) == 0:

        option_is_critical = 0

        if 'is_critical' in config_options and len(config_options['is_critical'].value) > 0:
            option_is_critical = int(config_options['is_critical'].value)

        if option_is_critical != 2:
            # if subject dn is absent; san must be critical per 5280
            r.add_error('When Subject DN is absent, Subject Alternate Name is required to be critical',
                        lint_info_prefix)
            config_options['is_critical'].value = '2'

    extension = _process_common_extension_options(config_options, cert, r)

    san = None
    if extension is not None:
        san = extension['extn_value'].parsed

    _lint_do_alt_name(r, config_options, san)

    return r


def lint_ian(config_options, cert):
    r = OutputRow("Issuer Alternate Name")

    extension = _process_common_extension_options(config_options, cert, r)

    ian = None
    if extension is not None:
        ian = extension['extn_value'].parsed

    _lint_do_alt_name(r, config_options, ian)

    return r


def lint_eku(config_options, cert):
    r = OutputRow("Extended Key Usage")

    extension = _process_common_extension_options(config_options, cert, r)

    if extension is not None:

        eku = extension['extn_value'].parsed

        eku_oids = []
        for eku_oid in eku:
            eku_oids.append(eku_oid.dotted)
            r.add_content(
                "{} ({})".format(eku_display_map.get(eku_oid.dotted, "Unknown EKU"), eku_oid.dotted))

        any_eku_present_and_allowed = False
        if 'oid_any_eku' in config_options:
            any_eku_present_and_allowed = ('2.5.29.37.0' in eku_oids) and (config_options['oid_any_eku'].value != '1')


        for ce in config_options:
            if "oid_" in ce:
                eku_display_string = "{} ({})".format(eku_display_map.get(config_options[ce].oid, "Unknown EKU"),
                                                      config_options[ce].oid)

                # if any eku is present and permitted, change required (2) values to optional (0)
                if any_eku_present_and_allowed and config_options[ce].value == '2':
                    config_options[ce].value = '0'

                _do_presence_test(r, config_options, ce,
                                  eku_display_string,
                                  config_options[ce].oid in eku_oids)

        if r.extension_is_critical and '2.5.29.37.0' in eku_oids:
            r.add_error('EKU should not be critical if anyExtendedKeyUsage is present (RFC5280)', lint_warning_prefix)

        if '1.3.6.1.5.5.7.3.1' in eku_oids:
            # todo if server auth in eku look for san and then dnsname in san
            pass

        # todo confirm cert sign, crl sign, ke and de *absent* when ocsp_no_check_value is present

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


def lint_crldp(config_options, cert):
    r = OutputRow("CRL Distribution Points")

    extension = _process_common_extension_options(config_options, cert, r)

    if extension is not None:

        crldp = extension['extn_value'].parsed

        dp_num = 0
        first_http = 0
        first_ldap = 0
        first_directory_name = 0
        indent_str = lint_cert_indent + lint_cert_indent

        for dp in crldp:

            dp_num += 1
            r.add_content("[{}] Distribution Point".format(dp_num))

            if not dp['distribution_point'] and not dp['crl_issuer']:
                r.add_error("Either distributionPoint or cRLIssuer must be present in [{}]".format(dp_num))

            if dp['distribution_point']:

                dpname = dp['distribution_point']

                r.add_content(lint_cert_indent + crldp_display_map[dpname.name])

                if dpname.name != 'full_name':
                    # todo find a sample cert with nameRelativeToCRLIssuer, should be able to pass to pretty dn function
                    r.add_content("{}{}".format(lint_cert_indent, der2asn(dpname.chosen.contents)))
                    print('Found a nameRelativeToCRLIssuer <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<')

                else:
                    for general_name in dpname.chosen:
                        # todo: Common Certificate Policy - attributes of type DirectoryString in the ... distributionPoint fields of cRLDistributionPoints ... shall be encoded in PrintableString.
                        # todo  Common Certificate Policy - The information must be made available via the default port number for the relevant protocol (80 for HTTP and 389 for LDAP) and so does not need to be specified in the URI.
                        # todo Common Certificate Policy - The hostname of every URI must be specified as a fully qualified domain name.
                        # todo Check CRL HTTP URLs for 200 OK and mime type, file size, and parsing

                        general_name_string = get_general_name_string(general_name, True)

                        if general_name.name == 'uniform_resource_identifier':

                            if general_name.native[0:7] == 'http://' and first_http == 0:
                                first_http = dp_num
                            if general_name.native[0:7] == 'ldap://' and first_ldap == 0:
                                first_ldap = dp_num

                        elif general_name.name == 'directory_name':
                            if first_directory_name == 0:
                                first_directory_name = dp_num

                            general_name_string = general_name_string.replace(lint_cert_newline,
                                                                              lint_cert_newline + indent_str)

                        r.add_content("{}{}".format(indent_str, general_name_string))

            _do_presence_test(r, config_options, 'crl_reasons', 'CRL Reason Code', dp['reasons'] != x509.VOID)

            if dp['reasons']:
                r.add_content(lint_cert_indent + "Reason Flag(s):")
                for bit in reason_flags_display_map.keys():
                    if dp['reasons'][bit]:
                        r.add_content(indent_str + reason_flags_display_map[bit])

                r.add_error("RFC5280 recommends against segmenting CRLs by reason code. "
                            "This may lead to unintended certificate trust by clients that ignore these flags.",
                            lint_warning_prefix)

            if dp['crl_issuer'] and isinstance(dp['crl_issuer'], x509.GeneralNames):

                r.add_content(lint_cert_indent + "CRL Issuer:")
                for general_name in dp['crl_issuer']:

                    general_name_string = indent_str + get_general_name_string(general_name, True)
                    general_name_string = general_name_string.replace(lint_cert_newline,
                                                                      lint_cert_newline + indent_str)
                    r.add_content(general_name_string)

                    #todo add option for crl issuer / _do_presence_test; common profiles 'The reasons and cRLIssuer fields must be omitted.'

        if first_http > 0 and first_ldap > 0:

            if 'http_before_ldap' in config_options and len(config_options['http_before_ldap'].value) > 0:

                http_before_ldap = int(config_options['http_before_ldap'].value)

                if http_before_ldap == 1 and first_http < first_ldap:
                    # require ldap first but http came first
                    r.add_error("LDAP URI must appear before the HTTP URI")
                elif http_before_ldap == 2 and first_ldap < first_http:
                    # require http first but ldap came first
                    r.add_error("HTTP URI must appear before the LDAP URI")

        _do_presence_test(r, config_options, 'http', 'HTTP', first_http > 0)
        _do_presence_test(r, config_options, 'ldap', 'LDAP', first_ldap > 0)
        _do_presence_test(r, config_options, 'directory_name', 'Directory Address', first_directory_name > 0)

    return r


def lint_aia(config_options, cert):
    r = OutputRow("Authority Information Access")

    extension = _process_common_extension_options(config_options, cert, r)

    if extension is not None:

        aia = extension['extn_value'].parsed

        dp_num = 0
        first_http = 0
        first_ldap = 0
        first_directory_name = 0
        ocsp_found = False
        ca_issuers_found = False
        ocsp_https = False
        aia_https = False
        aia_ldaps = False
        aia_with_p7c = 0

        for access_description in aia:
            access_method = access_description['access_method']  # AccessMethod
            access_location = access_description['access_location']  # GeneralName
            dp_num += 1

            method_display_string = access_method_display_map.get(access_method.native, "Unknown Access Method")
            r.add_content("[{}] {}:".format(dp_num, method_display_string))

            if access_method.native == 'ocsp':
                ocsp_found = True
            elif access_method.native == 'ca_issuers':
                ca_issuers_found = True

            general_name_string = get_general_name_string(access_location, True)
            indent_str = "{}{}".format(lint_cert_newline, lint_cert_indent)

            if access_location.name == 'uniform_resource_identifier':

                if access_method.native == 'ca_issuers':
                    # if access_location.native[0:4] == 'http':
                    if access_location.native.startswith('http'):
                        # todo Check AIA HTTP URLs for 200 OK and mime type, file size, and parsing
                        # todo Confirm valid issuer cert for this cert is present in AIA
                        if first_http == 0:
                            first_http = dp_num
                        if access_location.native.endswith('.p7c'):
                            aia_with_p7c += 1
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

                general_name_string = general_name_string.replace(lint_cert_newline, indent_str)
                # general_name_string = indent_str + general_name_string

            r.add_content("{}{}".format(lint_cert_indent, general_name_string))

        # linting
        if first_http > 0 and first_ldap > 0:

            if 'ca_issuers_http_before_ldap' in config_options and \
                            len(config_options['ca_issuers_http_before_ldap'].value) > 0:

                http_before_ldap = int(config_options['ca_issuers_http_before_ldap'].value)

                if http_before_ldap == 1 and first_http < first_ldap:
                    # require ldap first but http came first
                    r.add_error("LDAP URI must appear before the HTTP URI")
                elif http_before_ldap == 2 and first_ldap < first_http:
                    # require http first but ldap came first
                    r.add_error("HTTP URI must appear before the LDAP URI")

        _do_presence_test(r, config_options, 'ca_issuers_present', 'CA Issuer access method', ca_issuers_found)

        if ca_issuers_found is True:
            _do_presence_test(r, config_options, 'ca_issuers_http', 'HTTP caIssuers', first_http > 0)
            _do_presence_test(r, config_options, 'ca_issuers_ldap', 'LDAP caIssuers', first_ldap > 0)

            _do_presence_test(r, config_options, 'ca_issuers_https', 'HTTPS caIssuers (TLS)', aia_https)
            _do_presence_test(r, config_options, 'ca_issuers_ldaps', 'LDAPS caIssuers (TLS)', aia_ldaps)

            _do_presence_test(r, config_options, 'ca_issuers_directory_name', 'Directory Address AIA',
                              first_directory_name > 0)
            _do_presence_test(r, config_options, 'ca_issuers_http_p7c', 'caIssuers ending with .p7c', aia_with_p7c != 0)

        _do_presence_test(r, config_options, 'ocsp_present', 'OCSP', ocsp_found)

        if ocsp_found is True:
            _do_presence_test(r, config_options, 'ocsp_https', 'OCSP over HTTPS (TLS)', ocsp_https)

    return r


def lint_sia(config_options, cert):
    r = OutputRow("Subject Information Access")

    extension = _process_common_extension_options(config_options, cert, r)
    ca_repository_found = False

    if extension is not None:

        sia = extension['extn_value'].parsed

        access_method_number = 0
        first_http = 0
        first_ldap = 0
        first_directory_name = 0
        time_stamping_found = False
        sia_https = False
        sia_ldaps = False

        sia_not_p7c = 0

        for access_description in sia:
            access_method = access_description['access_method']  # AccessMethod
            access_location = access_description['access_location']  # GeneralName
            access_method_number += 1

            method_display_string = access_method_display_map.get(access_method.native, "Unknown Access Method")
            r.add_content("[{}] {}:".format(access_method_number, method_display_string))

            if access_method.native == 'ca_repository':
                ca_repository_found = True
            elif access_method.native == 'time_stamping':
                time_stamping_found = True

            general_name_string = get_general_name_string(access_location, True)
            indent_str = "{}{}".format(lint_cert_newline, lint_cert_indent)

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

                general_name_string = general_name_string.replace(lint_cert_newline, indent_str)
                # general_name_string = indent_str + general_name_string

            r.add_content("{}{}".format(lint_cert_indent, general_name_string))

        # linting
        if first_http > 0 and first_ldap > 0:

            if 'ca_repository_http_before_ldap' in config_options and \
                            len(config_options['ca_repository_http_before_ldap'].value) > 0:

                http_before_ldap = int(config_options['ca_repository_http_before_ldap'].value)

                if http_before_ldap == 1 and first_http < first_ldap:
                    # require ldap first but http came first
                    r.add_error("LDAP URI must appear before the HTTP URI")
                elif http_before_ldap == 2 and first_ldap < first_http:
                    # require http first but ldap came first
                    r.add_error("HTTP URI must appear before the LDAP URI")

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

    # config_options['ca_repository_required_if_not_path_len_zero'] = ConfigEntry()
    # config_options['ca_repository_required_if_not_path_len_zero'].value = '1'
    # config_options['ca_repository_required_if_not_path_len_zero'].oid = ''

    if not ca_repository_found and 'ca_repository_required_if_not_path_len_zero' in config_options and \
                len(config_options['ca_repository_required_if_not_path_len_zero'].value) > 0:

        ca_repository_required = int(config_options['ca_repository_required_if_not_path_len_zero'].value)

        if not ca_repository_required:
            return r

        # ca_repository_required_if_not_path_len_zero was set
        if isinstance(cert, x509.Certificate):
            cert = cert['tbs_certificate']

        # no need to check if ca, can assume the profile is for ca certs / this is a ca cert
        # extension, crit = get_extension_and_criticality(cert, '2.5.29.15')  # 'Key Usage',

        msg = None
        extension, crit = get_extension_and_criticality(cert, '2.5.29.19')  # basic constraints
        if extension:
            bc = extension['extn_value'].parsed
            if bc.native['path_len_constraint'] is None:
                msg = 'absent'
            elif bc.native['path_len_constraint'] != 0:
                msg = '{}'.format(bc.native['path_len_constraint'])
        else:
            msg = 'absent'

        if msg:
            msg = 'CA Repository URI is required when path length constraint is ' + msg
            r.add_error(msg)

    return r

# id-ce-privateKeyUsagePeriod OBJECT IDENTIFIER ::=  { id-ce 16 }
#
# PrivateKeyUsagePeriod ::= SEQUENCE {
#      notBefore       [0]     GeneralizedTime OPTIONAL,
#      notAfter        [1]     GeneralizedTime OPTIONAL }
#      -- either notBefore or notAfter MUST be present
#
# class PrivateKeyUsagePeriod(Sequence):
#     _fields = [
#         ('not_before', GeneralizedTime, {'implicit': 0, 'optional': True}),
#         ('not_after', GeneralizedTime, {'implicit': 1, 'optional': True}),
#     ]

def lint_pkup(config_options, cert):
    r = OutputRow("Private Key Usage Period")
    # '2.5.29.16'
    extension = _process_common_extension_options(config_options, cert, r)

    if extension is not None:
        pkup = extension['extn_value'].parsed

        # class Time(Choice):
        #     _alternatives = [
        #         ('utc_time', UTCTime),
        #         ('general_time', GeneralizedTime),
        #     ]

        if pkup['not_before'] is not None:
            not_before = x509.Time({'general_time': pkup['not_before']})
            r.add_content(lint_and_format_x509_time(not_before, "Not Before", r))
        if pkup['not_after'] is not None:
            not_after = x509.Time({'general_time': pkup['not_after']})
            r.add_content(lint_and_format_x509_time(not_after, "Not After", r))

    return r


def lint_sub_dir_attr(config_options, cert):
    r = OutputRow("Subject Directory Attributes")  # '2.5.29.9'

    extension = _process_common_extension_options(config_options, cert, r)

    if extension is not None:
        r.add_content(der2asn(extension['extn_value'].contents))

    return r


def lint_ocsp_nocheck(config_options, cert):
    r = OutputRow("OCSP No Check")

    extension = _process_common_extension_options(config_options, cert, r)

    if extension is not None:
        ocsp_no_check = extension['extn_value'].parsed

        # The value of the extension SHALL be NULL.
        if not len(ocsp_no_check.contents):
            r.add_content("NULL")
        else:
            r.add_content(get_der_display_string(ocsp_no_check.contents))
            r.add_error("Extension content is not NULL")

    return r


def lint_inhibit_any(config_options, cert):
    r = OutputRow("Inhibit Any Policy")

    extension = _process_common_extension_options(config_options, cert, r)

    if extension is not None:
        inhibit_any_policy = extension['extn_value'].parsed

        r.add_content("SkipCerts = {}".format(inhibit_any_policy.native))

        if 'inhibit_any_max' in config_options and len(
                config_options['inhibit_any_max'].value) > 0:

            inhibit_any_max = int(config_options['inhibit_any_max'].value)

            if inhibit_any_policy.native > inhibit_any_max:
                r.add_error("Skip cert value exceeds permitted maximum of {}"
                            .format(inhibit_any_max))

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

    r.add_content("{} ({})".format(sig_alg.native.replace('_', '-'), sig_alg.dotted))

    if sig_alg != tbs_alg:
        r.add_error("Signature algorithm ({}) does not match TBSCertificate::signature ({})".format(
            sig_alg.dotted, tbs_alg.dotted))

    found = False

    # iterate over all alg entries
    for ce in config_options:
        if "alg_" in ce:
            found = config_options[ce].oid == sig_alg.dotted
            if found:
                if config_options[ce].value == '1':
                    r.add_error("Signature algorithm not permitted")
                break

    if not found:
        r.add_error("Signature algorithm not included in option set", lint_warning_prefix)

    return r


# ('issuer_unique_id', OctetBitString, {'implicit': 1, 'optional': True}),
# ('subject_unique_id', OctetBitString, {'implicit': 2, 'optional': True}),

def lint_version(config_options, cert):
    cert_version = int(cert['tbs_certificate']['version'])

    r = OutputRow("Version", "v%i" % (cert_version + 1))

    if cert_version == 0:

        if cert['tbs_certificate']['issuer_unique_id'] or cert['tbs_certificate']['subject_unique_id']:
            r.add_error('UniqueIdentifier(s) must not be present in a v1 certificate')

    if not cert['tbs_certificate']['extensions']:
        # no extensions
        if cert_version == 2:
            r.add_error('Certificates without extensions should be v2', lint_warning_prefix)
    else:
        # has extensions
        if cert_version != 2:
            r.add_error('Extensions must not appear in {} certificates'.format(cert['tbs_certificate']['version'].native))

    if 'min_version' in config_options and len(config_options['min_version'].value) > 0:
        min_version_num = int(config_options['min_version'].value)

        if cert_version < min_version_num:
            r.add_error("Minimum permitted version is v{}".format(str(min_version_num + 1)))

    return r


def lint_serial_number(config_options, cert):
    r = OutputRow("Serial Number")

    serial_number = cert['tbs_certificate']['serial_number']
    serial_bytes = serial_number.contents

    r.add_content('{}{}({} octets)'.format(' '.join('%02X' % c for c in serial_bytes),
                                           lint_cert_newline,
                                           len(serial_bytes)))

    min_length = 0
    max_length = 0

    if 'min_length' in config_options and len(config_options['min_length'].value) > 0:
        min_length = int(config_options['min_length'].value)

    if 'max_length' in config_options and len(config_options['max_length'].value) > 0:
        max_length = int(config_options['max_length'].value)

    if min_length and len(serial_bytes) < min_length:
        r.add_error("Minimum permitted length is {} octets".format(str(min_length)))

    if max_length and len(serial_bytes) > max_length:
        r.add_error("Maximum permitted length is {} octets".format(str(max_length)))

    if len(serial_bytes) > 1 and serial_bytes[0] == 0 and serial_bytes[1] & 0x80 != 0x80:
        r.add_error("Invalid encoding. INTEGER must be encoded with the minimum number of octets")

    if serial_number.native == 0:
        r.add_error('Serial number may not be zero (RFC5280)')
    elif serial_number.native < 0:
        r.add_error('Serial number may not be negative (RFC5280)')

    return r

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

    r.add_content(
        '{}-{} ({})'.format(public_key_algorithm_display_map.get(public_key_alg, "Unknown"),
                            public_key_info.bit_size,
                            public_key_alg))
    r.add_content("")
    pub_key_bytes = public_key_info['public_key'].contents
    # strip leading 00 so it matches microsoft cert viewer
    if pub_key_bytes[0] == 0:
        pub_key_bytes = pub_key_bytes[1:]
    # 43 chars to match ms cert viewer
    pub_key_text = lint_cert_newline.join(textwrap.wrap(' '.join('%02X' % c for c in pub_key_bytes), 43))
    r.add_content(pub_key_text)

    if public_key_info.algorithm == 'rsa':
        # asn1crypto._errors.APIException: asn1crypto.keys.PublicKeyInfo().unwrap() has been removed,
        # please use oscrypto.asymmetric.PublicKey().unwrap() instead
        # pub_key = public_key_info.unwrap()
        pub_key = public_key_info['public_key'].parsed
        modulus = pub_key.native['modulus']
        if modulus < 0:
            r.add_error("RSA modulus is negative")

        # todo warning or error for small rsa exponent
        public_exponent = pub_key.native['public_exponent']
        if public_exponent < 0:
            r.add_error("RSA public exponent is negative")

    elif public_key_info.algorithm == 'ec':
        pass

    if 'parameters' in public_key_info['algorithm'] and public_key_info['algorithm']['parameters'] is not None:
        if len(public_key_info['algorithm']['parameters'].contents) > 0:
            if public_key_info.algorithm == 'ec' and public_key_info['algorithm']['parameters'].name == 'named':
                r.add_content("{}Named Curve: {} ({})".format(lint_cert_newline,
                                                              public_key_info['algorithm']['parameters'].chosen.native,
                                                              public_key_info['algorithm']['parameters'].chosen.dotted))
            else:
                # todo add better display support for rsa pss, ec specified curve
                r.add_content("{}Parameters:{}".format(lint_cert_newline, lint_cert_newline))
                r.add_content(der2asn(public_key_info['algorithm']['parameters'].contents))


    found = False

    # iterate over all alg entries
    for ce in config_options:
        if "alg_" in ce:
            found = config_options[ce].oid == public_key_alg
            if found:
                if config_options[ce].value == '1':
                    r.add_error("Algorithm not permitted")
                break

    if not found:
        r.add_error("Algorithm not included in option set", lint_warning_prefix)

    min_size = 0
    max_size = 0

    if public_key_info.algorithm == 'rsa':

        if 'rsa_min_size' in config_options and len(config_options['rsa_min_size'].value) > 0:
            min_size = int(config_options['rsa_min_size'].value)

        if 'rsa_max_size' in config_options and len(config_options['rsa_max_size'].value) > 0:
            max_size = int(config_options['rsa_max_size'].value)

    elif public_key_info.algorithm == 'ec':
        # todo alg_ec_named_curve

        if 'ec_min_size' in config_options and len(config_options['ec_min_size'].value) > 0:
            min_size = int(config_options['ec_min_size'].value)

        if 'ec_max_size' in config_options and len(config_options['ec_max_size'].value) > 0:
            max_size = int(config_options['ec_max_size'].value)

    if min_size > public_key_info.bit_size:
        r.add_error("Smaller than minimum key size ({} bits)".format(min_size))

    if max_size != 0 and max_size < public_key_info.bit_size:
        r.add_error("Larger than maximum key size ({} bits)".format(max_size))

    return r


def format_display_time_span(span):
    span_string = '{}'.format(span)
    if '.' in span_string:
        span_string = span_string[:span_string.rfind('.')]
    return span_string

# validity	validity_period_maximum
# validity	validity_period_generalized_time
def lint_validity(config_options, cert):
    r = OutputRow("Validity Period")
    validity_period_maximum = 0

    nb = cert['tbs_certificate']['validity']['not_before']
    na = cert['tbs_certificate']['validity']['not_after']

    r.add_content(lint_and_format_x509_time(nb, 'Not Before', r))
    r.add_content(lint_and_format_x509_time(na, 'Not After', r))

    lifespan = na.native - nb.native
    if na.native < nb.native:
        r.add_error("notAfter is before notBefore")
    elif na.native == nb.native:
        r.add_error("notBefore = notAfter")
    else:
        r.add_content("Validity period of {}".format(lifespan))

    is_valid_now = 0
    if 'is_valid_now' in config_options and len(config_options['is_valid_now'].value) > 0:
        is_valid_now = int(config_options['is_valid_now'].value)

    # todo Common - add config options to handle this: except self-signed certificates, that expire after 12/31/2030 shall be signed with keys of at least 3072 bits for RSA or at least 256 bits for ECDSA.

    now = datetime.now(na.native.tzinfo)

    if na.native < now:
        r.add_content('Certificate is expired')
        if is_valid_now == 2:
            r.add_error("Certificate is expired")
    else:
        if is_valid_now == 1:
            r.add_error("Certificate should be expired")

    if 'validity_period_maximum' in config_options and len(config_options['validity_period_maximum'].value) > 0:
        validity_period_maximum = int(config_options['validity_period_maximum'].value)

    if validity_period_maximum > 0:
        # lifespan must be less than validity_period_maximum
        # certificates should meet the spirit of the requirement. pad between 1 and 14 days.
        padded_validity_period_maximum = min(14, max(1, int(validity_period_maximum * .02))) + validity_period_maximum

        max_validity = timedelta(days=padded_validity_period_maximum)
        if lifespan > max_validity:
            r.add_error("Validity period exceeds {} days".format(str(validity_period_maximum)))

    _do_presence_test(r, config_options, 'validity_period_generalized_time',
                      'notBefore encoded as GeneralizedTime', nb.name == 'general_time')

    _do_presence_test(r, config_options, 'validity_period_generalized_time',
                      'notAfter encoded as GeneralizedTime', na.name == 'general_time')

    return r


_geo_or_dc_error = '{} must be a geo-political name (O=X, C=Y) or an Internet domain component (DC=X, DC=Y) name'

#         for c in asn_string.native:
#             if c not in printable_string_char_set:
#                 illegal_characters.append(c)

def check_permitted_string_types(rdn_seq, permitted_string_types, r, directory_string_only):
    bad_things_found = {}

    if not len(rdn_seq):
        return bad_things_found

    rdn_list = list()
    for rdn in rdn_seq:
        rdn_list.append(rdn)

    rdn_list.reverse()

    for rdn in rdn_list:
        for name in rdn:
            if get_name_type_and_value_string_type(name) not in permitted_string_types:
                if directory_string_only and not isinstance(name['value'], x509.DirectoryString):
                    continue
                string_type = get_name_type_and_value_string_type(name)
                rdn_type = get_pretty_dn_name_component(name['type'])
                if string_type in bad_things_found:
                    if rdn_type not in bad_things_found[string_type]:
                        bad_things_found[string_type] += ', ' + rdn_type
                else:
                    bad_things_found[string_type] = rdn_type

    for string_type, rdns in bad_things_found.items():
        if ',' in rdns:
            li = rdns.rsplit(', ', 1)
            rdns = ' and '.join(li)
        if ',' not in rdns:
            rdns = rdns.replace('and', 'nor')

        r.add_error('{} is not permitted in {}'.format(string_type, rdns))

    return bad_things_found


def lint_dn(config_options, dn, row_name):
    separator = ",{}".format(lint_cert_newline)
    # pretty_name = get_pretty_dn(dn, separator, " = ", True, True)
    pretty_name = get_pretty_dn(dn, separator, " = ", True, True)
    r = OutputRow(row_name, pretty_name)

    if 'present' in config_options and len(config_options['present'].value) > 0:
        present = int(config_options['present'].value)
        if present == 2 and len(dn) == 0:
            r.add_error('{} is required'.format(row_name))
        elif present == 1 and len(dn) > 0:
            r.add_error('{} is not permitted'.format(row_name))

    if 'require_geo_political_or_dc' in config_options and config_options['require_geo_political_or_dc'].value == '1':
        if len(dn) < 2:
            r.add_error(_geo_or_dc_error.format(row_name))
        else:
            rdn1 = dn.chosen[0][0].native['type']
            rdn2 = dn.chosen[1][0].native['type']
            # if rdn1 == 'country_name' and rdn2 == 'organization_name':
            if not ((rdn1 == 'country_name' and is_name_type_in_dn('2.5.4.10', dn))
                    or (rdn1 == 'domain_component' and rdn2 == 'domain_component')):
                r.add_error(_geo_or_dc_error.format(row_name))

    if 'permitted_string_types' in config_options and config_options['permitted_string_types'].value:
        permitted_string_types = config_options['permitted_string_types'].value.split(';')
        check_permitted_string_types(dn.chosen, permitted_string_types, r, directory_string_only=False)
    elif 'permitted_string_types_dir_string' in config_options and config_options['permitted_string_types_dir_string'].value:
        permitted_string_types = config_options['permitted_string_types_dir_string'].value.split(';')
        check_permitted_string_types(dn.chosen, permitted_string_types, r, directory_string_only=True)

    for ce in config_options:
        if 'rdn_' in ce and config_options[ce].value != '0':
            # print(ce + " " + config_options[ce].oid)
            found = is_name_type_in_dn(config_options[ce].oid, dn)
            if found is True and config_options[ce].value == '1':
                r.add_error('{} is not permitted'.format(ce[4:].replace('_', ' ').title()))
            elif found is False and config_options[ce].value == '2':
                r.add_error('{} is missing'.format(ce[4:].replace('_', ' ').title()))

        elif 'values_' in ce and len(config_options[ce].value):
            rdn_values = get_rdn_values_from_dn(config_options[ce].oid, dn)
            if len(rdn_values):
                # 2012-04 made this case insensitive because the Common CP does not explicitly state case sensitive
                # this change may allow a pass on DNs that will cause issues with name constraints
                # in any software that does not perform case-insensitive name comparisons with name constraints
                permitted_strings = config_options[ce].value.lower().split(';')
                for rdn_value in rdn_values:
                    if rdn_value.native['value'].lower() not in permitted_strings:
                        r.add_error('\'{} = {}\' is not permitted'.format(get_pretty_dn_name_component(rdn_value['type']), rdn_value.native['value']))

    lint_dn_strings(dn, r)

    return r


def lint_subject(config_options, cert):

    r = lint_dn(config_options, cert.subject, "Subject DN")

    if 'is_self_issued' in config_options and config_options['is_self_issued'].value != '0':
        if config_options['is_self_issued'].value == '1' and cert.subject == cert.issuer:
            r.add_error("Certificate issuer and subject names match. Certificate may not be self issued.")
        elif config_options['is_self_issued'].value == '2' and cert.subject != cert.issuer:
            r.add_error("Certificate issuer and subject names do not match.")

    if len(cert.subject) == 0:
        san, is_critical = get_extension_and_criticality(cert['tbs_certificate'], '2.5.29.17')
        # todo San must be critical when subject is missing
        if not san:
            r.add_content("Either Subject DN or SubjectAltName is required")

    # todo common policy: Add per-rdn options? The common name attribute type in the subject field of end entity certificates shall be encoded in PrintableString if it is possible to encode the certificate subject's name using that encoding.

    return r


def lint_issuer(config_options, cert):
    return lint_dn(config_options, cert.issuer, "Issuer DN")


_lint_processed_extensions = {
    "processed extension oids go here"
}

# returns a list of rows
def lint_other_extensions(config_options, cert):
    rows = OrderedDict()
    row_list = []

    extensions = cert['tbs_certificate']['extensions']

    if extensions is None:
        return rows

    others_non_critical = 0
    others_critical = 0

    for e in extensions:
        if e['extn_id'].dotted not in _lint_processed_extensions:
            # init_row_name = None, init_content = None, init_analysis = None, init_config_section = None):
            extension_name = map_extension_oid_to_display.get(e['extn_id'].dotted, "Unknown")
            if extension_name == 'Unknown':
                extension_name = "{} ({})".format(extension_name, e['extn_id'].dotted)

            r = OutputRow(extension_name, "", "", "other_extensions")
            r.extension_oid = e['extn_id'].dotted
            if r.extension_oid in rows:
                rows[r.extension_oid].add_error('Multiple instances of this extension found in the certificate.')
                rows[r.extension_oid].add_error('Only the first instance is shown.', lint_warning_prefix)

            if e['critical'].native is True:
                others_critical += 1
                r.add_content("Critical = TRUE")
                if 'other_critical_extensions_present' in config_options and \
                                config_options['other_critical_extensions_present'].value == '1':
                    r.add_error("Additional critical extensions are not permitted")
            else:
                others_non_critical += 1
                if 'other_non_critical_extensions_present' in config_options and \
                        config_options['other_non_critical_extensions_present'].value == '1':
                    r.add_error("Additional non-critical extensions are not permitted")

            if e.contents is not None:
                if e['extn_id'].dotted == '1.3.6.1.4.1.11129.2.4.2':
                    print('sct')

                der_string = None
                try:
                    der_string = der2asn(e['extn_value'].contents)
                except ValueError as value_exception:
                    print(value_exception)
                    r.add_content("Failed to parse extension value")
                    r.add_error(str(value_exception), "")
                    try:
                        der_string = der2asn(e.contents)
                    except ValueError as value_exception:
                        print(value_exception)
                        r.add_error(str(value_exception), "")

                if der_string:
                    r.add_content(der_string)

            row_list.append(r)

    # sort the other extensions list in place (by extension oid)
    if row_list and len(row_list) > 1:
        row_list.sort(key=lambda x: x.extension_oid)

    for r in row_list:
        rows[r.extension_oid] = r

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
    # other extensions are handled separately
    #    ('other_extensions', lint_other_extensions)
])


def check_cert_conformance(input_cert, json_profile):
    if not isinstance(input_cert, x509.Certificate):
        raise TypeError("input_cert must be an x509.Certificate")

    if not isinstance(json_profile, list):
        raise TypeError("json_profile must json list, e.g. from json.load()")

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

    output_rows = OrderedDict()  # {}
    profile_info_section = None
    other_extensions_section = None
    other_extensions_rows = None

    for config_section in cert_profile:
        # print(config_section)
        if config_section in conformance_check_functions:
            try:
                r = conformance_check_functions[config_section](cert_profile[config_section], input_cert)
            except ValueError as e:
                print(e)
                r = OutputRow(config_section, "Failed to parse content", str(e))
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

    if other_extensions_section:
        other_extensions_rows = lint_other_extensions(other_extensions_section, input_cert)

    # sort the rows in order they appear in conformance_check_functions
    for key in conformance_check_functions:
        if key in output_rows:
            output_rows.move_to_end(key)

    return output_rows, other_extensions_rows, profile_info_section


