from cert_helpers import *
import json
import datetime
import pytz
import ast
import textwrap
from collections import OrderedDict

_lint_cert_newline = '\n'
_lint_cert_indent = '\t'

_lint_processed_extensions = {
    "hello"
}

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


def _lint_cert_add_content_line(r, content_string):
    if len(r.content) > 0:
        r.content += _lint_cert_newline

    r.content += str(content_string)
    print(content_string)

    return


def _lint_cert_add_error_to_row(r, error_string, preface=None):
    if len(r.analysis) > 0:
        r.analysis += _lint_cert_newline

    if preface is None:
        preface = "**ERROR**"

    output_string = "{}: {}".format(preface, error_string)
    r.analysis += output_string
    print(output_string)

    return


class ConfigEntry:
    def __init__(self):
        self.value = ""
        self.oid = ""


def _do_presence_test(r, config_options, cfg_str, display_str, is_present):
    error_string = None

    if cfg_str in config_options and len(config_options[cfg_str].value) > 0:
        if config_options[cfg_str].value == '1' and is_present is True:
            error_string = "is not permitted"
        if config_options[cfg_str].value == '2' and is_present is False:
            error_string = "is missing"

    if error_string is not None:
        error_string = "{} {}".format(display_str, error_string)
        _lint_cert_add_error_to_row(r, error_string)
        print(error_string)

    return


def _get_extension_options(config_options):
    option_present = LINT_CERT_OPTIONAL
    option_is_critical = LINT_CERT_OPTIONAL

    if 'present' in config_options and len(config_options['present'].value) > 0:
        option_present = int(config_options['present'].value)

    if 'is_critical' in config_options and len(config_options['is_critical'].value) > 0:
        option_is_critical = int(config_options['is_critical'].value)

    return option_present, option_is_critical


def _process_common_extension_options(config_options, extension, extension_is_critical, r):

    option_present, option_is_critical = _get_extension_options(config_options)

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
            _lint_cert_add_content_line(r, "Critical = TRUE")

    return


def lint_name_constraints(config_options, cert):
    r = OutputRow("Name Constraints")
    print("\n--- " + r.row_name + " ---")

    _process_common_extension_options(config_options, cert.name_constraints_value,
                                      'name_constraints' in cert.critical_extensions,
                                      r)

    # todo permitted and excluded subtrees

    return r


def lint_other_extensions(config_options, cert):
    print("Other Extensions")

    rows = []

    extensions = cert['tbs_certificate']['extensions']

    if extensions is None:
        return rows

    others_non_critical = 0
    others_critical = 0

    for e in extensions:
        if e['extn_id'].dotted not in _lint_processed_extensions:
            # init_row_name = None, init_content = None, init_analysis = None, init_config_section = None):
            extension_name = e['extn_id'].dotted
            #todo soemthing more readable
            r = OutputRow(extension_name, "", "", "other_extensions")
            if e['critical'].native is True:
                others_critical += 1
                _lint_cert_add_content_line(r, "Critical = TRUE")
                if 'other_critical_extensions_present' in config_options and \
                                config_options['other_critical_extensions_present'].value is '1':
                    _lint_cert_add_error_to_row(r, "Additional critical extensions are not permitted")
            else:
                others_non_critical += 1
                if 'other_non_critical_extensions_present' in config_options and \
                                config_options['other_non_critical_extensions_present'].value is '1':
                    _lint_cert_add_error_to_row(r, "Additional non-critical extensions are not permitted")

            if e.contents is not None:
                der_string = 'DER:\n'
                der_string += textwrap.fill(' '.join('%02X' % c for c in e.contents), 43)
                der_string = der_string.replace('\n', _lint_cert_newline)
                _lint_cert_add_content_line(r, der_string)

            rows.append(r)

    # output_array = []
    # extensions = cert['tbs_certificate']['extensions']
    # cert_ext_oids = set()
    # for ext in extensions:
    #     cert_ext_oids.add(ext['extn_id'].dotted)
    # for ce in config_options:
    #     if ce == "other_non_critical_extensions_present":
    #         reason = "Other extensions not specifiled in profile is not allowed in certificate"
    #         output_array.append(
    #             {"Item": ce, "Result": cert_ext_oids <= prof_ext_oids, "Content": str(cert_ext_oids), "Reason": reason})

    # json_dump(output_array, config_options, cfg_sect, outJson)

    return rows


def lint_policy_mappings(config_options, cert):
    r = OutputRow("Policy Mappings")
    print("\n--- " + r.row_name + " ---")

    _process_common_extension_options(config_options, cert.policy_mappings_value,
                                      'policy_mappings' in cert.critical_extensions,
                                      r)

    # 
    # output_array = []
    # extensions = cert['tbs_certificate']['extensions']
    # content = False
    # oids = []
    # c_policies = None
    # for e in extensions:
    #     if e['extn_id'] == 'policy_mappings':
    #         c_policies = e
    #         break
    # 
    # for ce in config_options:
    #     if ce == "present":
    #         reason = "Policy Mappings not present in certificate"
    #         output_array.append(
    #             {"Item": ce, "Result": not c_policies == None, "Content": e['extn_id'].dotted, "Reason": reason})
    #     elif ce == "is_critical":
    #         if not c_policies == None:
    #             reason = "Policy Mappings ciriticality does not match between profile and certificate"
    #             output_array.append({"Item": ce, "Result": not c_policies == None, "Content": str(e['critical'].native),
    #                                  "Reason": reason})
    #     elif ce == "content":
    #         if not c_policies == None:
    #             for item in c_policies['extn_value']:
    #                 oids += [item['policy_identifier']]
    #             if [config_options[ce].oid] <= oids:
    #                 content = True
    #             reason = "Profile policy mapping content in certificate does not include the one in profile"
    #             output_array.append({"Item": ce, "Result": content, "Content": oids, "Reason": reason})
    # json_dump(output_array, config_options, cfg_sect, outJson)

    return r


def lint_piv_naci(config_options, cert):
    r = OutputRow("PIV NACI")
    print("\n--- " + r.row_name + " ---")
    
    pivnaci, is_critical = get_extension_from_certificate(cert, '2.16.840.1.101.3.6.9.1')

    _process_common_extension_options(config_options, pivnaci, is_critical, r)

    # output_array = []
    # extensions = cert['tbs_certificate']['extensions']
    # found = False
    # critical = False
    #
    # for e in extensions:
    #     if e['extn_id'] == config_options["present"].oid:
    #             found = True
    #             break
    #
    #
    # reason = "Profile oid is not in the certificate"
    # output_array.append({"Item": "present", "Result": found, "Content": e['extn_id'].dotted, "Reason": reason})
    # if found:
    #     reason = "extension criticality does not match  between profile and certificate"
    #     output_array.append({"Item": "is_critical", "Result": e['critical'].native, "Content": str(e['critical'].native),"Reason": reason})

    return r


def _lint_format_time(x509_time, name_string):
    return "{}:  {}{}".format(name_string, x509_time.native, _lint_cert_newline)


def lint_validity(config_options, cert):
    r = OutputRow("Validity Period")
    print("\n--- " + r.row_name + " ---")

    # output_array = []
    # reason = ""
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

    if 'validity_period_generalized_time' in config_options and len(config_options['validity_period_generalized_time'].value):
        validity_period_generalized_time = int(config_options['validity_period_generalized_time'].value)

    if validity_period_maximum > 0:
        # lifespan must be less than validity_period_maximum
        max_validity = datetime.timedelta(days=validity_period_maximum)
        if lifespan > max_validity:
            _lint_cert_add_error_to_row(r, "Validity period exceeds {} days".format(str(validity_period_maximum)))

    #todo i think this cutoff code probably doesn't work. the date would likely show up as 1950
    cut_off = datetime.datetime(2050, 1, 1)
    cut_off = cut_off.replace(tzinfo=pytz.UTC)

    # if nb.name == 'utc_time':
    #     if nb.native > cut_off:
    #         reason = "notBefore is required to be GeneralizedTime."

    if nb.name == 'utc_time':
        if nb.native > cut_off or validity_period_generalized_time is LINT_CERT_REQUIRED:
            _lint_cert_add_error_to_row(r, "notBefore is required to be GeneralizedTime")
    elif validity_period_generalized_time is LINT_CERT_DISALLOWED:
        _lint_cert_add_error_to_row(r, "notBefore is not permitted to be GeneralizedTime")

    if na.name == 'utc_time':
        if na.native > cut_off or validity_period_generalized_time is LINT_CERT_REQUIRED:
            _lint_cert_add_error_to_row(r, "notAfter is required to be GeneralizedTime")
    elif validity_period_generalized_time is LINT_CERT_DISALLOWED:
        _lint_cert_add_error_to_row(r, "notAfter is not permitted to be GeneralizedTime")

            
    # for ce in config_options:
    #     if ce == "validity_period_maximum":
    #         result = int(config_options[ce].value) == 0 or lifespan.days < int(config_options[ce].value)
    #         cert_value = lifespan.days
    #         reason += " Certificatre life span is less than the one specified in profile."
    #         output_array.append({"Item": ce, "Result": result, "Content": str(cert_value), "Reason": reason})
    #     elif ce == "validity_period_generalized_time":
    #         result = nb.native < cut_off #todo: ensure time compare
    #         cert_value = nb.native
    #         reason += " Generalized time validaity period is beyond what specified in profile."
    #         output_array.append({"Item": ce, "Result": result, "Content": str(cert_value), "Reason": reason})
    # for opa in output_array:
    #     gate = "PASS"
    #     ce = opa["Item"]
    #     result = opa["Result"]
    #     content = ""
    #     if not result:
    #         gate = "FAIL: " + opa["Reason"]
    #         content = opa["Content"]
    #     dictn = ast.literal_eval('{"Section": "' + cfg_sect + '",' +
    #                              '"Item": "' + ce + '",' +
    #                              '"Value": "' + config_options[ce].value + '",' +
    #                              '"OID": "' + config_options[ce].oid + '",' +
    #                              '"Content": "' + content + '",' +
    #                              '"OUTPUT": "' + gate + '"}')
    #     outJson.append(dictn.copy())

    return r


def lint_subject(config_options, cert):
    r = OutputRow("Subject")
    print("\n--- " + r.row_name + " ---")

    output_array = []

    subject = cert['tbs_certificate']['subject']
    r.content = get_pretty_dn(subject, ",{}".format(_lint_cert_newline), "=")

    found_base_dn = False

    # iterate over all rdn entries
    for ce in config_options:
        if "rdn_" in ce:
            # print(ce + " " + config_options[ce].oid)
            rdn_seq = subject.chosen
            found = False
            for rdn in rdn_seq:
                for name in rdn:
                    if name['type'].dotted == config_options[ce].oid:
                        found = True
                        break
                if found:
                    break
            reason = "oid does not match in profile and certificate"
            output_array.append({"Item": ce, "Result": found, "Content": str(rdn_seq.native), "Reason": reason})
        elif "subject_base_dn" in ce:
            for rdn in subject.native:  # need oid for base_dn to search for oid
                if 'base_dn' in rdn:
                    found_base_dn = True
                    # dn_split = ldap.dn(rdn) todo: compare dn's
                    break
            reason = "base DN not found"
            output_array.append(
                {"Item": "subject_base_dn", "Result": found_base_dn, "Content": str(subject.native), "Reason": reason})

    # json_dump(output_array, config_options, cfg_sect, outJson)

    return r


key_usage_display_map = {
    'digital_signature': 'digitalSignature (0)',
    'non_repudiation': 'nonRepudiation (1)',
    'key_encipherment': 'keyEncipherment (2)',
    'data_encipherment': 'dataEncipherment (3)',
    'key_agreement': 'keyAgreement (4)',
    'key_cert_sign': 'keyCertSign(5)',
    'crl_sign': 'cRLSign(6)',
    'encipher_only': 'encipherOnly(7)',
    'decipher_only': ' decipherOnly(8)',
}


def lint_key_usage(config_options, cert):
    r = OutputRow("Key Usage")
    print("\n--- " + r.row_name + " ---")

    _process_common_extension_options(config_options, cert.key_usage_value,
                                      'key_usage' in cert.critical_extensions, r)

    if cert.key_usage_value is not None:

        for ku in cert.key_usage_value.native:
            _lint_cert_add_content_line(r, key_usage_display_map[ku])

            if ku in config_options and config_options[ku].value == '1':
                _lint_cert_add_error_to_row(r, "{} is not permitted".format(key_usage_display_map[ku]))

        for ku in key_usage_display_map.keys():
            if ku in config_options and config_options[ku].value == '2' and ku not in cert.key_usage_value.native:
                _lint_cert_add_error_to_row(r, "{} is required".format(key_usage_display_map[ku]))


                #
                # output_array = []
                # extensions = cert['tbs_certificate']['extensions']
                # found = False
                # critical = False
                #
                # for e in extensions:
                #     if e['extn_id'].native == "key_usage":
                #             found = True
                #             break
                #
                # reason = "Profile oid is not in the certificate"
                # output_array.append({"Item": "present", "Result": found, "Content": e['extn_id'].dotted, "Reason": reason})
                # if found:
                #     reason = "extension criticality does not match  between profile and certificate"
                #     output_array.append({"Item": "is_critical", "Result": e['critical'].native, "Content": str(e['critical'].native),"Reason": reason})
                #
                #     reason = "Profile oid does not match the one in the certificate"
                #     output_array.append({"Item": "digital_signature", "Result": 'digital_signature' in e['extn_value'].native, "Content": e['extn_id'].dotted, "Reason": reason})
                #     output_array.append({"Item": "non_repudiation", "Result": 'non_repudiation' in e['extn_value'].native, "Content": e['extn_id'].dotted, "Reason": reason})
                #     output_array.append({"Item": "key_encipherment", "Result": 'key_encipherment' in e['extn_value'].native, "Content": e['extn_id'].dotted, "Reason": reason})
                #     output_array.append({"Item": "data_encipherment", "Result": 'data_encipherment' in e['extn_value'].native, "Content": e['extn_id'].dotted, "Reason": reason})
                #     result = opa["Result"]
                #     content = ""
                #     if result is True and config_options[ce].value is '1' or result is False and (config_options[ce].value is '3' or
                #         config_options[ce].value is '2') :
                #         gate = "FAIL: " + opa["Reason"]
                #         content = opa["Content"]
                #     dictn = ast.literal_eval('{"Section": "' + cfg_sect + '",' +
                #                   '"Item": "' + ce + '",' +
                #                   '"Value": "' + config_options[ce].value + '",' +
                #                   '"OID": "' + config_options[ce].oid + '",' +
                #                   '"Content": "' + content + '",' +
                #                   '"OUTPUT": "' +  gate + '"}')
                #     outJson.append(dictn.copy())
                # if "present" in ce:
                #    prof_ext_oids.add(config_options[ce].oid)
                #     output_array.append({"Item": "key_agreement", "Result": 'key_agreement' in e['extn_value'].native, "Content": e['extn_id'].dotted, "Reason": reason})
                #     output_array.append({"Item": "key_cert_sign", "Result": 'key_cert_sign' in e['extn_value'].native, "Content": e['extn_id'].dotted, "Reason": reason})
                #     output_array.append({"Item": "crl_sign", "Result": 'crl_sign' in e['extn_value'].native, "Content": e['extn_id'].dotted, "Reason": reason})
                #     output_array.append({"Item": "encipher_only", "Result": 'encipher_only' in e['extn_value'].native, "Content": e['extn_id'].dotted, "Reason": reason})
                #     output_array.append({"Item": "decipher_only", "Result": 'decipher_only' in e['extn_value'].native, "Content": e['extn_id'].dotted, "Reason": reason})
                # for opa in output_array:
                #     gate = "PASS"
                #     ce = opa["Item"]


    return r


def lint_issuer(config_options, cert):
    r = OutputRow("Issuer")
    print("\n--- " + r.row_name + " ---")

    r.content = get_pretty_dn(cert.issuer, ",{}".format(_lint_cert_newline), "=")

    output_array = []
    cert_leaf = cert['tbs_certificate']['issuer']
    found_base_dn = False
    found = False
    # iterate over all rdn entries
    for ce in config_options:
        if "rdn_" in ce:
            # print(ce + " " + config_options[ce].oid)
            rdn_seq = cert_leaf.chosen
            found = False
            for rdn in rdn_seq:
                for name in rdn:
                    if name['type'].dotted == config_options[ce].oid:
                        found = True
                        break
                if found:
                    break
            reason = "oid does not match in profile and certificate"
            output_array.append({"Item": ce, "Result": found, "Content": rdn_seq.native, "Reason": reason})
        elif "base_dn" in ce:
            for rdn in cert_leaf.native:  # need oid for base_dn to search for oid
                if 'base_dn' in rdn:
                    found_base_dn = True
                    # dn_split = ldap.dn(rdn) todo: compare dn's
                    break
            reason = "base DN not found"
            output_array.append(
                {"Item": "base_dn", "Result": found_base_dn, "Content": "", "Reason": reason})

    # json_dump(output_array, config_options, cfg_sect, outJson)

    return r


def lint_akid(config_options, cert):
    r = OutputRow("Authority Key Id")
    print("\n--- " + r.row_name + " ---")

    _process_common_extension_options(config_options, cert.authority_key_identifier_value,
                                      'authority_key_identifier' in cert.critical_extensions,
                                      r)

    output_array = []
    extensions = cert['tbs_certificate']['extensions']
    found = False

    for e in extensions:
        if e['extn_id'].native == "key_identifier":
            found = True
            break

    reason = "Subject Key Identifier is not present"
    output_array.append({"Item": "present", "Result": found, "Content": e['extn_id'].dotted, "Reason": reason})
    if found:
        reason = "extension criticality does not match between profile and certificate"
        output_array.append(
            {"Item": "is_critical", "Result": e['critical'].native, "Content": str(e['critical'].native),
             "Reason": reason})
        extn_v = '{}'.format('%02X' % c for c in e['extn_value'].native)

        # TODO: two more fields

    # json_dump(output_array, config_options, cfg_sect, outJson)

    return r


def lint_skid(config_options, cert):
    r = OutputRow("Subject Key Id")
    print("\n--- " + r.row_name + " ---")

    _process_common_extension_options(config_options, cert.key_identifier_value,
                                      'key_identifier' in cert.critical_extensions,
                                      r)

    output_array = []
    extensions = cert['tbs_certificate']['extensions']
    found = False

    for e in extensions:
        if e['extn_id'].native == "key_identifier":
            found = True
            break

    reason = "Subject Key Identifier is not present"
    output_array.append({"Item": "present", "Result": found, "Content": e['extn_id'].dotted, "Reason": reason})
    if found:
        reason = "extension criticality does not match between profile and certificate"
        output_array.append(
            {"Item": "is_critical", "Result": e['critical'].native, "Content": str(e['critical'].native),
             "Reason": reason})

        skid = cert.key_identifier_value.native
        they_used_method_one = skid == cert['tbs_certificate']['subject_public_key_info'].sha1
        reason = "Method one (sha1) is not allowed"
        output_array.append(
            {"Item": "require_method_one", "Result": they_used_method_one, "Content": str(skid),
             "Reason": reason})
        # todo look further
    # json_dump(output_array, config_options, cfg_sect, outJson)

    return r


def lint_policy_constraints(config_options, cert):
    r = OutputRow("Policy Constraints")
    print("\n--- " + r.row_name + " ---")

    _process_common_extension_options(config_options, cert.policy_constraints_value,
                                      'policy_constraints' in cert.critical_extensions,
                                      r)

    output_array = []
    extensions = cert['tbs_certificate']['extensions']
    found = False
    critical = False

    for e in extensions:  # not in cert, mimicing aia
        if e['extn_id'].native == "policy_constraints":
            found = True
            break

    reason = "Profile oid is not in the certificate"
    output_array.append({"Item": "present", "Result": found, "Content": e['extn_id'].dotted, "Reason": reason})
    if found:
        reason = "extension criticality does not match between profile and certificate"
        output_array.append(
            {"Item": "is_critical", "Result": e['critical'].native, "Content": str(e['critical'].native),
             "Reason": reason})

        '''
        explicit_policy_present = False
        policy_mapping_present = False

        for item in e['extn_value'].native:
            if item['require_explicit_policy']:
                explicit_policy_present = True
            elif item['inhibit_policy_mapping'] > 0:
                policy_mapping_present = True

            reason = "Policy Constraints Require Explicit Policy not present"
            output_array.append({"Item": "require_explicit_policy_present", "Result": explicit_policy_present,
                                     "Content": str(e['critical'].native), "Reason": reason})
            reason = "Policy Constraints Require Explicit Policy Max not present"
            output_array.append({"Item": "require_explicit_policy_max", "Result": e['critical'].native,
                                     "Content": str(e['critical'].native), "Reason": reason})
            reason = "Policy Constraints Require Explicit Policy Mapping not present"
            output_array.append({"Item": "inhibit_policy_mapping_present", "Result": policy_mapping_present,
                                     "Content": str(e['critical'].native), "Reason": reason})
            reason = "extension criticality does not match between profile and certificate"
            output_array.append({"Item": "inhibit_policy_mapping_max", "Result": e['critical'].native,
                                     "Content": str(e['critical'].native), "Reason": reason})
        '''

        # todo: need cert example

    # json_dump(output_array, config_options, cfg_sect, outJson)

    return r


def lint_serial_number(config_options, cert):
    r = OutputRow("Serial Number")
    print("\n--- " + r.row_name + " ---")

    output_array = []
    cert_leaf = cert['tbs_certificate']['serial_number'].native

    # todo we don't care about the length of the string representation of the binary converted to an int.
    # todo the length that matters is the length of the binary.
    # todo i.e. len(cert['tbs_certificate']['serial_number'].contents)
    # todo if the spreadsheet is not clear enough: "No minimum, minimum length (bytes), No max, max length (bytes)"
    # todo then please ask...

    ln = len(str(cert_leaf))
    pln = int(config_options["min_length"].value)
    reason = "Certficate serial number length is less than profile specifiled minimum length"
    output_array.append(
        {"Item": "min_length", "Result": pln == 0 or ln > pln, "Content": str(cert_leaf), "Reason": reason})
    pln = int(config_options["max_length"].value)
    reason = "Certficate serial number length is more than profile specifiled maximum length"
    output_array.append(
        {"Item": "max_length", "Result": pln == 0 or ln < pln, "Content": str(cert_leaf), "Reason": reason})

    # for opa in output_array:
    #     gate = "PASS"
    #     ce = opa["Item"]
    #     result = opa["Result"]
    #     content = ""
    #     if not result:
    #         gate = "FAIL: " + opa["Reason"]
    #         content = opa["Content"]
    #     dictn = ast.literal_eval('{"Section": "' + cfg_sect + '",' +
    #                              '"Item": "' + ce + '",' +
    #                              '"Value": "' + config_options[ce].value + '",' +
    #                              '"OID": "' + config_options[ce].oid + '",' +
    #                              '"Content": "' + content + '",' +
    #                              '"OUTPUT": "' + gate + '"}')
    #     outJson.append(dictn.copy())

    return r


def lint_basic_constraints(config_options, cert):
    r = OutputRow("Basic Constraints")
    print("\n--- " + r.row_name + " ---")

    _process_common_extension_options(config_options, cert.basic_constraints_value,
                                      'basic_constraints' in cert.critical_extensions,
                                     r)

    output_array = []
    extensions = cert['tbs_certificate']['extensions']
    found = False
    critical = False

    for e in extensions:  # not in cert, mimicing aia
        if e['extn_id'].native == "basic_constraints":
            found = True
            break

    reason = "Profile oid is not in the certificate"
    output_array.append({"Item": "present", "Result": found, "Content": e['extn_id'].dotted, "Reason": reason})
    if found:
        reason = "extension criticality does not match between profile and certificate"
        output_array.append(
            {"Item": "is_critical", "Result": e['critical'].native, "Content": str(e['critical'].native),
             "Reason": reason})


        # todo: need cert example. you have them in the zip file I sent you 10/18/2017 2:12 PM

    # json_dump(output_array, config_options, cfg_sect, outJson)

    return r


def lint_cert_policies(config_options, cert):
    r = OutputRow("Certificate Policies")
    print("\n--- " + r.row_name + " ---")

    _process_common_extension_options(config_options, cert.certificate_policies_value,
                                      'certificate_policies' in cert.critical_extensions,
                                      r)

    permitted_policies = None

    if cert.certificate_policies_value is not None:

        if 'permitted' in config_options and len(config_options['permitted'].value) > 0:
            permitted_policies = config_options['permitted'].value.split()

        for policy in cert.certificate_policies_value:
            _lint_cert_add_content_line(r, policy.native['policy_identifier'])

            if permitted_policies is not None and \
                            policy.native['policy_identifier'] not in permitted_policies:
                _lint_cert_add_error_to_row(r, "{} is not a permitted".format(policy.native['policy_identifier']))

    #
    #
    # output_array = []
    # extensions = cert['tbs_certificate']['extensions']
    # content = False
    # oids = set()
    # c_policies = None
    # for e in extensions:
    #     if e['extn_id'].native == 'certificate_policies':
    #         c_policies = e
    #         break
    #
    # for ce in config_options:
    #     if ce == "present":
    #         reason = "certificate policies not present"
    #         output_array.append(
    #             {"Item": ce, "Result": not c_policies == None, "Content": e['extn_id'].dotted, "Reason": reason})
    #     elif ce == "is_critical":
    #         if not c_policies == None:
    #             reason = "certificate policies is not critical"
    #             output_array.append(
    #                 {"Item": ce, "Result": c_policies['critical'], "Content": str(c_policies['critical']),
    #                  "Reason": reason})
    #     elif ce == "content":
    #         if not c_policies == None:
    #             for item in c_policies['extn_value'].native:
    #                 oids.add(item['policy_identifier'])
    #             if config_options[ce].oid in oids:
    #                 content = True
    #             reason = "profile policy oid is not in the certificate"
    #             output_array.append({"Item": ce, "Result": content, "Content": str(oids), "Reason": reason})

    # json_dump(output_array, config_options, cfg_sect, outJson)

    return r


def lint_subject_public_key_info(config_options, cert):
    r = OutputRow("Public Key")
    print("\n--- " + r.row_name + " ---")

    r.content = "Put public key here"

    output_array = []
    cert_leaf = cert['tbs_certificate']['subject_public_key_info']
    algo = cert_leaf['algorithm']['algorithm'].dotted
    found = False
    for ce in config_options:
        if config_options[ce].oid == algo:
            found = True
            break
    reason = "Profile oid is not in the certificate"
    vl = config_options[ce].value
    output_array.append({"Item": ce, "Result": vl == "0" or vl == "1" and not found or vl == "2" and found,
                         "Content": algo, "Reason": reason})

    blen = cert_leaf['public_key'].native['modulus'].bit_length()

    reason = "certificate public key size is less than prfoile minimum key size"
    output_array.append(
        {"Item": "min_size", "Result": blen > int(config_options['min_size'].value), "Content": str(blen), "Reason": reason})
    reason = "certificate public key size is more than prfoile maximum key size"
    output_array.append(
        {"Item": "max_size", "Result": blen < int(config_options['max_size'].value), "Content": str(blen), "Reason": reason})

    # for opa in output_array:
    #     gate = "PASS"
    #     ce = opa["Item"]
    #     result = opa["Result"]
    #     content = ""
    #     if not result:
    #         gate = "FAIL: " + opa["Reason"]
    #         content = opa["Content"]
    #     dictn = ast.literal_eval('{"Section": "' + cfg_sect + '",' +
    #                              '"Item": "' + ce + '",' +
    #                              '"Value": "' + config_options[ce].value + '",' +
    #                              '"OID": "' + config_options[ce].oid + '",' +
    #                              '"Content": "' + content + '",' +
    #                              '"OUTPUT": "' + gate + '"}')
    #     outJson.append(dictn.copy())

    return r


def lint_aia(config_options, cert):
    r = OutputRow("Authority Info Access")
    print("\n--- " + r.row_name + " ---")

    _process_common_extension_options(config_options, cert.authority_information_access_value,
                                      'authority_information_access' in cert.critical_extensions,
                                      r)

    # cert.authority_information_access_value['key_identifier']
    # cert.authority_information_access_value['authority_cert_issuer']
    # cert.authority_information_access_value['authority_cert_serial_number']

    output_array = []
    extensions = cert['tbs_certificate']['extensions']
    found = False
    critical = False

    for e in extensions:
        if e['extn_id'].native == "authority_information_access":
            found = True
            break

    reason = "Profile oid is not in the certificate"
    output_array.append({"Item": "present", "Result": found, "Content": e['extn_id'].dotted, "Reason": reason})
    if found:
        reason = "extension criticality does not match  between profile and certificate"
        output_array.append(
            {"Item": "is_critical", "Result": e['critical'].native, "Content": str(e['critical'].native),
             "Reason": reason})
        ca_issuers_present = False
        ocsp_found = False
        http_found = False
        ldap_found = False
        http_before_ldap = False
        ocsp_http = False
        for item in e['extn_value'].native:
            if item['access_method'] == 'ca_issuers':
                ca_issuers_present = True
                if 'http' in item['access_location']:
                    http_found = True
                elif 'ldap' in item['access_location']:
                    ldap_found = True
                    if http_found:
                        http_before_ldap = True
            elif item['access_method'] == 'ocsp':
                ocsp_found = True
                if 'http' in item['access_location']:
                    ocsp_http = True

        reason = "ca_repository_present not present"
        output_array.append(
            {"Item": "ca_issuers_present", "Result": ca_issuers_present, "Content": item['access_method'],
             "Reason": reason})

        reason = "AIA CA Repository HTTP is not found"
        output_array.append(
            {"Item": "ca_issuers_http", "Result": http_found, "Content": item['access_location'], "Reason": reason})

        reason = "AIA CA Repository LDAP is not found"
        output_array.append(
            {"Item": "ca_issuers_ldap", "Result": ldap_found, "Content": item['access_location'], "Reason": reason})

        reason = "AIA CA Repository LDAP is before HTTP"
        output_array.append(
            {"Item": "ca_issuers_http_before_ldap", "Result": http_before_ldap, "Content": item['access_location'],
             "Reason": reason})

        reason = "AIA OCSP not present"
        output_array.append(
            {"Item": "ocsp_present", "Result": ocsp_found, "Content": item['access_location'], "Reason": reason})

        reason = "AIA OCSP HTTP is not found"
        output_array.append(
            {"Item": "ocsp_https", "Result": ocsp_http, "Content": item['access_location'], "Reason": reason})

    # todo, cert example: "ca_issuers_directory_name"


    # json_dump(output_array, config_options, cfg_sect, outJson)

    return r


def lint_san(config_options, cert):
    r = OutputRow("Subject Alt Name")
    print("\n--- " + r.row_name + " ---")

    _process_common_extension_options(config_options, cert.subject_alt_name_value,
                                      'subject_alt_name' in cert.critical_extensions,
                                      r)

    output_array = []
    extensions = cert['tbs_certificate']['extensions']
    found = False
    critical = False

    for e in extensions:
        if e['extn_id'].native == "subject_alt_name":
            found = True
            break

    reason = "Profile oid is not in the certificate"
    output_array.append({"Item": "present", "Result": found, "Content": e['extn_id'].dotted, "Reason": reason})
    if found:
        reason = "extension criticality does not match  between profile and certificate"
        output_array.append(
            {"Item": "is_critical", "Result": e['critical'].native, "Content": str(e['critical'].native),
             "Reason": reason})

        # todo this is wrong
        c_oid = "1.2.3.4.5"
        # e['extn_value'].native[0]['type_id']

        reason = "Profile oid does not match the one in the certificate"
        #oid_found = False
        #for ce in config_options:
         #   if c_oid == config_options['rfc822_name'].oid:
          #      oid_found = True
          #      break need redesign tempate.json to accommodate section wide PASS/FAILL
        output_array.append(
            {"Item": "rfc822_name", "Result": c_oid == config_options['rfc822_name'].oid, "Content": c_oid, "Reason": reason})
        output_array.append({"Item": "x400_address", "Result": c_oid == config_options['x400_address'].oid, "Content": c_oid,
                             "Reason": reason})
        output_array.append(
            {"Item": "directory_name", "Result": c_oid == config_options['directory_name'].oid, "Content": c_oid,
             "Reason": reason})
        output_array.append(
            {"Item": "edi_party_name", "Result": c_oid == config_options['edi_party_name'].oid, "Content": c_oid,
             "Reason": reason})
        output_array.append(
            {"Item": "uniform_resource_identifier", "Result": c_oid == config_options['uniform_resource_identifier'].oid,
             "Content": c_oid, "Reason": reason})
        output_array.append(
            {"Item": "ip_address", "Result": c_oid == config_options['ip_address'].oid, "Content": c_oid, "Reason": reason})
        output_array.append({"Item": "registered_id", "Result": c_oid == config_options['registered_id'].oid, "Content": c_oid,
                             "Reason": reason})
        output_array.append(
            {"Item": "other_name_upn", "Result": c_oid == config_options['other_name_upn'].oid, "Content": c_oid,
             "Reason": reason})
        output_array.append(
            {"Item": "other_name_piv_fasc_n", "Result": c_oid == config_options['other_name_piv_fasc_n'].oid, "Content": c_oid,
             "Reason": reason})
        output_array.append({"Item": "uniform_resource_identifier_chuid",
                             "Result": c_oid == config_options['uniform_resource_identifier_chuid'].oid, "Content": c_oid,
                             "Reason": reason})

    # json_dump(output_array, config_options, cfg_sect, outJson)

    return r


def lint_ian(config_options, cert):
    r = OutputRow("Issuer Alt Name")
    print("\n--- " + r.row_name + " ---")

    _process_common_extension_options(config_options, cert.issuer_alt_name_value,
                                      'issuer_alt_name' in cert.critical_extensions,
                                      r)

    output_array = []
    extensions = cert['tbs_certificate']['extensions']
    found = False
    critical = False

    for e in extensions:
        if e['extn_id'].native == "issuer_alt_name":
            found = True
            break

    reason = "Profile oid is not in the certificate"
    output_array.append({"Item": "present", "Result": found, "Content": e['extn_id'].dotted, "Reason": reason})
    if found:
        reason = "extension criticality does not match  between profile and certificate"
        output_array.append(
            {"Item": "is_critical", "Result": e['critical'].native, "Content": str(e['critical'].native),
             "Reason": reason})

        c_oid = e['extn_value'].native[0]['type_id']
        reason = "Profile oid does not match the one in the certificate"
        output_array.append(
            {"Item": "rfc822_name", "Result": c_oid == config_options['rfc822_name'].oid, "Content": c_oid, "Reason": reason})
        output_array.append({"Item": "x400_address", "Result": c_oid == config_options['x400_address'].oid, "Content": c_oid,
                             "Reason": reason})
        output_array.append(
            {"Item": "directory_name", "Result": c_oid == config_options['directory_name'].oid, "Content": c_oid,
             "Reason": reason})
        output_array.append(
            {"Item": "edi_party_name", "Result": c_oid == config_options['edi_party_name'].oid, "Content": c_oid,
             "Reason": reason})
        output_array.append(
            {"Item": "uniform_resource_identifier", "Result": c_oid == config_options['uniform_resource_identifier'].oid,
             "Content": c_oid, "Reason": reason})
        output_array.append(
            {"Item": "ip_address", "Result": c_oid == config_options['ip_address'].oid, "Content": c_oid, "Reason": reason})
        output_array.append({"Item": "registered_id", "Result": c_oid == config_options['registered_id'].oid, "Content": c_oid,
                             "Reason": reason})
        output_array.append(
            {"Item": "other_name", "Result": c_oid == config_options['other_name'].oid, "Content": c_oid, "Reason": reason})
        output_array.append(
            {"Item": "dns_name", "Result": c_oid == config_options['dns_name'].oid, "Content": c_oid, "Reason": reason})
        output_array.append(
            {"Item": "other_name_piv_fasc_n", "Result": c_oid == config_options['other_name_piv_fasc_n'].oid, "Content": c_oid,
             "Reason": reason})
        output_array.append({"Item": "uniform_resource_identifier_chuid",
                             "Result": c_oid == config_options['uniform_resource_identifier_chuid'].oid, "Content": c_oid,
                             "Reason": reason})

    # json_dump(output_array, config_options, cfg_sect, outJson)

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
}


def lint_eku(config_options, cert):
    r = OutputRow("Extended Key Usage")
    print("\n--- " + r.row_name + " ---")

    _process_common_extension_options(config_options, cert.extended_key_usage_value,
                                      'extended_key_usage' in cert.critical_extensions,
                                      r)

    if cert.extended_key_usage_value is not None:

        eku_oids = []
        for eku in cert.extended_key_usage_value:
            eku_oids.append(eku.dotted)
            _lint_cert_add_content_line(r, "{} ({})".format(eku_display_map.get(eku.dotted, "Unknown EKU"), eku.dotted))

        for ce in config_options:
            if "oid_" in ce:
                _do_presence_test(r, config_options, ce, eku_display_map.get(config_options[ce].oid, "Unknown EKU"),
                                  config_options[ce].oid in eku_oids)


    # output_array = []
    # extensions = cert['tbs_certificate']['extensions']
    # found = False
    # critical = False
    #
    # for e in extensions:
    #     if e['extn_id'].native == "extended_key_usage":
    #             found = True
    #             break
    #
    # reason = "Profile oid is not in the certificate"
    # output_array.append({"Item": "present", "Result": found, "Content": e['extn_id'].dotted, "Reason": reason})
    # if found:
    #     reason = "extension criticality does not match  between profile and certificate"
    #     output_array.append({"Item": "is_critical", "Result": e['critical'].native, "Content": str(e['critical'].native),"Reason": reason})
    #
    #     c_oid = e['extn_value'].native[0]
    #     reason = "Profile oid does not match the one in the certificate"
    #     output_array.append({"Item": "oid_server_auth", "Result": c_oid == config_options['oid_server_auth'].oid, "Content": c_oid, "Reason": reason})
    #     output_array.append({"Item": "oid_client_auth", "Result": c_oid == config_options['oid_client_auth'].oid, "Content": c_oid, "Reason": reason})
    #     output_array.append({"Item": "oid_code_signing", "Result": c_oid == config_options['oid_code_signing'].oid, "Content": c_oid, "Reason": reason})
    #     output_array.append({"Item": "oid_email_protection", "Result": c_oid == config_options['oid_email_protection'].oid, "Content": c_oid, "Reason": reason})
    #     output_array.append({"Item": "oid_time_stamping", "Result": c_oid == config_options['oid_time_stamping'].oid, "Content": c_oid, "Reason": reason})
    #     output_array.append({"Item": "oid_ocsp_signing", "Result": c_oid == config_options['oid_ocsp_signing'].oid, "Content": c_oid, "Reason": reason})
    #     output_array.append({"Item": "oid_any_eku", "Result": c_oid == config_options['oid_any_eku'].oid, "Content": c_oid, "Reason": reason})
    #     output_array.append({"Item": "oid_smart_card_logon", "Result": c_oid == config_options['oid_smart_card_logon'].oid, "Content": c_oid, "Reason": reason})
    #     output_array.append({"Item": "oid_ipsec_ike_intermediate", "Result": c_oid == config_options['oid_ipsec_ike_intermediate'].oid, "Content": c_oid, "Reason": reason})
    #     output_array.append({"Item": "oid_ipsec_end_system", "Result": c_oid == config_options['oid_ipsec_end_system'].oid, "Content": c_oid, "Reason": reason})
    #     output_array.append({"Item": "oid_ipsec_tunnel_termination", "Result": c_oid == config_options['oid_ipsec_tunnel_termination'].oid, "Content": c_oid, "Reason": reason})
    #     output_array.append({"Item": "oid_ipsec_user", "Result": c_oid == config_options['oid_ipsec_user'].oid, "Content": c_oid, "Reason": reason})
    #     output_array.append({"Item": "oid_piv_card_auth", "Result": c_oid == config_options['oid_piv_card_auth'].oid, "Content": c_oid, "Reason": reason})
    #     output_array.append({"Item": "oid_pivi_content_signing", "Result": c_oid == config_options['oid_pivi_content_signing'].oid, "Content": c_oid, "Reason": reason})
    #     output_array.append({"Item": "oid_smartCardLogon", "Result": c_oid == config_options['oid_smartCardLogon'].oid, "Content": c_oid, "Reason": reason})
    #     output_array.append({"Item": "oid_pkinit_KPKdc", "Result": c_oid == config_options['oid_pkinit_KPKdc'].oid, "Content": c_oid, "Reason": reason})
    #     output_array.append({"Item": "oid_pkinit_KPClientAuth", "Result": c_oid == config_options['oid_pkinit_KPClientAuth'].oid, "Content": c_oid, "Reason": reason})
    #     output_array.append({"Item": "other", "Result": c_oid == config_options['other'].oid, "Content": c_oid, "Reason": reason})
    #
    # for opa in output_array:
    #     gate = "PASS"
    #     ce = opa["Item"]
    #     result = opa["Result"]
    #     content = ""
    #     if result is True and config_options[ce].value is '1' or result is False and (config_options[ce].value is '3' or
    #         config_options[ce].value is '2') :
    #         gate = "FAIL: " + opa["Reason"]
    #         content = opa["Content"]
    #     dictn = ast.literal_eval('{"Section": "' + cfg_sect + '",' +
    #                   '"Item": "' + ce + '",' +
    #                   '"Value": "' + config_options[ce].value + '",' +
    #                   '"OID": "' + config_options[ce].oid + '",' +
    #                   '"Content": "' + content + '",' +
    #                   '"OUTPUT": "' +  gate + '"}')
    #     outJson.append(dictn.copy())
    # if "present" in ce:
    #    prof_ext_oids.add(config_options[ce].oid)

    return r


def lint_crldp(config_options, cert):
    r = OutputRow("CRL Distribution Points")
    print("\n--- " + r.row_name + " ---")

    _process_common_extension_options(config_options, cert.crl_distribution_points_value,
                                      'crl_distribution_points' in cert.critical_extensions,
                                      r)
    output_array = []
    extensions = cert['tbs_certificate']['extensions']
    found = False
    http = False
    ldap = False
    http_before_ldap = False
    http = False
    for e in extensions:
        if e['extn_id'].native == "crl_distribution_points":
            found = True
            break

    reason = "Profile oid is not in the certificate"
    output_array.append({"Item": "present", "Result": found, "Content": e['extn_id'].dotted, "Reason": reason})
    if found:
        reason = "extension criticality does not match  between profile and certificate"
        output_array.append(
            {"Item": "is_critical", "Result": e['critical'].native, "Content": str(e['critical'].native),
             "Reason": reason})

        for item in e['extn_value'].native:
            if "http" in str(item['distribution_point']):
                http = True  # search oid?
            if "ldap" in str(item['distribution_point']):
                ldap = True
                if http:
                    http_before_ldap = True
                    # elif dn tell dn

        reason = "CRL Dirstribution Point HTTP is not found"
        output_array.append(
            {"Item": "http", "Result": http, "Content": item['distribution_point'][0], "Reason": reason})

        reason = "CRL Dirstribution Point LDAP is not found"
        output_array.append(
            {"Item": "ldap", "Result": ldap, "Content": item['distribution_point'][0], "Reason": reason})

        reason = "CRL Dirstribution Point LDAP is before HTTP"
        output_array.append(
            {"Item": "http_before_ldap", "Result": http_before_ldap, "Content": item['distribution_point'][0],
             "Reason": reason})

        # todo, cert example: "directory_name"

    # json_dump(output_array, config_options, cfg_sect, outJson)

    return r


def lint_sia(config_options, cert):
    r = OutputRow("Subject info Access")
    print("\n--- " + r.row_name + " ---")

    _process_common_extension_options(config_options, cert.subject_information_access_value,
                                      'subject_information_access' in cert.critical_extensions,
                                      r)

    output_array = []
    extensions = cert['tbs_certificate']['extensions']
    found = False
    critical = False

    for e in extensions:
        if e['extn_id'].native == "subject_information_access":
            found = True
            break

    reason = "Profile oid is not in the certificate"
    output_array.append({"Item": "present", "Result": found, "Content": e['extn_id'].dotted, "Reason": reason})
    if found:
        reason = "extension criticality does not match  between profile and certificate"
        output_array.append(
            {"Item": "is_critical", "Result": e['critical'].native, "Content": str(e['critical'].native),
             "Reason": reason})

        ca_repository_present = False
        http_found = False
        ldap_found = False
        http_before_ldap = False
        for item in e['extn_value'].native:
            if item['access_method'] == 'ca_repository':
                ca_repository_present = True
                if 'http' in item['access_location']:
                    http_found = True
                elif 'ldap' in item['access_location']:
                    ldap_found = True
                    if http_found:
                        http_before_ldap = True
        reason = "ca_repository_present not present"
        output_array.append(
            {"Item": "ca_repository_present", "Result": ca_repository_present, "Content": item['access_method'],
             "Reason": reason})

        reason = "SIA CA Repository HTTP is not found"
        output_array.append(
            {"Item": "ca_repository_http", "Result": http_found, "Content": item['access_location'], "Reason": reason})

        reason = "SIA CA Repository LDAP is not found"
        output_array.append(
            {"Item": "ca_repository_ldap", "Result": ldap_found, "Content": item['access_location'], "Reason": reason})

        reason = "SIA CA Repository LDAP is before HTTP"
        output_array.append(
            {"Item": "ca_repository_http_before_ldap", "Result": http_before_ldap, "Content": item['access_location'],
             "Reason": reason})

    # json_dump(output_array, config_options, cfg_sect, outJson)

    return r


def lint_pkup(config_options, cert):
    r = OutputRow("Private Key Usage Period")
    print("\n--- " + r.row_name + " ---")

    pkup, is_critical = get_extension_from_certificate(cert, '2.5.29.16')

    _process_common_extension_options(config_options, pkup,
                                      is_critical,
                                      r)

    # output_array = []
    # extensions = cert['tbs_certificate']['extensions']
    # found = False
    #
    # oids = []
    # for e in extensions:  # not in cert, mimicing aia
    #     oids.append(e['extn_id'].dotted)
    #     if e['extn_id'].native == "private_key_usage_period":
    #         found = True
    #         break
    #
    # reason = "Profile oid is not in the certificate"
    # output_array.append({"Item": "present", "Result": found, "Content": str(oids), "Reason": reason})
    #
    # if found:
    #     reason = "extension criticality does not match  between profile and certificate"
    #     output_array.append(
    #         {"Item": "is_critical", "Result": e['critical'].native, "Content": str(e['critical'].native),
    #          "Reason": reason})
    #
    # json_dump(output_array, config_options, cfg_sect, outJson)

    return r


def lint_sub_dir_attr(config_options, cert):
    r = OutputRow("Subject Directory Attributes")
    print("\n--- " + r.row_name + " ---")

    _process_common_extension_options(config_options, cert.subject_directory_attributes_value,
                                      'subject_directory_attributes' in cert.critical_extensions,
                                      r)
    #
    # output_array = []
    # extensions = cert['tbs_certificate']['extensions']
    # found = False
    #
    # oids = []
    # for e in extensions:  # not in cert, mimicing aia
    #     oids.append(e['extn_id'].dotted)
    #     if e['extn_id'].native == "subject_directory_attribute":
    #         found = True
    #         break
    #
    # reason = "Profile oid is not in the certificate"
    # output_array.append({"Item": "present", "Result": found, "Content": str(oids), "Reason": reason})
    #
    # if found:
    #     reason = "extension criticality does not match  between profile and certificate"
    #     output_array.append(
    #         {"Item": "is_critical", "Result": e['critical'].native, "Content": str(e['critical'].native),
    #          "Reason": reason})
    #
    # json_dump(output_array, config_options, cfg_sect, outJson)

    return r


def lint_signature_algorithm(config_options, cert):
    r = OutputRow("Signature Algorithm")
    print("\n--- " + r.row_name + " ---")

    output_array = []
    cert_leaf = cert['signature_algorithm']['algorithm']
    oid = cert_leaf.dotted
    found = False
    for ce in config_options:
        if config_options[ce].oid == oid:
            found = True
            break

    cert_leaf1 = cert['tbs_certificate']['signature']['algorithm'].dotted
    reason = "the certificate signature algorithm not found in profile or the signature algorithm and TBS certificate signature algorithm are not the same"
    output_array.append({"Item": ce, "Result": found and cert_leaf.dotted == cert_leaf1,
                         "Content": "signature algorithm:" + oid + ". tbs certificate sig algorithm: " + cert_leaf1,
                         "Reason": reason})

    # for opa in output_array:
    #     gate = "PASS"
    #     ce = opa["Item"]
    #     result = opa["Result"]
    #     content = ""
    #     if result is True and config_options[ce].value is '1':
    #         gate = "FAIL: " + opa["Reason"]
    #         content = opa["Content"]
    #     dictn = ast.literal_eval('{"Section": "' + cfg_sect + '",' +
    #                              '"Item": "' + ce + '",' +
    #                              '"Value": "' + config_options[ce].value + '",' +
    #                              '"OID": "' + config_options[ce].oid + '",' +
    #                              '"Content": "' + content + '",' +
    #                              '"OUTPUT": "' + gate + '"}')
    #     outJson.append(dictn.copy())
    #     # if "present" in ce:
    #     #    prof_ext_oids.add(config_options[ce].oid)

    return r


def lint_version(config_options, cert):
    r = OutputRow("Version", cert['tbs_certificate']['version'].native)
    print("\n--- " + r.row_name + " ---")

    min_version = 'v3'

    if 'min_version' in config_options and len(config_options['min_version'].value) > 0:
        min_version_num = int(config_options['min_version'].value)
        min_version = "v{}".format(str(min_version_num + 1))

    if int(cert['tbs_certificate']['version']) < min_version_num:
        _lint_cert_add_error_to_row(r, "Minimum permitted version is {}".format(min_version))

    # output_array = []
    # cert_leaf = cert['tbs_certificate']['version'].native
    #
    # reason = "Certifcate Version is less than the minimum certificate versoin specified in the profile"
    # output_array.append(
    #     {"Item": "min_version", "Result": int(cert_leaf[1:]) >= int(config_options['min_version'].value), "Content": cert_leaf,
    #      "Reason": reason})

    # json_dump(output_array, config_options, cfg_sect, outJson)

    return r


def lint_ocsp_nocheck(config_options, cert):
    r = OutputRow("OCSP NoCheck")
    print("\n--- " + r.row_name + " ---")

    _process_common_extension_options(config_options, cert.ocsp_no_check_value,
                                      'ocsp_no_check' in cert.critical_extensions,
                                      r)

    output_array = []
    extensions = cert['tbs_certificate']['extensions']
    found = False

    for e in extensions:  # not in cert, mimicing aia
        if e['extn_id'].native == "ocsp_no_ckeck":
            found = True
            break

    reason = "Profile oid is not in the certificate"
    output_array.append({"Item": "present", "Result": found, "Content": e['extn_id'].dotted, "Reason": reason})

    if found:
        reason = "extension criticality does not match  between profile and certificate"
        output_array.append({"Item": "critical", "Result": e['critical'].native, "Content": str(e['critical'].native),
                             "Reason": reason})

    # json_dump(output_array, config_options, cfg_sect, outJson)

    return r


def lint_inhibit_any(config_options, cert):
    r = OutputRow("Inhibit Any Policy")
    print("\n--- " + r.row_name + " ---")

    _process_common_extension_options(config_options, cert.inhibit_any_policy_value,
                                      'inhibit_any_policy' in cert.critical_extensions,
                                      r)
    #
    # output_array = []
    # extensions = cert['tbs_certificate']['extensions']
    # found = False
    # critical = False
    #
    # for e in extensions:  # not in cert, mimicing aia
    #     if e['extn_id'].native == "inhibit_any_policy":
    #         found = True
    #         break
    # reason = "Profile oid is not in the certificate"
    # output_array.append({"Item": "present", "Result": found, "Content": e['extn_id'].dotted, "Reason": reason})
    #
    # if found:
    #     reason = "extension criticality does not match  between profile and certificate"
    #     output_array.append(
    #         {"Item": "is_critical", "Result": e['critical'].native, "Content": str(e['critical'].native),
    #          "Reason": reason})
    #
    # json_dump(output_array, config_options, cfg_sect, outJson)

    return r

# def json_dump(output_array, config_options, cfg_sect, outJson):
#     for opa in output_array:
#         gate = "PASS"
#         ce = opa["Item"]
#         result = opa["Result"]
#         content = ""
#         if result is True and config_options[ce].value is '1' or result is False and config_options[ce].value is '2':
#             gate = "FAIL: " + opa["Reason"]
#             content = opa["Content"]
#         dictn = ast.literal_eval('{"Section": "' + cfg_sect + '",' +
#                                  '"Item": "' + ce + '",' +
#                                  '"Value": "' + config_options[ce].value + '",' +
#                                  '"OID": "' + config_options[ce].oid + '",' +
#                                  '"Content": "' + content + '",' +
#                                  '"OUTPUT": "' + gate + '"}')
#         outJson.append(dictn.copy())
#     return


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

    ('cert_policies', lint_cert_policies),
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
        else:
            print("ERROR - Unrecognized config section:  {}".format(config_section))

    # other_extensions_rows = []
    other_extensions_rows = lint_other_extensions(other_extensions_section, input_cert)

    _lint_cert_newline = lint_cert_newline_reset
    _lint_cert_indent = lint_cert_indent_reset

    return output_rows, other_extensions_rows


def process_one_certificate(cert, profile_file, output_file):

    output_rows, other_extensions_rows = check_cert_conformance(cert, profile_file, "<br>", '&nbsp;&nbsp;&nbsp;&nbsp;')

    strap_start = "<!DOCTYPE html>\n<html>\n<title>CPCT Output</title>\n<xmp theme=\"cerulean\" style=\"display:none;\">\n"
    strap_end = "\n</xmp>\n<script src=\"strapdown.js\"></script>\n</html>\n"

    header = "| **Field** | **Content** | **Analysis** |\n"
    cols = "|:-------- |: ------------------------------------------- |:------------------------------------------------------ |\n"

    output_file.write(strap_start)
    output_file.write(header)
    output_file.write(cols)

    final_sorted_rows = []
    for key, r in conformance_check_functions.items():
        if key in output_rows:
            final_sorted_rows.append(output_rows[key])
    for r in other_extensions_rows:
        final_sorted_rows.append(r)

    for r in final_sorted_rows:
        output_file.write("| **{}** ".format(r.row_name))
        output_file.write("| {} ".format(r.content))
        output_file.write("| {}&nbsp;|\n".format(r.analysis))

    output_file.write(strap_end)


if __name__ == "__main__":

    filePath = "testcerts/test.cer"
    with open(filePath, 'rb') as cert_file:
        encoded = cert_file.read()

    input_cert = None

    try:
        input_cert = parse_cert(encoded)
    except:
        # todo add proper exception handlers
        print("Failed to parse the certificate")

    if input_cert is None:
        exit(0)

    print("\nSubject:\n{}\n".format(get_pretty_dn(input_cert.subject, "\n", "=")))
    print("Issuer:\n{}\n".format(get_pretty_dn(input_cert.issuer, "\n", "=")))

    with open('output/test.html', 'w') as output_file:
        process_one_certificate(input_cert, "devtest", output_file)


    # with open('profiles/template.json') as json_data:
    #     json_profile = json.load(json_data)
    #
    # cert_profile = {}
    #
    # for entry in json_profile:
    #     if entry['Section'] not in cert_profile:
    #         cert_profile[entry['Section']] = {}
    #     pce = config_entry()
    #     pce.value = entry['Value']
    #     pce.oid = entry['OID']
    #     cert_profile[entry['Section']][entry['Item']] = pce
    # outJson = []
    # for cfg_sect in cert_profile:
    #     # print(cfg_sect)
    #     if cfg_sect in conformance_check_functions:
    #         conformance_check_functions[cfg_sect](cert_profile[cfg_sect], input_cert, cfg_sect, outJson)
    #         if "critical" in cert_profile[cfg_sect] and "present" in cert_profile[cfg_sect]: #why critical?
    #             prof_ext_oids.add(cert_profile[cfg_sect]["present"].oid)
    #     elif not cfg_sect == "other_extensions":
    #         print("Invalid config section:  {}".format(cfg_sect))
    # lint_other_extensions(cert_profile["other_extensions"], input_cert, cfg_sect, outJson)
    # #output
    # json.dump(outJson, sys.stdout, indent=2)




