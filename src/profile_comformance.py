from cert_helpers import *
import json
import datetime
import pytz
import glob
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

def _snake_to_camelcase(snake_str):
    components = snake_str.split('_')
    return components[0] + "".join(x.title() for x in components[1:])

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

def _process_more_cert_options(found_set, r, config_options):
    #todo: add content
    for ku in config_options:
        if not ku == 'present' and not ku == 'is_critical':
            camelcase = _snake_to_camelcase(ku)  # alternatively use a map between profile key and display text
            semi = ""
            if ku in found_set:
                if len(found_set[ku]) > 0:
                    semi = ": "
                _lint_cert_add_content_line(r, camelcase + semi + found_set[ku])
            if   ku in found_set and config_options[ku].value == '1':

                    _lint_cert_add_error_to_row(r, "{} is not permitted".format(camelcase))
            elif not ku in found_set and config_options[ku].value == '2':
                _lint_cert_add_error_to_row(r, "{} is required".format(_snake_to_camelcase(ku)))
    return

def lint_name_constraints(config_options, cert):
    r = OutputRow("Name Constraints")
    print("\n--- " + r.row_name + " ---")

    ext_value = cert.name_constraints_value
    _process_common_extension_options(config_options, ext_value,
                                      'name_constraints' in cert.critical_extensions,
                                      r)
    if ext_value is not None:
        found_set = {}

        perm = ext_value['permitted_subtrees']
        if perm:
            i = 1
            s =""
            for item in perm:
                max = item[2].native
                if not max:
                    max = "Max"
                s += "\n\t[{}]Subtree({}..{}): {} Name={}".format(i, item[1].native, max, item[0].name, item[0].native)
                i += 1
            found_set.update({"permitted": s})
        else:
            found_set.update({"permitted": "Permitted None"})

        excl =  ext_value['excluded_subtrees']
        if excl:
            i = 1
            s = ""
            for item in excl:
                max = item[2].native
                if not max:
                    max = "Max"
                s += "\n\t[{}]Subtree({}..{}): {} Name={}".format(i, item[1].native, max, item[0].name,
                                                                    item[0].native)
                i += 1
            found_set.update({"excluded": s})
        else:
            found_set.update({"excluded": "Excluded None"})
        _process_more_cert_options(found_set, r, config_options)

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
            extension_name = e.native['extn_id']
            # todo soemthing more readable
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

    return rows


def lint_policy_mappings(config_options, cert):
    r = OutputRow("Policy Mappings")
    print("\n--- " + r.row_name + " ---")

    ext_value = cert.policy_mappings_value
    _process_common_extension_options(config_options, ext_value, 
                                      'policy_mappings' in cert.critical_extensions,
                                      r)

    if ext_value is not None:
        permitted_policies = None
        if 'permitted' in config_options and len(config_options['permitted'].value) > 0:
            permitted_policies = config_options['permitted'].value.split()
        for policy in ext_value:
            _lint_cert_add_content_line(r, "Issuer Domain={} Subject Domain={}".format(policy.native['issuer_domain_policy']
                                               ,policy.native['subject_domain_policy']))

            if permitted_policies is not None and \
                            policy.native['issuer_domain_policy'] not in permitted_policies: #todo: check permitted value format
                _lint_cert_add_error_to_row(r, "{} is not a permitted".format(policy.native['issuer_domain_policy']))

            if permitted_policies is not None and \
                            policy.native['subject_domain_policy'] not in permitted_policies:
                _lint_cert_add_error_to_row(r, "{} is not a permitted".format(policy.native['subject_domain_policy']))
    return r


def lint_piv_naci(config_options, cert):
    r = OutputRow("PIV NACI")
    print("\n--- " + r.row_name + " ---")

    pivnaci, is_critical = get_extension_from_certificate(cert, '2.16.840.1.101.3.6.9.1')

    _process_common_extension_options(config_options, pivnaci, is_critical, r)

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

    if 'validity_period_generalized_time' in config_options and len(
            config_options['validity_period_generalized_time'].value):
        validity_period_generalized_time = int(config_options['validity_period_generalized_time'].value)

    if validity_period_maximum > 0:
        # lifespan must be less than validity_period_maximum
        max_validity = datetime.timedelta(days=validity_period_maximum)
        if lifespan > max_validity:
            _lint_cert_add_error_to_row(r, "Validity period exceeds {} days".format(str(validity_period_maximum)))

    # todo i think this cutoff code probably doesn't work. the date would likely show up as 1950
    cut_off = datetime.datetime(2050, 1, 1)
    cut_off = cut_off.replace(tzinfo=pytz.UTC)


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

    return r


def lint_subject(config_options, cert):
    r = OutputRow("Subject")
    print("\n--- " + r.row_name + " ---")

    subject = cert['tbs_certificate']['subject']
    r.content = get_pretty_dn(subject, ",{}".format(_lint_cert_newline), "=")

    for ce in config_options:
        if "rdn_" in ce:
            rdn_seq = subject.chosen
            found = False
            for rdn in rdn_seq:
                for name in rdn:
                    if name['type'].dotted == config_options[ce].oid:
                        found = True
                        break
                if found:
                    break
            camelcase = _snake_to_camelcase(ce)

            if found:
                if config_options[ce].value == '1':
                    _lint_cert_add_error_to_row(r, "{} is not permitted".format(camelcase))
            elif config_options[ce].value == '2':
                _lint_cert_add_error_to_row(r, "{} is required".format(camelcase))
        elif ce == "subject_base_dn":
            camelcase = _snake_to_camelcase(ce)
            if 'base_dn' in subject.native:  #todo: dict compare
                c_base_dn_dic = json.dumps(subject.native['base_dn'])
                p_base_dn_dict = json.dumps(config_options[ce].value)
                if not c_base_dn_dic == p_base_dn_dict:
                    _lint_cert_add_error_to_row(r, "{} is required to be matched".format(camelcase))
            elif  len(config_options[ce].value) > 0:
                _lint_cert_add_error_to_row(r, "{} is required".format(camelcase))

    return r


key_usage_display_map = {
    'digital_signature': 'digitalSignature(0)',
    'non_repudiation': 'nonRepudiation(1)',
    'key_encipherment': 'keyEncipherment(2)',
    'data_encipherment': 'dataEncipherment(3)',
    'key_agreement': 'keyAgreement (4)',
    'key_cert_sign': 'keyCertSign(5)',
    'crl_sign': 'cRLSign(6)',
    'encipher_only': 'encipherOnly(7)',
    'decipher_only': 'decipherOnly(8)',
}


def lint_key_usage(config_options, cert):
    r = OutputRow("Key Usage")
    print("\n--- " + r.row_name + " ---")
    
    ext_value = cert.key_usage_value
    _process_common_extension_options(config_options, ext_value, 
                                      'key_usage' in cert.critical_extensions, r)

    if ext_value is not None:

        for ku in cert.key_usage_value.native:
            _lint_cert_add_content_line(r, key_usage_display_map[ku])

            if ku in config_options and config_options[ku].value == '1':
                _lint_cert_add_error_to_row(r, "{} is not permitted".format(key_usage_display_map[ku]))

        for ku in key_usage_display_map.keys():
            if ku in config_options and config_options[ku].value == '2' and ku not in ext_value.native:
                _lint_cert_add_error_to_row(r, "{} is required".format(key_usage_display_map[ku]))

    return r


def lint_issuer(config_options, cert):
    r = OutputRow("Issuer")
    print("\n--- " + r.row_name + " ---")

    issuer = cert.issuer
    r.content = get_pretty_dn(issuer, ",{}".format(_lint_cert_newline), "=")

    for ce in config_options:
        if "rdn_" in ce:
            rdn_seq = issuer.chosen
            found = False
            for rdn in rdn_seq:
                for name in rdn:
                    if name['type'].dotted == config_options[ce].oid:
                        found = True
                        break
                if found:
                    break
            camelcase = _snake_to_camelcase(ce)

            if found:
                if config_options[ce].value == '1':
                    _lint_cert_add_error_to_row(r, "{} is not permitted".format(camelcase))
            elif config_options[ce].value == '2':
                _lint_cert_add_error_to_row(r, "{} is required".format(camelcase))
        elif ce == "issuer_base_dn":
            camelcase = _snake_to_camelcase(ce)
            if 'base_dn' in issuer.native:  #todo: dict compare
                c_base_dn_dic = json.dumps(issuer.native['base_dn'])
                p_base_dn_dict = json.dumps(config_options[ce].value)
                if not c_base_dn_dic == p_base_dn_dict:
                    _lint_cert_add_error_to_row(r, "{} is required to be matched".format(camelcase))
            elif  len(config_options[ce].value) > 0:
                _lint_cert_add_error_to_row(r, "{} is required".format(camelcase))

    return r


def lint_akid(config_options, cert):
    r = OutputRow("Authority Key Id")
    print("\n--- " + r.row_name + " ---")
    ext_value = cert.authority_key_identifier_value
    _process_common_extension_options(config_options, ext_value, 
                                      'authority_key_identifier' in cert.critical_extensions,
                                      r)
    if ext_value is not None:
        kid = ext_value['key_identifier']
        ku = "key_id"
        camelcase = _snake_to_camelcase(ku)
        if kid:
            s = 'KeyID:  {} ({} octets)'.format(' '.join('%02X' % c for c in kid.contents), len(kid.contents))
            _lint_cert_add_content_line(r, s)
            if config_options[ku].value == 1:
                _lint_cert_add_error_to_row(r, "{} is not allowed".format(_snake_to_camelcase(ku)))
        elif config_options[ku].value == 2:
            _lint_cert_add_error_to_row(r, "{} is required".format(camelcase))
        ku = "name_and_serial"
        camelcase = _snake_to_camelcase(ku)
        item = ext_value['authority_cert_serial_number']
        if item: #todo: no example cert
            s = 'Name and Serial:  {} ({} octets)'.format(' '.join('%02X' % c for c in item.contents), len(item.contents))
            _lint_cert_add_content_line(r, s)
            if config_options[ku].value == 1:
                _lint_cert_add_error_to_row(r, "{} is not allowed".format(_snake_to_camelcase(ku)))
        elif config_options[ku].value == 2:
            _lint_cert_add_error_to_row(r, "{} is required".format(camelcase))


    return r


def lint_skid(config_options, cert):
    r = OutputRow("Subject Key Id")
    print("\n--- " + r.row_name + " ---")
    ext_value = cert.key_identifier_value
    _process_common_extension_options(config_options, ext_value, 
                                      'key_identifier' in cert.critical_extensions,
                                      r)

    if ext_value is not None:
        skid = ext_value.native
        _lint_cert_add_content_line(r, 'sha1')
        if not skid == cert['tbs_certificate']['subject_public_key_info'].sha1:
            ku = "require_method_one"
            if config_options[ku].value == '1':
                _lint_cert_add_error_to_row(r, "{} is required".format(_snake_to_camelcase(ku)))


    return r


def lint_policy_constraints(config_options, cert):
    r = OutputRow("Policy Constraints")
    print("\n--- " + r.row_name + " ---")

    ext_value = cert.policy_constraints_value
    _process_common_extension_options(config_options, ext_value, 
                                      'policy_constraints' in cert.critical_extensions,
                                      r)
    
    if ext_value is not None:
        ku = 'require_explicit_policy_present'
        camelcase = _snake_to_camelcase(ku)
        mku = 'require_explicit_policy_max'
        mcamelcase = _snake_to_camelcase(mku)
        rep = ext_value['require_explicit_policy']

        if rep:
            _lint_cert_add_content_line(r, "Require Explicit Policy Skip Certs={}".format(str(rep)))
            if config_options[ku].value == '1':
                _lint_cert_add_error_to_row(r, "{} is not permitted".format(camelcase))
            elif config_options[ku].value == '2':
                max = config_options[mku].value
                if max > 0 and ext_value['require_explicit_policy'] > max:
                    _lint_cert_add_error_to_row(r, "{} is more than maximum permitted".format(mcamelcase))
        elif config_options[ku].value == '2':
            _lint_cert_add_error_to_row(r, "{} is required".format(camelcase))

        ku = 'inhibit_policy_mapping_present'
        camelcase = _snake_to_camelcase(ku)
        mku = 'inhibit_policy_mapping_max'
        mcamelcase = _snake_to_camelcase(mku)
        ipm = ext_value['inhibit_policy_mapping']

        if ipm:
            _lint_cert_add_content_line(r, "Inhibit Policy Mapping Skip Certs={}".format(str(ipm)))
            if config_options[ku].value == '1':
                _lint_cert_add_error_to_row(r, "{} is not permitted".format(camelcase))
            elif config_options[ku].value == '2':
                max = int(config_options[mku].value)
                if max > 0 and ext_value['inhibit_policy_mapping'].native > max:
                    _lint_cert_add_error_to_row(r, "{} is more than maximum permitted".format(mcamelcase))
        elif config_options[ku].value == '2':
            _lint_cert_add_error_to_row(r, "{} is required".format(camelcase))

    return r


def lint_serial_number(config_options, cert):
    r = OutputRow("Serial Number")
    print("\n--- " + r.row_name + " ---")

    serial_number = cert['tbs_certificate']['serial_number'].contents

    # todo we don't care about the length of the string representation of the binary converted to an int.
    # todo the length that matters is the length of the binary.
    # todo i.e. len(cert['tbs_certificate']['serial_number'].contents)
    # todo if the spreadsheet is not clear enough: "No minimum, minimum length (bytes), No max, max length (bytes)"
    # todo then please ask...
    s = '{} ({} octets)'.format(' '.join('%02X' % c for c in serial_number), len(serial_number))
    _lint_cert_add_content_line(r, s)
    ln = len(serial_number)
    ku = 'min_length'
    camelcase = _snake_to_camelcase(ku)
    pln = int(config_options[ku].value)
    if pln > 0 and ln < pln:
        _lint_cert_add_error_to_row(r, "{} is required minimum".format(camelcase))
    ku = 'max_length'
    camelcase = _snake_to_camelcase(ku)
    pln = int(config_options[ku].value)
    if pln > 0 and ln > pln:
        _lint_cert_add_error_to_row(r, "{} is required maximum".format(camelcase))

    return r


def lint_basic_constraints(config_options, cert):
    r = OutputRow("Basic Constraints")
    print("\n--- " + r.row_name + " ---")

    ext_value = cert.basic_constraints_value
    _process_common_extension_options(config_options, ext_value, 
                                      'basic_constraints' in cert.critical_extensions,
                                      r)

    if ext_value is not None:
        ku = 'ca_true'
        camelcase = _snake_to_camelcase(ku)

        if ext_value['ca']:
            _lint_cert_add_content_line(r, "Subject Type=CA")
            if config_options[ku].value == '1':
                _lint_cert_add_error_to_row(r, "{} is not permitted".format(camelcase))
        elif config_options[ku].value == '2':
            _lint_cert_add_error_to_row(r, "{} is required".format(camelcase))

        ku = 'path_length_constraint_req'
        camelcase = _snake_to_camelcase(ku)

        mku = 'path_length_constraint_max'
        mcamelcase = _snake_to_camelcase(mku)
        if ext_value['path_len_constraint']:
            _lint_cert_add_content_line(r, "Path Length Constraint={}".format(ext_value['path_len_constraint']))
            if config_options[ku].value == '1':
                _lint_cert_add_error_to_row(r, "{} is not permitted".format(camelcase))
            elif config_options[ku].value == '2':
                max = int(config_options[mku].value)
                if max > 0 and ext_value['path_len_constraint'].native > max:
                    _lint_cert_add_error_to_row(r, "{} is more than maximum permitted".format(mcamelcase))
        elif config_options[ku].value == '2':
            _lint_cert_add_error_to_row(r, "{} is required".format(camelcase))


    return r


def lint_cert_policies(config_options, cert):
    r = OutputRow("Certificate Policies")
    print("\n--- " + r.row_name + " ---")

    ext_value = cert.certificate_policies_value
    _process_common_extension_options(config_options, ext_value, 
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

    return r


def lint_subject_public_key_info(config_options, cert):
    r = OutputRow("Public Key")
    print("\n--- " + r.row_name + " ---")

    ext_value = cert.public_key

    if ext_value is not None:
        c_oid = ext_value['algorithm'][0].dotted
        if c_oid == "1.2.840.113549.1.1.1":
            if config_options['alg_rsa'].value == '1':
                _lint_cert_add_error_to_row(r, "{} is not permitted".format(_snake_to_camelcase('alg_rsa')))
        elif c_oid == "1.2.840.10045.2.1":
            if config_options['alg_ec'].value == '1':
                _lint_cert_add_error_to_row(r, "{} is not permitted".format(_snake_to_camelcase('alg_ec')))
        elif c_oid == "1.2.840.10040.4.1":
            if config_options['alg_dsa'].value == '1':
                _lint_cert_add_error_to_row(r, "{} is not permitted".format(_snake_to_camelcase('alg_dsa')))
        elif c_oid in config_options['alg_ec_named_curve'].value:
            if config_options['alg_ec_named_curve'].value == '1':
                _lint_cert_add_error_to_row(r, "{} is not permitted".format(_snake_to_camelcase('alg_ec_named_curve')))
        else:
            for ce in config_options:
             if config_options[ce].value == '2' and not ce in set({'max_size', 'min_size'}):
                _lint_cert_add_error_to_row(r, "{} is require".format(_snake_to_camelcase('ce')))
        der_string = 'DER:\n'
        der_string += textwrap.fill(' '.join('%02X' % c for c in ext_value.contents), 43)
        der_string = der_string.replace('\n', _lint_cert_newline)
        _lint_cert_add_content_line(r, der_string)

        ln = ext_value.bit_size
        ku = 'max_size'
        camelcase = _snake_to_camelcase(ku)
        pln = int(config_options[ku].value)
        if pln > 0 and ln > pln:
            _lint_cert_add_error_to_row(r, "{} is required maximum".format(camelcase))
        ku = 'min_size'
        camelcase = _snake_to_camelcase(ku)
        pln = int(config_options[ku].value)
        if pln > 0 and ln < pln:
            _lint_cert_add_error_to_row(r, "{} is required minimum".format(camelcase))

    return r


def lint_aia(config_options, cert):
    r = OutputRow("Authority Info Access")
    print("\n--- " + r.row_name + " ---")

    ext_value = cert.authority_information_access_value
    _process_common_extension_options(config_options, ext_value,
                                      'authority_information_access' in cert.critical_extensions,
                                      r)
    if ext_value is not None:
        found_set = {}
        http_before_ldap = False
        http = False
        for child in ext_value:
            if child['access_method'].native == 'ca_issuers':
                found_set.update({"ca_issuers_present": ""})
                if child['access_location'].name == 'universal_resource_identifier':
                    found_set.update({"ca_issuers_http": child['access_location'].native})
                    http = True
                elif 'ldap://' in child['access_location'].native:
                    found_set.update({"ca_issuers_ldap": child['access_location'].native})
                    if http: #todo check http before ldap logic, https?
                        http_before_ldap = True
                elif 'https://' in child['access_location'].native:
                    found_set.update({"ca_issuers_https": child['access_location'].native})
                    http = True
                elif 'ldaps://' in child['access_location'].native:
                    found_set.update({"ca_issuers_ldaps": child['access_location'].native})
                elif child['access_location'].name == 'dictionary_name':
                    found_set.update({"ca_issuers_directory_name": child['access_location'].native})
            elif child['access_method'].native == 'ocsp':
                found_set.update({"ocsp_present": child['access_location'].native})
                if child['access_location'].name == 'universal_resource_identifier':
                    found_set.update({"ocsp_https": child['access_location'].native})
        if http_before_ldap:
            found_set.update({"ca_issuers_http_before_ldap": ""})
        _process_more_cert_options(found_set, r, config_options)

    return r


def lint_san(config_options, cert):
    r = OutputRow("Subject Alt Name")
    print("\n--- " + r.row_name + " ---")

    ext_value = cert.subject_alt_name_value
    _process_common_extension_options(config_options, ext_value, 
                                      'subject_alt_name' in cert.critical_extensions,
                                      r)

    if ext_value is not None:
        found_set = {}
        for child in ext_value:
            found_set.update({child.name: ""}) #todo: confirm shared keys: other_name_upn, other_name_piv_fasc_n, uniform_resource_identifier_chuid
        _process_more_cert_options(found_set, r, config_options)

    return r


def lint_ian(config_options, cert):
    r = OutputRow("Issuer Alt Name")
    print("\n--- " + r.row_name + " ---")

    ext_value = cert.issuer_alt_name_value
    _process_common_extension_options(config_options, ext_value, 
                                      'issuer_alt_name' in cert.critical_extensions,
                                      r)

    if ext_value is not None:
        found_set = {}
        for child in ext_value:
            found_set.update({child.name: ""}) #todo: confirm shared keys: other_name_upn, other_name_piv_fasc_n, uniform_resource_identifier_chuid
        _process_more_cert_options(found_set, r, config_options)

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

    ext_value = cert.extended_key_usage_value
    _process_common_extension_options(config_options, ext_value, 
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

    return r


def lint_crldp(config_options, cert):
    r = OutputRow("CRL Distribution Points")
    print("\n--- " + r.row_name + " ---")

    ext_value = cert.crl_distribution_points_value
    _process_common_extension_options(config_options, ext_value, 
                                      'crl_distribution_points' in cert.critical_extensions,
                                        r)
    if ext_value is not None:
        found_set = {}
        http_before_ldap = False
        http = False
        for child in ext_value:
            i = 1
            for dp in  child.native['distribution_point']:
                _lint_cert_add_content_line(r,"({}) CRL Distribution Point: {}".format(i, dp))
                if 'ldap://' in dp:
                    found_set.update({"http": dp})
                    http = True
                elif 'ldap://' in dp:
                    found_set.update({"ldap": dp})
                    if http: #todo check http before ldap logic, https?
                        http_before_ldap = True
                elif child['distribution_point'].name == 'dictionary_name':
                    found_set.update({"directory_name": child['distribution_point'].native})

        if http_before_ldap:
            found_set.update({"http_before_ldap": ""})
        _process_more_cert_options(found_set, r, config_options)


    return r


def lint_sia(config_options, cert):
    r = OutputRow("Subject info Access")
    print("\n--- " + r.row_name + " ---")

    ext_value = cert.subject_information_access_value
    _process_common_extension_options(config_options, ext_value, 
                                      'subject_information_access' in cert.critical_extensions,
                                      r)
    if ext_value is not None:
        found_set = {}
        http_before_ldap = False
        http = False
        for child in ext_value:
            if child['access_method'].native == 'ca_repository':
                found_set.update({"ca_repository_present": child['access_location'].native})
                if child['access_location'].name == 'universal_resource_identifier':
                    found_set.update({"ca_repository_http": ""})
                    http = True
                elif 'ldap://' in child['access_location'].native:
                    found_set.update({"ca_repository_ldap": child['access_location'].native})
                    if http: #todo check http before ldap logic, https?
                        http_before_ldap = True
        if http_before_ldap:
            found_set.update({"ca_repository_http_before_ldap": ""})
        _process_more_cert_options(found_set, r, config_options)
    return r


def lint_pkup(config_options, cert):
    r = OutputRow("Private Key Usage Period")
    print("\n--- " + r.row_name + " ---")

    pkup, is_critical = get_extension_from_certificate(cert, '2.5.29.16')

    _process_common_extension_options(config_options, pkup,
                                      is_critical,
                                      r)

    return r


def lint_sub_dir_attr(config_options, cert):
    r = OutputRow("Subject Directory Attributes")
    print("\n--- " + r.row_name + " ---")

    ext_value = cert.subject_directory_attributes_value
    _process_common_extension_options(config_options, ext_value, 
                                      'subject_directory_attributes' in cert.critical_extensions,
                                      r)
    if ext_value:
        s = '{} ({} octets)'.format(' '.join('%02X' % c for c in ext_value.contents), len(ext_value.contents))
        _lint_cert_add_content_line(r, s)

    return r


def lint_signature_algorithm(config_options, cert):
    r = OutputRow("Signature Algorithm")
    print("\n--- " + r.row_name + " ---")

    cert_leaf = cert['signature_algorithm']['algorithm']
    oid = cert_leaf.dotted
    found = False
    for ce in config_options:
        if config_options[ce].oid == oid:
            _lint_cert_add_content_line(r, cert_leaf.native)  # todo: export table content of cert or profile?
            if config_options[ce].value == '1':
                _lint_cert_add_error_to_row(r, "{} is not permitted".format(_snake_to_camelcase(ce)))
            elif not cert['tbs_certificate']['signature']['algorithm'].dotted == oid:
                _lint_cert_add_error_to_row(r, "{} is required to equal to {}".format(_snake_to_camelcase(ce), cert['tbs_certificate']['signature']['algorithm'].dotted))

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

    return r


def lint_ocsp_nocheck(config_options, cert):
    r = OutputRow("OCSP NoCheck")
    print("\n--- " + r.row_name + " ---")

    ext_value = cert.ocsp_no_check_value
    _process_common_extension_options(config_options, ext_value, 
                                      'ocsp_no_check' in cert.critical_extensions,
                                      r)

    return r


def lint_inhibit_any(config_options, cert):
    r = OutputRow("Inhibit Any Policy")
    print("\n--- " + r.row_name + " ---")

    ext_value = cert.inhibit_any_policy_value
    _process_common_extension_options(config_options, ext_value, 
                                      'inhibit_any_policy' in cert.critical_extensions,
                                      r)
    if ext_value:
        s = '{} ({} octets)'.format(' '.join('%02X' % c for c in ext_value.contents), len(ext_value.contents))
        _lint_cert_add_content_line(r, s)
    return r


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


def check_cert_conformance(input_cert, json_profile, end_of_line=None, indent=None):
    if not isinstance(input_cert, x509.Certificate):
        raise TypeError("input_cert must be an x509.Certificate")

    global _lint_cert_newline
    lint_cert_newline_reset = _lint_cert_newline
    global _lint_cert_indent
    lint_cert_indent_reset = _lint_cert_indent
    global _lint_processed_extensions

    if end_of_line is not None:
        _lint_cert_newline = end_of_line

    if indent is not None:
        _lint_cert_indent = indent

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


def process_one_certificate(cert, json_profile, output_file):
    output_rows, other_extensions_rows = check_cert_conformance(cert, json_profile, "<br>", '&nbsp;&nbsp;&nbsp;&nbsp;')

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

# the main setup is to load many profiles and many certs for different testing cases
       for filePath in glob.glob("testcerts/*.cer"):
            #filePath = "testcerts/test.cer"
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

            for profile_file in glob.glob("profiles/*.json"):
                with open(profile_file) as json_data:
                    json_profile = json.load(json_data)
                    with open('output/' + filePath.replace('/', '_') + profile_file.replace('/', '_') + '.html', 'w') as output_file:
                        process_one_certificate(input_cert, json_profile, output_file)
