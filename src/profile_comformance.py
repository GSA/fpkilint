from cert_helpers import *
import json
import datetime
import pytz
import collections

class config_entry:
    def __init__(self):
        self.value = ""
        self.oid = ""


def lint_other_extensions(cfg_options, cert, config_section):
    #cert_leaf = cert. what is this?
    #oid_match(cfg_options, cert_leaf, config_section, oid_list)
    return

def lint_policy_mappings(cfg_options, cert, config_section):
    cert_leaf = cert.policy_mappings_value
    oid_list = []
    oid_match(cfg_options, cert_leaf, config_section, oid_list)
    return


def lint_name_constraints(cfg_options, cert, config_section):
    cert_leaf = cert.name_constraints_value
    oid_list = []
    oid_match(cfg_options, cert_leaf, config_section, oid_list)
    return


def lint_piv_naci(cfg_options, cert, config_section):
    # missing in asn1
    return


def lint_validity(cfg_options, cert, config_section):
    nb = cert['tbs_certificate']['validity']['not_before']
    na = cert['tbs_certificate']['validity']['not_after']
    lifespan = na.native - nb.native
    #r.content += "Valid for {}".format(lifespan)

    cut_off = datetime.datetime(2050, 1, 1)
    cut_off = cut_off.replace(tzinfo=pytz.UTC)

    if nb.name == 'utc_time':
        if nb.native > cut_off:
            print("notBefore is required to be GeneralizedTime")

    return


def lint_subject(cfg_options, cert, config_section):

    if 'base_dn' in  cfg_options and len(cfg_options['base_dn']) > 0:
        # todo: check for base_dn match if base_dn has value
        print("fill in base dn check code")

    cert_leaf = cert.subject
    oid_list = []
    rdn_seq = cert_leaf.chosen
    for rdn in rdn_seq:
         for name in rdn:
              oid_list += [name['type'].dotted]
    oid_match(cfg_options, cert_leaf, config_section, oid_list)

    return


def lint_key_usage(cfg_options, cert, config_section):
    cert_leaf = cert.key_usage_value
    oid_list = []
    oid_match(cfg_options, cert_leaf, config_section, oid_list)
    return


def lint_issuer(cfg_options, cert, config_section):
    cert_leaf = cert.issuer
    oid_list = []
    oid_match(cfg_options, cert_leaf, config_section, oid_list)
    return


def lint_akid(cfg_options, cert, config_section):
    cert_leaf = cert.authority_key_identifier
    oid_list = []
    oid_match(cfg_options, cert_leaf, config_section, oid_list)
    return

def lint_skid(cfg_options, cert, config_section):
    cert_leaf = cert['tbs_certificate']['subject_public_key_info']
    oid_list = []
    oid_match(cfg_options, cert_leaf, config_section, oid_list)
    return

def lint_policy_constraints(cfg_options, cert, config_section):
    cert_leaf = cert.policy_constraints_value
    oid_list = []
    oid_match(cfg_options, cert_leaf, config_section, oid_list)
    return


def lint_serial_number(cfg_options, cert, config_section):
    cert_leaf = cert.serial_number
    oid_list = []
    oid_match(cfg_options, cert_leaf, config_section, oid_list)
    return


def lint_basic_constraints(cfg_options, cert, config_section):
    cert_leaf = cert.basic_constraints_value
    oid_list = []
    oid_match(cfg_options, cert_leaf, config_section, oid_list)
    return


def lint_cert_policies(cfg_options, cert, config_section):
    cert_leaf = cert.certificate_policies_value
    oid_list = [cert_leaf.native[0]['policy_identifier']]
    oid_match(cfg_options, cert_leaf, config_section, oid_list)
    return


def lint_subject_public_key_info(cfg_options, cert, config_section):
    cert_leaf = cert.public_key
    oid_list = []
    oid_match(cfg_options, cert_leaf, config_section, oid_list)
    return


def lint_aia(cfg_options, cert, config_section):
    cert_leaf = cert.authority_information_access_value
    oid_list = []
    oid_match(cfg_options, cert_leaf, config_section, oid_list)
    return


def lint_san(cfg_options, cert, config_section):
    cert_leaf = cert.subject_alt_name_value
    oid_list = []
    oid_match(cfg_options, cert_leaf, config_section, oid_list)
    return


def lint_ian(cfg_options, cert, config_section):
    cert_leaf = cert.issuer_alt_name_value
    oid_list = []
    oid_match(cfg_options, cert_leaf, config_section, oid_list)
    return


def lint_eku(cfg_options, cert, config_section):
    cert_leaf = cert.extended_key_usage_value
    oid_list = []
    oid_match(cfg_options, cert_leaf, config_section, oid_list)
    return


def lint_crldp(cfg_options, cert, config_section):
    cert_leaf = cert.crl_distribution_points
    oid_list = []
    oid_match(cfg_options, cert_leaf, config_section, oid_list)
    return


def lint_sia(cfg_options, cert, config_section):
    cert_leaf = cert.subject_information_access_value
    oid_list = []
    oid_match(cfg_options, cert_leaf, config_section, oid_list)
    return


def lint_pkup(cfg_options, cert, config_section):
    #missing in asn1
    return


def lint_sub_dir_attr(cfg_options, cert, config_section):
    cert_leaf = cert.subject_directory_attributes_value
    oid_list = []
    oid_match(cfg_options, cert_leaf, config_section, oid_list)
    return


def lint_signature_algorithm(cfg_options, cert, config_section):
    cert_leaf = cert['signature_algorithm']['algorithm']
    oid_list = [cert_leaf.dotted]
    oid_match(cfg_options, cert_leaf, config_section, oid_list)
    cert_leaf1 = cert['tbs_certificate']['signature']['algorithm'].dotted
    if not cert_leaf.dotted == cert_leaf1:
        print ("['signature_algorithm']['signature'] and ['tbs_certificate']['signature']['algorithm'] has differnt values: "
            + str(cert_leaf.dotted) + " vs. " + str(cert_leaf1))
    return


def lint_version(cfg_options, cert, config_section):
    cert_leaf = cert['tbs_certificate']['version']
    oid_list = []
    oid_match(cfg_options, cert_leaf, config_section, oid_list)
    return


def lint_ocsp_nocheck(cfg_options, cert, config_section):
    cert_leaf = cert.ocsp_no_check_value
    oid_list = []
    oid_match(cfg_options, cert_leaf, config_section, oid_list)
    return


def lint_inhibit_any(cfg_options, cert, config_section):
    cert_leaf = cert.inhibit_any_policy_value
    oid_list = []
    oid_match(cfg_options, cert_leaf, config_section, oid_list)
    return

def output(result, ce, cfg_opt, config_section, cert_value):
    if result is True and cfg_opt[ce].value is '1' or result is False and cfg_opt[ce].value is '2':
      print("FAIL with  Section: {}, Item: {}, Value: {}, OID: {} and Cert Value: {}"
            .format(config_section, ce, cfg_opt[ce].value, cfg_opt[ce].oid, cert_value))
    else:
      print("PASS with  Section: {}, Item: {}, Value: {}, OID: {} and Cert Value: {}"
            .format(config_section, ce, cfg_opt[ce].value, cfg_opt[ce].oid, cert_value))
    return

def oid_collect(cert_item, list):
    if (hasattr(cert_item, 'chosen')):
        cert_item = cert_item.chosen
        for names in cert_item:
            for name in names:
                list = list + [name['type'].dotted]
    else:
      if hasattr(cert_item, 'dotted'):
        list = list + [cert_item.dotted]
      elif (hasattr(cert_item, '__dict__') and isinstance(cert_item, collections.Iterable)):
        for item in cert_item:
            list = oid_collect(item, list)

    return list

def oid_match(cfg_options, cert_leaf, config_section, oid_list):
    #oid_list = oid_collect(cert_item, [])
    for ce in cfg_options:
       result = False
       for oid in oid_list:
            if oid == cfg_options[ce].oid:
                  result = True
                  cert_value = oid
       output(result, ce, cfg_options, config_section, oid_list)
    return

conformance_check_functions = {
    'Other Extensions': lint_other_extensions,
    'Policy Mappings': lint_policy_mappings,
    'Name Constraints': lint_name_constraints,
    'PIV NACI': lint_piv_naci,
    'Validity': lint_validity,
    'Subject': lint_subject,
    'Issuer': lint_issuer,
    'Authority Key Identifier': lint_akid,
    'Subject Key Identifier': lint_skid,
    'Key Usage': lint_key_usage,
    'Policy Constraints': lint_policy_constraints,
    'Serial Number': lint_serial_number,
    'Basic Constraints': lint_basic_constraints,
    'Certificate Policies': lint_cert_policies,
    'subjectPublicKeyInfo': lint_subject_public_key_info,
    'Authority Information Access': lint_aia,
    'Subject Alternative Name': lint_san,
    'Issuer Alternative Name': lint_ian,
    'Extended Key Usage': lint_eku,
    'CRL Distribution Point': lint_crldp,
    'Subject Information Access': lint_sia,
    'Private Key Usage Period': lint_pkup,
    'Subject Directory Attributes': lint_sub_dir_attr,
    'Signature Algorithm': lint_signature_algorithm,
    'Version': lint_version,
    'OCSP No-Check': lint_ocsp_nocheck,
    'Inhibit Any Policy': lint_inhibit_any
    }


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

    with open('profiles/template.json') as json_data:
        json_profile = json.load(json_data)

    cert_profile = {}

    for entry in json_profile:
        if entry['Section'] not in cert_profile:
            cert_profile[entry['Section']] = {}
        pce = config_entry()
        pce.value = entry['Value']
        pce.oid = entry['OID']
        cert_profile[entry['Section']][entry['Item']] = pce

    for config_section in cert_profile:
        # print(config_section)
        if config_section in conformance_check_functions:
            conformance_check_functions[config_section](cert_profile[config_section], input_cert, config_section)
        else:
            print("Invalid config section:  {}".format(config_section))

