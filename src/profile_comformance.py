from cert_helpers import *
import json
import datetime
import pytz
import sys
import ast
# import ldap


class config_entry:
    def __init__(self):
        self.value = ""
        self.oid = ""

prof_ext_oids = set()

LINT_CERT_NONE = 0
LINT_CERT_OPTIONAL = 0
LINT_CERT_DISALLOWED = 1
LINT_CERT_REQUIRED = 2


def _get_extension_options(cfg_options):
    option_present = LINT_CERT_OPTIONAL
    option_is_critical = LINT_CERT_OPTIONAL

    if 'present' in cfg_options and len(cfg_options['present'].value) > 0:
        option_present = int(cfg_options['present'].value)

    if 'is_critical' in cfg_options and len(cfg_options['is_critical'].value) > 0:
        option_is_critical = int(cfg_options['is_critical'].value)

    return option_present, option_is_critical


def _process_common_extension_options(cfg_options, extension, extension_is_critical, display_name):

    print("\nProcessing {}...".format(display_name))
    option_present, option_is_critical = _get_extension_options(cfg_options)

    if extension is None:
        if option_present is LINT_CERT_REQUIRED:
            print("{} no found".format(display_name))
    else:
        if option_present is LINT_CERT_DISALLOWED:
            print("{} not allowed".format(display_name))
        if option_is_critical is LINT_CERT_REQUIRED and extension_is_critical is False:
            print("{} is not critical".format(display_name))
        if option_is_critical is LINT_CERT_DISALLOWED and extension_is_critical is True:
            print("{} cannot be critical".format(display_name))

        # Content column needs this:
        if extension_is_critical is True:
            print("Critical = TRUE")

    return


def lint_name_contraints(cfg_opt, cert, cfg_sect, outJson):
    output_array = []

    _process_common_extension_options(cfg_opt, cert.name_constraints_value,
                                      'name_constraints' in cert.critical_extensions,
                                      "Name Constraints")

    return


def lint_other_extensions(cfg_opt, cert, cfg_sect, outJson):
    output_array = []
    extensions = cert['tbs_certificate']['extensions']
    cert_ext_oids = set()
    for ext in extensions:
        cert_ext_oids.add(ext['extn_id'].dotted)
    for ce in cfg_opt:
        if ce == "other_non_critical_extensions_present":
                reason = "Other extensions not specifiled in profile is not allowed in certificate"
                output_array.append({"Item": ce, "Result": cert_ext_oids <= prof_ext_oids, "Content": str(cert_ext_oids), "Reason": reason})


    for opa in output_array:
        gate = "PASS"
        ce = opa["Item"]
        result = opa["Result"]
        content = ""
        if result is True and cfg_opt[ce].value is '1' or result is False and (cfg_opt[ce].value is '3' or
            cfg_opt[ce].value is '2') :
            gate = "FAIL: " + opa["Reason"]
            content = opa["Content"]
        dictn = ast.literal_eval('{"Section": "' + cfg_sect + '",' +
                      '"Item": "' + ce + '",' +
                      '"Value": "' + cfg_opt[ce].value + '",' +
                      '"OID": "' + cfg_opt[ce].oid + '",' +
                      '"Content": "' + content + '",' +
                      '"OUTPUT": "' +  gate + '"}')
        outJson.append(dictn.copy())
        # if "present" in ce:
	     #    prof_ext_oids.add(cfg_opt[ce].oid)
    return

def lint_policy_mappings(cfg_opt, cert, cfg_sect, outJson):

    _process_common_extension_options(cfg_opt, cert.policy_mappings_value,
                                      'policy_mappings' in cert.critical_extensions,
                                      "Policy Mappings")

    output_array = []
    extensions = cert['tbs_certificate']['extensions']
    content = False
    oids = []
    c_policies = None
    for e in extensions:
        if e['extn_id'] == 'policy_mappings':
            c_policies = e
            break

    for ce in cfg_opt:
        if ce == "present":
            reason = "Policy Mappings not present in certificate"
            output_array.append({"Item": ce, "Result": not c_policies == None, "Content": e['extn_id'].dotted, "Reason": reason})
        elif ce == "is_critical":
            if not c_policies == None:
               reason = "Policy Mappings ciriticality does not match between profile and certificate"
               output_array.append({"Item": ce, "Result": not c_policies == None, "Content": str(e['critical'].native), "Reason": reason})
        elif ce == "content":
            if not c_policies == None:
              for item in c_policies['extn_value']:
                oids += [item['policy_identifier']]
              if [cfg_opt[ce].oid] <= oids:
                content = True
              reason = "Profile policy mapping content in certificate does not include the one in profile"
              output_array.append({"Item": ce, "Result": content, "Content": oids, "Reason": reason})
    for opa in output_array:
        gate = "PASS"
        ce = opa["Item"]
        result = opa["Result"]
        content = ""
        if result is True and cfg_opt[ce].value is '1' or result is False and (cfg_opt[ce].value is '3' or
            cfg_opt[ce].value is '2') :
            gate = "FAIL: " + opa["Reason"]
            content = opa["Content"]
        dictn = ast.literal_eval('{"Section": "' + cfg_sect + '",' +
                      '"Item": "' + ce + '",' +
                      '"Value": "' + cfg_opt[ce].value + '",' +
                      '"OID": "' + cfg_opt[ce].oid + '",' +
                      '"Content": "' + content + '",' +
                      '"OUTPUT": "' +  gate + '"}')
        outJson.append(dictn.copy())
        # if "present" in ce:
	     #    prof_ext_oids.add(cfg_opt[ce].oid)
    return


def lint_piv_naci(cfg_opt, cert, cfg_sect, outJson):

    pivnaci, is_critical = get_extension_from_certificate(cert, '2.16.840.1.101.3.6.9.1')

    _process_common_extension_options(cfg_opt, pivnaci, is_critical, "PIV NACI")

    # output_array = []
    # extensions = cert['tbs_certificate']['extensions']
    # found = False
    # critical = False
    #
    # for e in extensions:
    #     if e['extn_id'] == cfg_opt["present"].oid:
    #             found = True
    #             break
    #
    #
    # reason = "Profile oid is not in the certificate"
    # output_array.append({"Item": "present", "Result": found, "Content": e['extn_id'].dotted, "Reason": reason})
    # if found:
    #     reason = "extension criticality does not match  between profile and certificate"
    #     output_array.append({"Item": "is_critical", "Result": e['critical'].native, "Content": str(e['critical'].native),"Reason": reason})

    return


def lint_validity(cfg_opt, cert, cfg_sect, outJson):
    output_array = []
    reason = ""
    nb = cert['tbs_certificate']['validity']['not_before']
    na = cert['tbs_certificate']['validity']['not_after']
    lifespan = na.native - nb.native

    cut_off = datetime.datetime(2050, 1, 1)
    cut_off = cut_off.replace(tzinfo=pytz.UTC)

    if nb.name == 'utc_time':
        if nb.native > cut_off:
            reason = "notBefore is required to be GeneralizedTime."

    for ce in cfg_opt:
        if ce == "validity_period_maximum":
            result = lifespan.days < int(cfg_opt[ce].value) or int(cfg_opt[ce].value) == 0
            cert_value = lifespan.days
            reason += " Certificatre life span is less than the one specified in profile."
            output_array.append({"Item": ce, "Result": result, "Content": str(cert_value),"Reason": reason})
        elif ce == "validity_period_generalized_time":
            result = nb.native < cut_off
            cert_value = nb.native
            reason += " Generalized time validaity period is beyond what specified in profile."
            output_array.append({"Item": ce, "Result": result, "Content": str(cert_value),"Reason": reason})
    for opa in output_array:
        gate = "PASS"
        ce = opa["Item"]
        result = opa["Result"]
        content = ""
        if result is True and cfg_opt[ce].value is '1' or result is False and (cfg_opt[ce].value is '3' or
            cfg_opt[ce].value is '2') :
            gate = "FAIL: " + opa["Reason"]
            content = opa["Content"]
        dictn = ast.literal_eval('{"Section": "' + cfg_sect + '",' +
                      '"Item": "' + ce + '",' +
                      '"Value": "' + cfg_opt[ce].value + '",' +
                      '"OID": "' + cfg_opt[ce].oid + '",' +
                      '"Content": "' + content + '",' +
                      '"OUTPUT": "' +  gate + '"}')
        outJson.append(dictn.copy())
        # if "present" in ce:
	     #    prof_ext_oids.add(cfg_opt[ce].oid)
    return


def lint_subject(cfg_opt, cert, cfg_sect, outJson):
    output_array = []
    subject = cert['tbs_certificate']['subject']
    found_base_dn = False
    found = False
    # iterate over all rdn entries
    for ce in cfg_opt:
        if "rdn_" in ce:
            # print(ce + " " + cfg_opt[ce].oid)
            rdn_seq = subject.chosen
            for rdn in rdn_seq:
                for name in rdn:
                    if name['type'].dotted == cfg_opt[ce].oid:
                        found = True
                        break
            reason = "oid does not match in profile and certificate"
            output_array.append({"Item": ce, "Result": found, "Content": str(rdn_seq.native),"Reason": reason})
        elif "subject_base_dn" in ce:
            for rdn in subject.native: # need oid for base_dn to search for oid
                if 'base_dn' in rdn:
                    found_base_dn = True
                    #dn_split = ldap.dn(rdn) todo: compare dn's
                    break
            reason = "base DN not found"
            output_array.append({"Item": "subject_base_dn", "Result": found_base_dn, "Content": str(subject.native), "Reason": reason})

    for opa in output_array:
        gate = "PASS"
        ce = opa["Item"]
        result = opa["Result"]
        content = ""
        if result is True and cfg_opt[ce].value is '1' or result is False and (cfg_opt[ce].value is '3' or
            cfg_opt[ce].value is '2') :
            gate = "FAIL: " + opa["Reason"]
            content = opa["Content"]
        dictn = ast.literal_eval('{"Section": "' + cfg_sect + '",' +
                      '"Item": "' + ce + '",' +
                      '"Value": "' + cfg_opt[ce].value + '",' +
                      '"OID": "' + cfg_opt[ce].oid + '",' +
                      '"Content": "' + content + '",' +
                      '"OUTPUT": "' +  gate + '"}')
        outJson.append(dictn.copy())
        # if "present" in ce:
	     #    prof_ext_oids.add(cfg_opt[ce].oid)
    return


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

def lint_key_usage(cfg_opt, cert, cfg_sect, outJson):

    _process_common_extension_options(cfg_opt, cert.key_usage_value,
                                      'key_usage' in cert.critical_extensions, "Key Usage")

    if cert.key_usage_value is not None:

        for ku in cert.key_usage_value.native:
            # CONTENT
            print(key_usage_display_map[ku])

            if ku in cfg_opt and cfg_opt[ku].value == '1':
                print("{} is not permitted".format(key_usage_display_map[ku]))

        for ku in key_usage_display_map.keys():
            if ku in cfg_opt and cfg_opt[ku].value == '2' and ku not in cert.key_usage_value.native:
                print("{} is required".format(key_usage_display_map[ku]))

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
    #     output_array.append({"Item": "key_agreement", "Result": 'key_agreement' in e['extn_value'].native, "Content": e['extn_id'].dotted, "Reason": reason})
    #     output_array.append({"Item": "key_cert_sign", "Result": 'key_cert_sign' in e['extn_value'].native, "Content": e['extn_id'].dotted, "Reason": reason})
    #     output_array.append({"Item": "crl_sign", "Result": 'crl_sign' in e['extn_value'].native, "Content": e['extn_id'].dotted, "Reason": reason})
    #     output_array.append({"Item": "encipher_only", "Result": 'encipher_only' in e['extn_value'].native, "Content": e['extn_id'].dotted, "Reason": reason})
    #     output_array.append({"Item": "decipher_only", "Result": 'decipher_only' in e['extn_value'].native, "Content": e['extn_id'].dotted, "Reason": reason})
    # for opa in output_array:
    #     gate = "PASS"
    #     ce = opa["Item"]
    #     result = opa["Result"]
    #     content = ""
    #     if result is True and cfg_opt[ce].value is '1' or result is False and (cfg_opt[ce].value is '3' or
    #         cfg_opt[ce].value is '2') :
    #         gate = "FAIL: " + opa["Reason"]
    #         content = opa["Content"]
    #     dictn = ast.literal_eval('{"Section": "' + cfg_sect + '",' +
    #                   '"Item": "' + ce + '",' +
    #                   '"Value": "' + cfg_opt[ce].value + '",' +
    #                   '"OID": "' + cfg_opt[ce].oid + '",' +
    #                   '"Content": "' + content + '",' +
    #                   '"OUTPUT": "' +  gate + '"}')
    #     outJson.append(dictn.copy())
        # if "present" in ce:
	     #    prof_ext_oids.add(cfg_opt[ce].oid)

    return


def lint_issuer(cfg_opt, cert, cfg_sect, outJson):
    output_array = []
    cert_leaf = cert['tbs_certificate']['issuer']
    found_base_dn = False
    found = False
    # iterate over all rdn entries
    for ce in cfg_opt:
        if "rdn_" in ce:
            # print(ce + " " + cfg_opt[ce].oid)
            rdn_seq = cert_leaf.chosen
            for rdn in rdn_seq:
                for name in rdn:
                    if name['type'].dotted == cfg_opt[ce].oid:
                        found = True
                        break
            reason = "oid does not match in profile and certificate"
            output_array.append({"Item": ce, "Result": found, "Content": rdn_seq.native,"Reason": reason})
    for opa in output_array:
        gate = "PASS"
        ce = opa["Item"]
        result = opa["Result"]
        content = ""
        if result is True and cfg_opt[ce].value is '1' or result is False and (cfg_opt[ce].value is '3' or
                                                                                           cfg_opt[ce].value is '2'):
            gate = "FAIL: " + opa["Reason"]
            content = opa["Content"]
        dictn = ast.literal_eval('{"Section": "' + cfg_sect + '",' +
                                    '"Item": "' + ce + '",' +
                                    '"Value": "' + cfg_opt[ce].value + '",' +
                                    '"OID": "' + cfg_opt[ce].oid + '",' +
                                    '"Content": "' + content + '",' +
                                    '"OUTPUT": "' + gate + '"}')
        outJson.append(dictn.copy())
        # if "present" in ce:
        #     prof_ext_oids.add(cfg_opt[ce].oid)
    return


def lint_akid(cfg_opt, cert, cfg_sect, outJson):

    _process_common_extension_options(cfg_opt, cert.authority_key_identifier_value,
                                      'authority_key_identifier' in cert.critical_extensions,
                                      "Authority Key Id")

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
        output_array.append({"Item": "is_critical", "Result": e['critical'].native, "Content": str(e['critical'].native),"Reason": reason})
        #extn_v = '{}'.format('%02X' % c for c in e['extn_value'].native)

        #TODO: two more fields


    for opa in output_array:
        gate = "PASS"
        ce = opa["Item"]
        result = opa["Result"]
        content = ""
        if result is True and cfg_opt[ce].value is '1' or result is False and (cfg_opt[ce].value is '3' or
            cfg_opt[ce].value is '2') :
            gate = "FAIL: " + opa["Reason"]
            content = opa["Content"]
        dictn = ast.literal_eval('{"Section": "' + cfg_sect + '",' +
                      '"Item": "' + ce + '",' +
                      '"Value": "' + cfg_opt[ce].value + '",' +
                      '"OID": "' + cfg_opt[ce].oid + '",' +
                      '"Content": "' + content + '",' +
                      '"OUTPUT": "' +  gate + '"}')
        outJson.append(dictn.copy())
        # if "present" in ce:
	     #    prof_ext_oids.add(cfg_opt[ce].oid)
    return

def lint_skid(cfg_opt, cert, cfg_sect, outJson):

    _process_common_extension_options(cfg_opt, cert.key_identifier_value,
                                      'key_identifier' in cert.critical_extensions,
                                      "Subject Key Id")

    output_array = []
    extensions = cert['tbs_certificate']['extensions']
    found = False
    critical = False
    #cert entry not found

    for e in extensions:
        if e['extn_id'].native == "key_identifier":
                found = True
                break

    reason = "Subject Key Identifier is not present"
    output_array.append({"Item": "present", "Result": found, "Content": e['extn_id'].dotted, "Reason": reason})
    if found:
        reason = "extension criticality does not match between profile and certificate"
        output_array.append({"Item": "is_critical", "Result": e['critical'].native, "Content": str(e['critical'].native),"Reason": reason})
        #extn_v = '{}'.format('%02X' % c for c in e['extn_value'].native)
        skid = cert.key_identifier_value.native
        they_used_method_one = skid == cert['tbs_certificate']['subject_public_key_info'].sha1
        reason = "Method one (sha1) is not allowed"
        output_array.append(
            {"Item": "require_method_one", "Result": they_used_method_one, "Content": str(skid),
             "Reason": reason})
      #todo look further
    for opa in output_array:
        gate = "PASS"
        ce = opa["Item"]
        result = opa["Result"]
        content = ""
        if result is True and cfg_opt[ce].value is '1' or result is False and (cfg_opt[ce].value is '3' or
            cfg_opt[ce].value is '2') :
            gate = "FAIL: " + opa["Reason"]
            content = opa["Content"]
        dictn = ast.literal_eval('{"Section": "' + cfg_sect + '",' +
                      '"Item": "' + ce + '",' +
                      '"Value": "' + cfg_opt[ce].value + '",' +
                      '"OID": "' + cfg_opt[ce].oid + '",' +
                      '"Content": "' + content + '",' +
                      '"OUTPUT": "' +  gate + '"}')
        outJson.append(dictn.copy())
        # if "present" in ce:
	     #    prof_ext_oids.add(cfg_opt[ce].oid)
    return

def lint_policy_constraints(cfg_opt, cert, cfg_sect, outJson):

    _process_common_extension_options(cfg_opt, cert.policy_constraints_value,
                                      'policy_constraints' in cert.critical_extensions,
                                      "Policy Constraints")

    output_array = []
    extensions = cert['tbs_certificate']['extensions']
    found = False
    critical = False

    for e in extensions: #not in cert, mimicing aia
        if e['extn_id'].native == "policy_constraints":
                found = True
                break

    reason = "Profile oid is not in the certificate"
    output_array.append({"Item": "present", "Result": found, "Content": e['extn_id'].dotted, "Reason": reason})
    if found:
        reason = "extension criticality does not match between profile and certificate"
        output_array.append({"Item": "is_critical", "Result": e['critical'].native, "Content": str(e['critical'].native),"Reason": reason})

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

                #todo: need cert example

    
    for opa in output_array:
        gate = "PASS"
        ce = opa["Item"]
        result = opa["Result"]
        content = ""
        if result is True and cfg_opt[ce].value is '1' or result is False and (cfg_opt[ce].value is '3' or
            cfg_opt[ce].value is '2') :
            gate = "FAIL: " + opa["Reason"]
            content = opa["Content"]
        dictn = ast.literal_eval('{"Section": "' + cfg_sect + '",' +
                      '"Item": "' + ce + '",' +
                      '"Value": "' + cfg_opt[ce].value + '",' +
                      '"OID": "' + cfg_opt[ce].oid + '",' +
                      '"Content": "' + content + '",' +
                      '"OUTPUT": "' +  gate + '"}')
        outJson.append(dictn.copy())
        # if "present" in ce:
	     #    prof_ext_oids.add(cfg_opt[ce].oid)
    return


def lint_serial_number(cfg_opt, cert, cfg_sect, outJson):
    output_array = []
    cert_leaf = cert['tbs_certificate']['serial_number'].native
    ln = len(str(cert_leaf))
    pln = int(cfg_opt["min_length"].value)
    reason = "Certficate serial number length is less than profile specifiled minimum length"
    output_array.append({"Item": "min_length", "Result": pln == 0 or ln > pln, "Content": str(cert_leaf), "Reason": reason})
    pln = int(cfg_opt["max_length"].value)
    reason = "Certficate serial number length is more than profile specifiled maximum length"
    output_array.append({"Item": "max_length", "Result": pln == 0 or ln < pln, "Content": str(cert_leaf), "Reason": reason})
    
    for opa in output_array:
        gate = "PASS"
        ce = opa["Item"]
        result = opa["Result"]
        content = ""
        if not result :
            gate = "FAIL: " + opa["Reason"]
            content = opa["Content"]
        dictn = ast.literal_eval('{"Section": "' + cfg_sect + '",' +
                      '"Item": "' + ce + '",' +
                      '"Value": "' + cfg_opt[ce].value + '",' +
                      '"OID": "' + cfg_opt[ce].oid + '",' +
                      '"Content": "' + content + '",' +
                      '"OUTPUT": "' +  gate + '"}')
        outJson.append(dictn.copy())
        # if "present" in ce:
	     #    prof_ext_oids.add(cfg_opt[ce].oid)
    return


def lint_basic_constraints(cfg_opt, cert, cfg_sect, outJson):

    _process_common_extension_options(cfg_opt, cert.basic_constraints_value,
                                      'basic_constraints' in cert.critical_extensions,
                                      "Basic Constraints")

    output_array = []
    extensions = cert['tbs_certificate']['extensions']
    found = False
    critical = False

    for e in extensions: #not in cert, mimicing aia
        if e['extn_id'].native == "basic_constraints":
                found = True
                break

    reason = "Profile oid is not in the certificate"
    output_array.append({"Item": "present", "Result": found, "Content": e['extn_id'].dotted, "Reason": reason})
    if found:
        reason = "extension criticality does not match between profile and certificate"
        output_array.append({"Item": "is_critical", "Result": e['critical'].native, "Content": str(e['critical'].native),"Reason": reason})


        #todo: need cert example

    
    for opa in output_array:
        gate = "PASS"
        ce = opa["Item"]
        result = opa["Result"]
        content = ""
        if result is True and cfg_opt[ce].value is '1' or result is False and (cfg_opt[ce].value is '3' or
            cfg_opt[ce].value is '2') :
            gate = "FAIL: " + opa["Reason"]
            content = opa["Content"]
        dictn = ast.literal_eval('{"Section": "' + cfg_sect + '",' +
                      '"Item": "' + ce + '",' +
                      '"Value": "' + cfg_opt[ce].value + '",' +
                      '"OID": "' + cfg_opt[ce].oid + '",' +
                      '"Content": "' + content + '",' +
                      '"OUTPUT": "' +  gate + '"}')
        outJson.append(dictn.copy())
        # if "present" in ce:
	     #    prof_ext_oids.add(cfg_opt[ce].oid)
    return


def lint_cert_policies(cfg_opt, cert, cfg_sect, outJson):

    _process_common_extension_options(cfg_opt, cert.certificate_policies_value,
                                      'certificate_policies' in cert.critical_extensions,
                                      "Certificate Policies")

    output_array = []
    extensions = cert['tbs_certificate']['extensions']
    content = False
    oids = set()
    c_policies = None
    for e in extensions:
        if e['extn_id'].native == 'certificate_policies':
            c_policies = e
            break

    for ce in cfg_opt:
        if ce == "present":
            reason = "certificate policies not present"
            output_array.append({"Item": ce, "Result": not c_policies == None, "Content": e['extn_id'].dotted, "Reason": reason})
        elif ce == "is_critical":
            if not c_policies == None:
               reason = "certificate policies is not critical"
               output_array.append({"Item": ce, "Result": c_policies['critical'], "Content": str(c_policies['critical']), "Reason": reason})
        elif ce == "content":
            if not c_policies == None:
              for item in c_policies['extn_value'].native:
                oids.add(item['policy_identifier'])
              if cfg_opt[ce].oid in oids:
                content = True
              reason = "profile policy oid is not in the certificate"
              output_array.append({"Item": ce, "Result": content, "Content": str(oids), "Reason": reason})
    
    for opa in output_array:
        gate = "PASS"
        ce = opa["Item"]
        result = opa["Result"]
        content = ""
        if result is True and cfg_opt[ce].value is '1' or result is False and (cfg_opt[ce].value is '3' or
            cfg_opt[ce].value is '2') :
            gate = "FAIL: " + opa["Reason"]
            content = opa["Content"]
        dictn = ast.literal_eval('{"Section": "' + cfg_sect + '",' +
                      '"Item": "' + ce + '",' +
                      '"Value": "' + cfg_opt[ce].value + '",' +
                      '"OID": "' + cfg_opt[ce].oid + '",' +
                      '"Content": "' + content + '",' +
                      '"OUTPUT": "' +  gate + '"}')
        outJson.append(dictn.copy())
        # if "present" in ce:
	     #    prof_ext_oids.add(cfg_opt[ce].oid)
    return


def lint_subject_public_key_info(cfg_opt, cert, cfg_sect, outJson):
    output_array = []
    cert_leaf = cert['tbs_certificate']['subject_public_key_info']
    algo = cert_leaf['algorithm']['algorithm'].dotted
    found = False
    for ce in cfg_opt:
        if cfg_opt[ce].oid == algo:
            found = True
            break
    reason = "Profile oid is not in the certificate"
    output_array.append({"Item": ce, "Result": found, "Content": algo, "Reason": reason})

    blen = cert_leaf['public_key'].native['modulus'].bit_length()

    reason = "certificate public key size is less than prfoile minimum key size"
    output_array.append({"Item": "min_size", "Result": blen > int(cfg_opt['min_size'].value), "Content": str(blen), "Reason": reason})
    reason = "certificate public key size is more than prfoile maximum key size"
    output_array.append({"Item": "max_size", "Result": blen < int(cfg_opt['max_size'].value), "Content": str(blen), "Reason": reason})
    
    for opa in output_array:
        gate = "PASS"
        ce = opa["Item"]
        result = opa["Result"]
        content = ""
        if result is True and cfg_opt[ce].value is '1' or result is False and (cfg_opt[ce].value is '3' or
            cfg_opt[ce].value is '2') :
            gate = "FAIL: " + opa["Reason"]
            content = opa["Content"]
        dictn = ast.literal_eval('{"Section": "' + cfg_sect + '",' +
                      '"Item": "' + ce + '",' +
                      '"Value": "' + cfg_opt[ce].value + '",' +
                      '"OID": "' + cfg_opt[ce].oid + '",' +
                      '"Content": "' + content + '",' +
                      '"OUTPUT": "' +  gate + '"}')
        outJson.append(dictn.copy())
        # if "present" in ce:
	     #    prof_ext_oids.add(cfg_opt[ce].oid)
    return


def lint_aia(cfg_opt, cert, cfg_sect, outJson):

    _process_common_extension_options(cfg_opt, cert.authority_information_access_value,
                                      'authority_information_access' in cert.critical_extensions,
                                      "Authority Info Access")

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
        output_array.append({"Item": "is_critical", "Result": e['critical'].native, "Content": str(e['critical'].native),"Reason": reason})
        ca_issuers_present = False
        ocsp_present = False
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
                ocsp_present = True
                if 'http' in item['access_location']:
                    ocsp_http = True

        reason = "ca_repository_present not present"
        output_array.append({"Item": "ca_issuers_present", "Result": ca_issuers_present, "Content": item['access_method'],"Reason": reason})

        reason = "AIA CA Repository HTTP is not found"
        output_array.append({"Item": "ca_issuers_http", "Result": http_found, "Content": item['access_method'],"Reason": reason})

        reason = "AIA CA Repository LDAP is not found"
        output_array.append({"Item": "ca_issuers_ldap", "Result": http_found, "Content": item['access_method'],"Reason": reason})

        reason = "AIA CA Repository LDAP is before HTTP"
        output_array.append({"Item": "ca_issuers_http_before_ldap", "Result": http_found, "Content": item['access_method'],"Reason": reason})

        reason = "AIA OCSP not present"
        output_array.append({"Item": "ocsp_present", "Result": http_found, "Content": item['access_method'],"Reason": reason})

        reason = "AIA OCSP HTTP is not found"
        output_array.append({"Item": "ocsp_https", "Result": http_found, "Content": item['access_method'],"Reason": reason})

#todo, cert example: "ca_issuers_directory_name"

    
    for opa in output_array:
        gate = "PASS"
        ce = opa["Item"]
        result = opa["Result"]
        content = ""
        if result is True and cfg_opt[ce].value is '1' or result is False and (cfg_opt[ce].value is '3' or
            cfg_opt[ce].value is '2') :
            gate = "FAIL: " + opa["Reason"]
            content = opa["Content"]
        dictn = ast.literal_eval('{"Section": "' + cfg_sect + '",' +
                      '"Item": "' + ce + '",' +
                      '"Value": "' + cfg_opt[ce].value + '",' +
                      '"OID": "' + cfg_opt[ce].oid + '",' +
                      '"Content": "' + content + '",' +
                      '"OUTPUT": "' +  gate + '"}')
        outJson.append(dictn.copy())
        # if "present" in ce:
	     #    prof_ext_oids.add(cfg_opt[ce].oid)

    return


def lint_san(cfg_opt, cert, cfg_sect, outJson):

    _process_common_extension_options(cfg_opt, cert.subject_alt_name_value,
                                      'subject_alt_name' in cert.critical_extensions,
                                      "Subject Alt Name")

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
        output_array.append({"Item": "is_critical", "Result": e['critical'].native, "Content": str(e['critical'].native),"Reason": reason})

        #c_oid = e['extn_value'].native[0]['type_id']
        c_oid = "1.2.3.4.5"
        reason = "Profile oid does not match the one in the certificate"
        output_array.append({"Item": "rfc822_name", "Result": c_oid == cfg_opt['rfc822_name'].oid, "Content": c_oid, "Reason": reason})
        output_array.append({"Item": "x400_address", "Result": c_oid == cfg_opt['x400_address'].oid, "Content": c_oid, "Reason": reason})
        output_array.append({"Item": "directory_name", "Result": c_oid == cfg_opt['directory_name'].oid, "Content": c_oid, "Reason": reason})
        output_array.append({"Item": "edi_party_name", "Result": c_oid == cfg_opt['edi_party_name'].oid, "Content": c_oid, "Reason": reason})
        output_array.append({"Item": "uniform_resource_identifier", "Result": c_oid == cfg_opt['uniform_resource_identifier'].oid, "Content": c_oid, "Reason": reason})
        output_array.append({"Item": "ip_address", "Result": c_oid == cfg_opt['ip_address'].oid, "Content": c_oid, "Reason": reason})
        output_array.append({"Item": "registered_id", "Result": c_oid == cfg_opt['registered_id'].oid, "Content": c_oid, "Reason": reason})
        output_array.append({"Item": "other_name_upn", "Result": c_oid == cfg_opt['other_name_upn'].oid, "Content": c_oid, "Reason": reason})
        output_array.append({"Item": "other_name_piv_fasc_n", "Result": c_oid == cfg_opt['other_name_piv_fasc_n'].oid, "Content": c_oid, "Reason": reason})
        output_array.append({"Item": "uniform_resource_identifier_chuid", "Result": c_oid == cfg_opt['uniform_resource_identifier_chuid'].oid, "Content": c_oid, "Reason": reason})
    
    for opa in output_array:
        gate = "PASS"
        ce = opa["Item"]
        result = opa["Result"]
        content = ""
        if result is True and cfg_opt[ce].value is '1' or result is False and (cfg_opt[ce].value is '3' or
            cfg_opt[ce].value is '2') :
            gate = "FAIL: " + opa["Reason"]
            content = opa["Content"]
        dictn = ast.literal_eval('{"Section": "' + cfg_sect + '",' +
                      '"Item": "' + ce + '",' +
                      '"Value": "' + cfg_opt[ce].value + '",' +
                      '"OID": "' + cfg_opt[ce].oid + '",' +
                      '"Content": "' + content + '",' +
                      '"OUTPUT": "' +  gate + '"}')
        outJson.append(dictn.copy())
        # if "present" in ce:
	     #    prof_ext_oids.add(cfg_opt[ce].oid)

    return


def lint_ian(cfg_opt, cert, cfg_sect, outJson):

    _process_common_extension_options(cfg_opt, cert.issuer_alt_name_value,
                                      'issuer_alt_name' in cert.critical_extensions,
                                      "Issuer Alt Name")

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
        output_array.append({"Item": "is_critical", "Result": e['critical'].native, "Content": str(e['critical'].native),"Reason": reason})

        c_oid = e['extn_value'].native[0]['type_id']
        reason = "Profile oid does not match the one in the certificate"
        output_array.append({"Item": "rfc822_name", "Result": c_oid == cfg_opt['rfc822_name'].oid, "Content": c_oid, "Reason": reason})
        output_array.append({"Item": "x400_address", "Result": c_oid == cfg_opt['x400_address'].oid, "Content": c_oid, "Reason": reason})
        output_array.append({"Item": "directory_name", "Result": c_oid == cfg_opt['directory_name'].oid, "Content": c_oid, "Reason": reason})
        output_array.append({"Item": "edi_party_name", "Result": c_oid == cfg_opt['edi_party_name'].oid, "Content": c_oid, "Reason": reason})
        output_array.append({"Item": "uniform_resource_identifier", "Result": c_oid == cfg_opt['uniform_resource_identifier'].oid, "Content": c_oid, "Reason": reason})
        output_array.append({"Item": "ip_address", "Result": c_oid == cfg_opt['ip_address'].oid, "Content": c_oid, "Reason": reason})
        output_array.append({"Item": "registered_id", "Result": c_oid == cfg_opt['registered_id'].oid, "Content": c_oid, "Reason": reason})
        output_array.append({"Item": "other_name", "Result": c_oid == cfg_opt['other_name'].oid, "Content": c_oid, "Reason": reason})
        output_array.append({"Item": "dns_name", "Result": c_oid == cfg_opt['dns_name'].oid, "Content": c_oid, "Reason": reason})
        output_array.append({"Item": "other_name_piv_fasc_n", "Result": c_oid == cfg_opt['other_name_piv_fasc_n'].oid, "Content": c_oid, "Reason": reason})
        output_array.append({"Item": "uniform_resource_identifier_chuid", "Result": c_oid == cfg_opt['uniform_resource_identifier_chuid'].oid, "Content": c_oid, "Reason": reason})
    
    for opa in output_array:
        gate = "PASS"
        ce = opa["Item"]
        result = opa["Result"]
        content = ""
        if result is True and cfg_opt[ce].value is '1' or result is False and (cfg_opt[ce].value is '3' or
            cfg_opt[ce].value is '2') :
            gate = "FAIL: " + opa["Reason"]
            content = opa["Content"]
        dictn = ast.literal_eval('{"Section": "' + cfg_sect + '",' +
                      '"Item": "' + ce + '",' +
                      '"Value": "' + cfg_opt[ce].value + '",' +
                      '"OID": "' + cfg_opt[ce].oid + '",' +
                      '"Content": "' + content + '",' +
                      '"OUTPUT": "' +  gate + '"}')
        outJson.append(dictn.copy())
        # if "present" in ce:
	     #    prof_ext_oids.add(cfg_opt[ce].oid)

    return


def _do_presence_test(cfg_options, cfg_str, display_str, is_present):

    error_string = None

    if cfg_str in cfg_options and len(cfg_options[cfg_str].value) > 0:
        if cfg_options[cfg_str].value == '1' and is_present is True:
            error_string = "is not allowed"
        if cfg_options[cfg_str].value == '2' and is_present is False:
            error_string = "was not found"

    if error_string is not None:
        error_string = "{} {}".format(display_str, error_string)

    return error_string


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


def lint_eku(cfg_opt, cert, cfg_sect, outJson):

    _process_common_extension_options(cfg_opt, cert.extended_key_usage_value,
                                      'extended_key_usage' in cert.critical_extensions,
                                      "Extended Key Usage")

    if cert.extended_key_usage_value is not None:

        eku_oids = []
        for eku in cert.extended_key_usage_value:
            eku_oids.append(eku.dotted)
            print("{} ({})".format(eku_display_map.get(eku.dotted, "Unknown EKU"), eku.dotted))

        for ce in cfg_opt:
            if "oid_" in ce:
                error_string = _do_presence_test(cfg_opt, ce,
                                  eku_display_map.get(cfg_opt[ce].oid, "Unknown EKU"),
                                                 cfg_opt[ce].oid in eku_oids)
                if error_string is not None:
                    print(error_string)

    #
    #
    #
    #
    #
    #
    #
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
    #     output_array.append({"Item": "oid_server_auth", "Result": c_oid == cfg_opt['oid_server_auth'].oid, "Content": c_oid, "Reason": reason})
    #     output_array.append({"Item": "oid_client_auth", "Result": c_oid == cfg_opt['oid_client_auth'].oid, "Content": c_oid, "Reason": reason})
    #     output_array.append({"Item": "oid_code_signing", "Result": c_oid == cfg_opt['oid_code_signing'].oid, "Content": c_oid, "Reason": reason})
    #     output_array.append({"Item": "oid_email_protection", "Result": c_oid == cfg_opt['oid_email_protection'].oid, "Content": c_oid, "Reason": reason})
    #     output_array.append({"Item": "oid_time_stamping", "Result": c_oid == cfg_opt['oid_time_stamping'].oid, "Content": c_oid, "Reason": reason})
    #     output_array.append({"Item": "oid_ocsp_signing", "Result": c_oid == cfg_opt['oid_ocsp_signing'].oid, "Content": c_oid, "Reason": reason})
    #     output_array.append({"Item": "oid_any_eku", "Result": c_oid == cfg_opt['oid_any_eku'].oid, "Content": c_oid, "Reason": reason})
    #     output_array.append({"Item": "oid_smart_card_logon", "Result": c_oid == cfg_opt['oid_smart_card_logon'].oid, "Content": c_oid, "Reason": reason})
    #     output_array.append({"Item": "oid_ipsec_ike_intermediate", "Result": c_oid == cfg_opt['oid_ipsec_ike_intermediate'].oid, "Content": c_oid, "Reason": reason})
    #     output_array.append({"Item": "oid_ipsec_end_system", "Result": c_oid == cfg_opt['oid_ipsec_end_system'].oid, "Content": c_oid, "Reason": reason})
    #     output_array.append({"Item": "oid_ipsec_tunnel_termination", "Result": c_oid == cfg_opt['oid_ipsec_tunnel_termination'].oid, "Content": c_oid, "Reason": reason})
    #     output_array.append({"Item": "oid_ipsec_user", "Result": c_oid == cfg_opt['oid_ipsec_user'].oid, "Content": c_oid, "Reason": reason})
    #     output_array.append({"Item": "oid_piv_card_auth", "Result": c_oid == cfg_opt['oid_piv_card_auth'].oid, "Content": c_oid, "Reason": reason})
    #     output_array.append({"Item": "oid_pivi_content_signing", "Result": c_oid == cfg_opt['oid_pivi_content_signing'].oid, "Content": c_oid, "Reason": reason})
    #     output_array.append({"Item": "oid_smartCardLogon", "Result": c_oid == cfg_opt['oid_smartCardLogon'].oid, "Content": c_oid, "Reason": reason})
    #     output_array.append({"Item": "oid_pkinit_KPKdc", "Result": c_oid == cfg_opt['oid_pkinit_KPKdc'].oid, "Content": c_oid, "Reason": reason})
    #     output_array.append({"Item": "oid_pkinit_KPClientAuth", "Result": c_oid == cfg_opt['oid_pkinit_KPClientAuth'].oid, "Content": c_oid, "Reason": reason})
    #     output_array.append({"Item": "other", "Result": c_oid == cfg_opt['other'].oid, "Content": c_oid, "Reason": reason})
    #
    # for opa in output_array:
    #     gate = "PASS"
    #     ce = opa["Item"]
    #     result = opa["Result"]
    #     content = ""
    #     if result is True and cfg_opt[ce].value is '1' or result is False and (cfg_opt[ce].value is '3' or
    #         cfg_opt[ce].value is '2') :
    #         gate = "FAIL: " + opa["Reason"]
    #         content = opa["Content"]
    #     dictn = ast.literal_eval('{"Section": "' + cfg_sect + '",' +
    #                   '"Item": "' + ce + '",' +
    #                   '"Value": "' + cfg_opt[ce].value + '",' +
    #                   '"OID": "' + cfg_opt[ce].oid + '",' +
    #                   '"Content": "' + content + '",' +
    #                   '"OUTPUT": "' +  gate + '"}')
    #     outJson.append(dictn.copy())
        # if "present" in ce:
	     #    prof_ext_oids.add(cfg_opt[ce].oid)

    return


def lint_crldp(cfg_opt, cert, cfg_sect, outJson):

    _process_common_extension_options(cfg_opt, cert.crl_distribution_points_value,
                                      'crl_distribution_points' in cert.critical_extensions,
                                      "CRL Distribution Points")
    output_array = []
    extensions = cert['tbs_certificate']['extensions']
    found = False
    http = False
    ldap = False
    ocsp_present = False
    http_before_ldap = False
    ocsp_http = False
    for e in extensions:
        if e['extn_id'].native == "crl_distribution_points":
                found = True
                break

    reason = "Profile oid is not in the certificate"
    output_array.append({"Item": "present", "Result": found, "Content": e['extn_id'].dotted, "Reason": reason})
    if found:
        reason = "extension criticality does not match  between profile and certificate"
        output_array.append({"Item": "is_critical", "Result": e['critical'].native, "Content": str(e['critical'].native),"Reason": reason})

        for item in e['extn_value'].native:
            if "http" in str(item['distribution_point']):
                http = True #search oid?
            if "ldap" in str(item['distribution_point']):
                ldap = True
                if http:
                    http_before_ldap = True
            # elif dn tell dn

        reason = "CRL Dirstribution Point HTTP is not found"
        output_array.append({"Item": "http", "Result": http, "Content": item['distribution_point'][0],"Reason": reason})

        reason = "CRL Dirstribution Point LDAP is not found"
        output_array.append({"Item": "ldap", "Result": ldap, "Content": item['distribution_point'][0],"Reason": reason})

        reason = "CRL Dirstribution Point LDAP is before HTTP"
        output_array.append({"Item": "http_before_ldap", "Result": http_before_ldap, "Content": item['distribution_point'][0],"Reason": reason})

        # todo, cert example: "directory_name"

    
    for opa in output_array:
        gate = "PASS"
        ce = opa["Item"]
        result = opa["Result"]
        content = ""
        if result is True and cfg_opt[ce].value is '1' or result is False and (cfg_opt[ce].value is '3' or
            cfg_opt[ce].value is '2') :
            gate = "FAIL: " + opa["Reason"]
            content = opa["Content"]
        dictn = ast.literal_eval('{"Section": "' + cfg_sect + '",' +
                      '"Item": "' + ce + '",' +
                      '"Value": "' + cfg_opt[ce].value + '",' +
                      '"OID": "' + cfg_opt[ce].oid + '",' +
                      '"Content": "' + content + '",' +
                      '"OUTPUT": "' +  gate + '"}')
        outJson.append(dictn.copy())
        # if "present" in ce:
	     #    prof_ext_oids.add(cfg_opt[ce].oid)

    return

def lint_sia(cfg_opt, cert, cfg_sect, outJson):

    _process_common_extension_options(cfg_opt, cert.subject_information_access_value,
                                      'subject_information_access' in cert.critical_extensions,
                                      "Subject info Access")

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
        output_array.append({"Item": "is_critical", "Result": e['critical'].native, "Content": str(e['critical'].native),"Reason": reason})

        ca_repository_present = False
        ocsp_present = False
        http_found = False
        ldap_found = False
        http_before_ldap = False
        ocsp_http = False
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
        output_array.append({"Item": "ca_repository_present", "Result": ca_repository_present, "Content": item['access_method'],"Reason": reason})

        reason = "SIA CA Repository HTTP is not found"
        output_array.append({"Item": "ca_repository_http", "Result": http_found, "Content": item['access_method'],"Reason": reason})

        reason = "SIA CA Repository LDAP is not found"
        output_array.append({"Item": "ca_repository_ldap", "Result": http_found, "Content": item['access_method'],"Reason": reason})

        reason = "SIA CA Repository LDAP is before HTTP"
        output_array.append({"Item": "ca_repository_http_before_ldap", "Result": http_found, "Content": item['access_method'],"Reason": reason})


    
    for opa in output_array:
        gate = "PASS"
        ce = opa["Item"]
        result = opa["Result"]
        content = ""
        if result is True and cfg_opt[ce].value is '1' or result is False and (cfg_opt[ce].value is '3' or
            cfg_opt[ce].value is '2') :
            gate = "FAIL: " + opa["Reason"]
            content = opa["Content"]
        dictn = ast.literal_eval('{"Section": "' + cfg_sect + '",' +
                      '"Item": "' + ce + '",' +
                      '"Value": "' + cfg_opt[ce].value + '",' +
                      '"OID": "' + cfg_opt[ce].oid + '",' +
                      '"Content": "' + content + '",' +
                      '"OUTPUT": "' +  gate + '"}')
        outJson.append(dictn.copy())
        # if "present" in ce:
	     #    prof_ext_oids.add(cfg_opt[ce].oid)
    return


def lint_pkup(cfg_opt, cert, cfg_sect, outJson):

    pkup, is_critical = get_extension_from_certificate(cert, '2.5.29.16')

    _process_common_extension_options(cfg_opt, pkup,
                                      is_critical,
                                      "Private Key Usage Period")

    output_array = []
    extensions = cert['tbs_certificate']['extensions']
    found = False
    critical = False

    oids = []
    for e in extensions: #not in cert, mimicing aia
        oids.append(e['extn_id'].dotted)
        if e['extn_id'].native == "private_key_usage_period":
                found = True
                break

    reason = "Profile oid is not in the certificate"
    output_array.append({"Item": "present", "Result": found, "Content": str(oids),"Reason": reason})

    if found:
        reason = "extension criticality does not match  between profile and certificate"
        output_array.append({"Item": "is_critical", "Result": e['critical'].native, "Content": str(e['critical'].native),"Reason": reason})
    
    for opa in output_array:
        gate = "PASS"
        ce = opa["Item"]
        result = opa["Result"]
        content = ""
        if result is True and cfg_opt[ce].value is '1' or result is False and (cfg_opt[ce].value is '3' or
            cfg_opt[ce].value is '2') :
            gate = "FAIL: " + opa["Reason"]
            content = opa["Content"]
        dictn = ast.literal_eval('{"Section": "' + cfg_sect + '",' +
                      '"Item": "' + ce + '",' +
                      '"Value": "' + cfg_opt[ce].value + '",' +
                      '"OID": "' + cfg_opt[ce].oid + '",' +
                      '"Content": "' + content + '",' +
                      '"OUTPUT": "' +  gate + '"}')
        outJson.append(dictn.copy())
        # if "present" in ce:
	     #    prof_ext_oids.add(cfg_opt[ce].oid)
    return


def lint_sub_dir_attr(cfg_opt, cert, cfg_sect, outJson):

    _process_common_extension_options(cfg_opt, cert.subject_directory_attributes_value,
                                      'subject_directory_attributes' in cert.critical_extensions,
                                      "Subject Directory Attributes")

    output_array = []
    extensions = cert['tbs_certificate']['extensions']
    found = False

    oids = []
    for e in extensions: #not in cert, mimicing aia
        oids.append(e['extn_id'].dotted)
        if e['extn_id'].native == "subject_directory_attribute":
                found = True
                break

    reason = "Profile oid is not in the certificate"
    output_array.append({"Item": "present", "Result": found, "Content": str(oids),"Reason": reason})

    if found:
        reason = "extension criticality does not match  between profile and certificate"
        output_array.append({"Item": "is_critical", "Result": e['critical'].native, "Content": str(e['critical'].native),"Reason": reason})

    
    for opa in output_array:
        gate = "PASS"
        ce = opa["Item"]
        result = opa["Result"]
        content = ""
        if result is True and cfg_opt[ce].value is '1' or result is False and (cfg_opt[ce].value is '3' or
            cfg_opt[ce].value is '2') :
            gate = "FAIL: " + opa["Reason"]
            content = opa["Content"]
        dictn = ast.literal_eval('{"Section": "' + cfg_sect + '",' +
                      '"Item": "' + ce + '",' +
                      '"Value": "' + cfg_opt[ce].value + '",' +
                      '"OID": "' + cfg_opt[ce].oid + '",' +
                      '"Content": "' + content + '",' +
                      '"OUTPUT": "' +  gate + '"}')
        outJson.append(dictn.copy())
        # if "present" in ce:
	     #    prof_ext_oids.add(cfg_opt[ce].oid)
    return


def lint_signature_algorithm(cfg_opt, cert, cfg_sect, outJson):
    output_array = []
    cert_leaf = cert['signature_algorithm']['algorithm']
    oid = cert_leaf.dotted
    found = False
    for ce in cfg_opt:
        if cfg_opt[ce].oid == oid:
            found = True
            break

    cert_leaf1 = cert['tbs_certificate']['signature']['algorithm'].dotted
    reason = "the certificate signature algorithm not found in profile or the signature algorithm and TBS certificate signature algorithm are not the same"
    output_array.append({"Item": ce, "Result": found and cert_leaf.dotted == cert_leaf1, "Content": "signature algorithm:" + oid + ". tbs certificate sig algorithm: " + cert_leaf1, "Reason": reason})
    
    for opa in output_array:
        gate = "PASS"
        ce = opa["Item"]
        result = opa["Result"]
        content = ""
        if result is True and cfg_opt[ce].value is '1':
            gate = "FAIL: " + opa["Reason"]
            content = opa["Content"]
        dictn = ast.literal_eval('{"Section": "' + cfg_sect + '",' +
                      '"Item": "' + ce + '",' +
                      '"Value": "' + cfg_opt[ce].value + '",' +
                      '"OID": "' + cfg_opt[ce].oid + '",' +
                      '"Content": "' + content + '",' +
                      '"OUTPUT": "' +  gate + '"}')
        outJson.append(dictn.copy())
        # if "present" in ce:
	     #    prof_ext_oids.add(cfg_opt[ce].oid)

    return


def lint_version(cfg_opt, cert, cfg_sect, outJson):
    output_array = []
    cert_leaf = cert['tbs_certificate']['version'].native

    reason = "Certifcate Version is less than the minimum certificate versoin specified in the profile"
    output_array.append({"Item": "min_version", "Result": int(cert_leaf[1:]) >= int(cfg_opt['min_version'].value), "Content": cert_leaf,"Reason": reason})
    
    for opa in output_array:
        gate = "PASS"
        ce = opa["Item"]
        result = opa["Result"]
        content = ""
        if result is True and cfg_opt[ce].value is '1' or result is False and (cfg_opt[ce].value is '3' or
            cfg_opt[ce].value is '2') :
            gate = "FAIL: " + opa["Reason"]
            content = opa["Content"]
        dictn = ast.literal_eval('{"Section": "' + cfg_sect + '",' +
                      '"Item": "' + ce + '",' +
                      '"Value": "' + cfg_opt[ce].value + '",' +
                      '"OID": "' + cfg_opt[ce].oid + '",' +
                      '"Content": "' + content + '",' +
                      '"OUTPUT": "' +  gate + '"}')
        outJson.append(dictn.copy())
        # if "present" in ce:
	     #    prof_ext_oids.add(cfg_opt[ce].oid)
    return


def lint_ocsp_nocheck(cfg_opt, cert, cfg_sect, outJson):

    _process_common_extension_options(cfg_opt, cert.ocsp_no_check_value,
                                      'ocsp_no_check' in cert.critical_extensions,
                                      "OCSP NoCheck")

    output_array = []
    extensions = cert['tbs_certificate']['extensions']
    found = False

    for e in extensions: #not in cert, mimicing aia
        if e['extn_id'].native == "ocsp_no_ckeck":
                found = True
                break

    reason = "Profile oid is not in the certificate"
    output_array.append({"Item": "present", "Result": found, "Content": e['extn_id'].dotted,"Reason": reason})

    if found:
        reason = "extension criticality does not match  between profile and certificate"
        output_array.append({"Item": "critical", "Result": e['critical'].native, "Content": str(e['critical'].native),"Reason": reason})

    
    for opa in output_array:
        gate = "PASS"
        ce = opa["Item"]
        result = opa["Result"]
        content = ""
        if result is True and cfg_opt[ce].value is '1' or result is False and (cfg_opt[ce].value is '3' or
            cfg_opt[ce].value is '2') :
            gate = "FAIL: " + opa["Reason"]
            content = opa["Content"]
        dictn = ast.literal_eval('{"Section": "' + cfg_sect + '",' +
                      '"Item": "' + ce + '",' +
                      '"Value": "' + cfg_opt[ce].value + '",' +
                      '"OID": "' + cfg_opt[ce].oid + '",' +
                      '"Content": "' + content + '",' +
                      '"OUTPUT": "' +  gate + '"}')
        outJson.append(dictn.copy())
        # if "present" in ce:
	     #    prof_ext_oids.add(cfg_opt[ce].oid)

    return


def lint_inhibit_any(cfg_opt, cert, cfg_sect, outJson):

    _process_common_extension_options(cfg_opt, cert.inhibit_any_policy_value,
                                      'inhibit_any_policy' in cert.critical_extensions,
                                      "Inhibit Any Policy")

    output_array = []
    extensions = cert['tbs_certificate']['extensions']
    found = False
    critical = False

    for e in extensions: #not in cert, mimicing aia
        if e['extn_id'].native == "inhibit_any_policy":
                found = True
                break
    reason = "Profile oid is not in the certificate"
    output_array.append({"Item": "present", "Result": found, "Content": e['extn_id'].dotted,"Reason": reason})

    if found:
        reason = "extension criticality does not match  between profile and certificate"
        output_array.append({"Item": "is_critical", "Result": e['critical'].native, "Content": str(e['critical'].native),"Reason": reason})

    
    for opa in output_array:
        gate = "PASS"
        ce = opa["Item"]
        result = opa["Result"]
        content = ""
        if result is True and cfg_opt[ce].value is '1' or result is False and (cfg_opt[ce].value is '3' or
            cfg_opt[ce].value is '2') :
            gate = "FAIL: " + opa["Reason"]
            content = opa["Content"]
        dictn = ast.literal_eval('{"Section": "' + cfg_sect + '",' +
                      '"Item": "' + ce + '",' +
                      '"Value": "' + cfg_opt[ce].value + '",' +
                      '"OID": "' + cfg_opt[ce].oid + '",' +
                      '"Content": "' + content + '",' +
                      '"OUTPUT": "' +  gate + '"}')
        outJson.append(dictn.copy())
        # if "present" in ce:
	     #    prof_ext_oids.add(cfg_opt[ce].oid)

    return


conformance_check_functions = {
    'policy_mappings': lint_policy_mappings,
    'piv_naci': lint_piv_naci,
    'validity': lint_validity,
    'subject': lint_subject,
    'issuer': lint_issuer,
    'akid': lint_akid,
    'skid': lint_skid,
    'key_usage': lint_key_usage,
    'policy_constraints': lint_policy_constraints,
    'serial_number': lint_serial_number,
    'basic_constraints': lint_basic_constraints,
    'cert_policies': lint_cert_policies,
    'subject_public_key_info': lint_subject_public_key_info,
    'aia': lint_aia,
    'san': lint_san,
    'ian': lint_ian,
    'eku': lint_eku,
    'crldp': lint_crldp,
    'sia': lint_sia,
    'pkup': lint_pkup,
    'sub_dir_attr': lint_sub_dir_attr,
    'signature_algorithm': lint_signature_algorithm,
    'version': lint_version,
    'ocsp_nocheck': lint_ocsp_nocheck,
    'inhibit_any': lint_inhibit_any,
    'name_constraints': lint_name_contraints
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
    outJson = []
    for cfg_sect in cert_profile:
        # print(cfg_sect)
        if cfg_sect in conformance_check_functions:
            conformance_check_functions[cfg_sect](cert_profile[cfg_sect], input_cert, cfg_sect, outJson)
            if "critical" in cert_profile[cfg_sect] and "present" in cert_profile[cfg_sect]:
                prof_ext_oids.add(cert_profile[cfg_sect]["present"].oid)
        elif not cfg_sect == "other_extensions":
            print("Invalid config section:  {}".format(cfg_sect))
    lint_other_extensions(cert_profile["other_extensions"], input_cert, cfg_sect, outJson)
  #  json.dump(outJson, sys.stdout, indent=2)

