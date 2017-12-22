import base64
from asn1crypto import pem, x509
from binary_utils import *


def parse_cert(byte_data):

    if not isinstance(byte_data, bytes):
        raise TypeError("byte_data must be a byte string")

    if byte_data[0] == 'M':
        byte_data = base64.b64decode(byte_data)

    if pem.detect(byte_data):
        file_type, headers, byte_data = pem.unarmor(byte_data)

        if file_type != 'CERTIFICATE':
            raise TypeError("CERTIFICATE expected, but got {}".format(file_type))

    x509cert = x509.Certificate.load(byte_data)

    return x509cert


def is_policy_in_policies(policy_oid_string, certificate_policies):

    if not isinstance(certificate_policies, x509.CertificatePolicies):
        raise TypeError("certificate_policies must be a x509.CertificatePolicies")

    if not isinstance(policy_oid_string, str):
        raise TypeError("policy_oid_string must be a string")

    oid = x509.PolicyIdentifier(policy_oid_string)
    pi = x509.PolicyInformation({'policy_identifier': oid})

    if pi.native in certificate_policies.native:
        return True

    return False


def get_extension_list_from_certificate(cert, oid=None):

    if oid and not isinstance(oid, str):
        raise TypeError("oid must be dotted oid string")

    extensions = cert['tbs_certificate']['extensions']
    extension_list = list()

    for e in extensions:
        if oid is None or e['extn_id'].dotted == oid:
            extension_list.append([e, e['critical'].native])

    return extension_list


def get_extension_from_certificate(cert, oid):

    if not isinstance(oid, str):
        raise TypeError("oid must be dotted oid string")

    ext_list = get_extension_list_from_certificate(cert, oid)

    if len(ext_list) is 0:
        return None, False

    return ext_list[0][0], ext_list[0][1]


def is_name_type_in_dn(oid_string, name):
    if not isinstance(name, x509.Name):
        raise TypeError("name must be an x509.Name")

    rdn_seq = name.chosen
    if len(rdn_seq):
        for rdn in rdn_seq:
            for name in rdn:
                if name['type'].dotted == oid_string:
                    return True

    return False


def get_pretty_dn_name_component(name_type):

    # name_type = NameType

    return {
        'common_name': 'CN',
        'surname': 'SN',
        'serial_number': 'Serial',
        'country_name': 'C',
        'locality_name': 'L',
        'state_or_province_name': 'State',
        'street_address': 'Street',
        'organization_name': 'O',
        'organizational_unit_name': 'OU',
        'title': 'Title',
        'business_category': 'Business Category',
        'postal_code': 'Postal Code',
        'telephone_number': 'Telephone Number',
        'name': 'Name',
        'given_name': 'GN',
        'initials': 'Initials',
        'generation_qualifier': 'Generation Qualifier',
        'unique_identifier': 'Unique ID',
        'dn_qualifier': 'DN Qual',
        'pseudonym': 'Pseudonym',
        'email_address': 'Email',
        'incorporation_locality': 'Incorporation Locality',
        'incorporation_state_or_province': 'Incorporation State/Province',
        'incorporation_country': 'Incorporation Country',
        'domain_component': 'DC',
        'name_distinguisher': 'Name Distinguisher',
        'organization_identifier': 'Organization Identifier',
        '0.9.2342.19200300.100.1.1': 'User ID',
        '2.23.133.2.3': 'TPMVersion',
        '2.23.133.2.2': 'TPMModel',
        '2.23.133.2.1': 'TPMManufacturer',
    }.get(name_type.native, name_type.native)


_directory_string_type_display_map = {
    'printable_string': 'Printable',
    'utf8_string': 'UTF8',
    'bmp_string': 'BMP',
    'teletex_string': 'Teletex',
    'universal_string': 'Universal',
    'ia5_string': 'IA5',
}


# type = Name e.g. subject = tbs_cert['subject']
def get_pretty_dn(name, rdn_separator=None, type_value_separator=None, include_oid=None, include_string_type=None):

    if not isinstance(name, x509.Name):
        raise TypeError("name must be an x509.Name")

    s = ""
    if rdn_separator is None:
        rdn_separator = ", "

    if type_value_separator is None:
        type_value_separator = "="

    if include_oid is None:
        include_oid = False

    if include_string_type is None:
        include_string_type = False

    string_type = ''

    rdn_seq = name.chosen  # type = RDNSequence
    if len(rdn_seq):
        rdn_list = list()
        for rdn in rdn_seq:
            rdn_list.append(rdn)

        rdn_list.reverse()

        for rdn2 in rdn_list:
            for name2 in rdn2:
                if s is not "":
                    s += rdn_separator
                s += get_pretty_dn_name_component(name2['type'])
                if include_oid is True:
                    s += ' ({})'.format(name2['type'])

                if include_string_type is True:
                    string_type = '({}) '.format(_directory_string_type_display_map.get(name2['value'].name,
                                                                                        "Undefined"))

                s += '{}{}{}'.format(type_value_separator, string_type, name2.native['value'])
    else:
        s = "None"

    return s


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


import urllib.parse


def get_general_name_string(general_name, multiline=None, indent_string=None):
    if multiline is None:
        multiline = False
    elif indent_string is None:
        indent_string = '    '

    general_name_string = "{}: ".format(general_name_display_map.get(general_name.name, "Unknown Name Type"))

    if general_name.name == 'uniform_resource_identifier':

        if general_name.native[0:9] == 'urn:uuid:':
            general_name_string += "(CHUID) " + general_name.native
        else:
            general_name_string += urllib.parse.quote(general_name.native, safe="%/:=&?~#+!$,;'@()*[]")

    elif general_name.name == 'directory_name':

        separator = ", "

        if multiline is True:
            general_name_string += '\n'
            general_name_string += indent_string
            separator = ",{}{}".format('\n', indent_string)

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
