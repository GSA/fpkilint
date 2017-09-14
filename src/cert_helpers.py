import base64
from asn1crypto import pem, x509


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
        'unique_identifier': 'UID',
        'dn_qualifier': 'DN Qual',
        'pseudonym': 'Pseudonym',
        'email_address': 'Email',
        'incorporation_locality': 'Incorporation Locality',
        'incorporation_state_or_province': 'Incorporation State/Province',
        'incorporation_country': 'Incorporation Country',
        'domain_component': 'DC',
        'name_distinguisher': 'Name Distinguisher',
        'organization_identifier': 'Organization Identifier',
    }.get(name_type.native, name_type.native)


# type = Name e.g. subject = tbs_cert['subject']
def get_pretty_dn(name, rdn_separator=None, type_value_separator=None, include_oid=None):

    if not isinstance(name, x509.Name):
        raise TypeError("name must be an x509.Name")

    s = ""
    if rdn_separator is None:
        rdn_separator = ", "

    if type_value_separator is None:
        type_value_separator = "="

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
                if include_oid is not None:
                    s += ' ({})'.format(name2['type'])
                s += '{}{}'.format(type_value_separator, name2.native['value'])
    else:
        s = ""

    return s



