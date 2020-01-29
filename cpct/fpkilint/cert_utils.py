import base64
from collections import OrderedDict
from asn1crypto import pem, x509
from fpkilint.binary_utils import *

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
    '1.3.6.1.4.1.311.10.3.12': 'Microsoft Doc Signing',
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
    '1.3.6.1.4.1.311.20.2.2': 'MS Smart Card Logon',
    '2.16.840.1.101.3.6.8': 'id-PIV-cardAuth',
    '2.16.840.1.101.3.6.7': 'id-PIV-content-signing',
    '2.16.840.1.101.3.8.7': 'id-fpki-pivi-content-signing',
    '1.3.6.1.5.2.3.4': 'id-pkinit-KPClientAuth',
    '1.3.6.1.5.2.3.5': 'id-pkinit-KPKdc',
    '1.3.6.1.4.1.311.20.2.1': 'MS Enrollment Agent',
    '1.3.6.1.4.1.311.21.6': 'MS Key Recovery Agent',  # Enhanced Key Usage for key recovery agent certificate
    '1.2.840.113583.1.1.5': 'Adobe PDF Signing',
    '2.23.133.8.1': 'Endorsement Key Certificate',
    '1.3.6.1.5.5.8.2.2': 'IKE Intermediate',
    # https://pub.carillon.ca/CertificatePolicy.pdf
    '1.3.6.1.4.1.25054.3.5.1': 'Carillon LSAP Code Signing',
    '1.3.6.1.4.1.25054.3.4.1': 'Carillon CIV Authentication',
    '1.3.6.1.4.1.25054.3.4.2': 'Carillon CIV Content Signing',
    # Air Canada
    '1.3.6.1.4.1.49507.1.10.1': 'Air Canada CIV Card Authentication',
    '1.3.6.1.4.1.49507.1.10.2': 'Air Canada CIV Content Signing',
}

key_usage_display_map = OrderedDict([
    ('digital_signature', 'digitalSignature (0)'),
    ('non_repudiation', 'nonRepudiation (1)'),
    ('key_encipherment', 'keyEncipherment (2)'),
    ('data_encipherment', 'dataEncipherment (3)'),
    ('key_agreement', 'keyAgreement (4)'),
    ('key_cert_sign', 'keyCertSign (5)'),
    ('crl_sign', 'cRLSign (6)'),
    ('encipher_only', 'encipherOnly (7)'),
    ('decipher_only', 'decipherOnly (8)'),
])

qualifiers_display_map = {
    'certification_practice_statement': 'CPS URI',
    'user_notice': 'User Notice',
    'notice_ref': 'Ref',
    'explicit_text': 'Explicit Text',
}

crldp_display_map = {
    'full_name': 'Full Name',
    'name_relative_to_crl_issuer': 'Name Relative to Issuer',
}


reason_flags_display_map = OrderedDict([
    (0, 'Unspecified (0)'),
    (1, 'Key Compromise (1)'),
    (2, 'CA Compromise (2)'),
    (3, 'Affiliation Changed (3)'),
    (4, 'Superseded (4)'),
    (5, 'Cessation of Operation (5)'),
    (6, 'Certificate Hold (6)'),
    (7, 'Privilege Withdrawn (7)'),
    (8, 'AA Compromise (8)'),
])


access_method_display_map = {
    'time_stamping': 'Time STamping',
    'ca_issuers': 'Certification Authority Issuers',
    'ca_repository': 'CA Repository',
    'ocsp': 'On-line Certificate Status Protocol'
}

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

map_extension_oid_to_display = {
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
    # Entrust
    '1.2.840.113533.7.65.0': 'Entrust Version Extension',
    '2.16.840.1.114027.30.1': 'Entrust Exportable Private Key',
    # Netscape
    '2.16.840.1.113730.1.1': 'Netscape Certificate Type',
    '2.16.840.1.113730.1.2': 'Netscape Base Url',
    '2.16.840.1.113730.1.3': 'Netscape Revocation Url',
    '2.16.840.1.113730.1.4': 'Netscape CaRevocation Url',
    '2.16.840.1.113730.1.7': 'Netscape Cert Renewal Url',
    '2.16.840.1.113730.1.8': 'Netscape CA Policy Url',
    '2.16.840.1.113730.1.12': 'Netscape SSL Server Name',
    '2.16.840.1.113730.1.13': 'Netscape Comment',
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
    '1.2.840.113549.1.9.15': 'S/Mime Capabilities',
    '1.3.6.1.4.1.311.21.2': 'Microsoft Previous CA Cert Hash',
    '1.3.6.1.4.1.11129.2.4.2': 'Signed Certificate Timestamp',
    '1.3.6.1.4.1.25054.3.6.1': 'Carillon Applicability Extension',  # https://pub.carillon.ca/CertificatePolicy.pdf

    '1.3.6.1.4.1.11129.2.4.3': 'CT Pre-Cert Poison Extension',  # RFC 6962

    '1.3.6.1.5.5.7.1.3': 'Qualified Certificate Statements',  # https://tools.ietf.org/html/rfc3739#section-3.2.6
}


def parse_certificate(byte_data):

    if not isinstance(byte_data, bytes):
        raise TypeError("byte_data must be a byte string")

    if byte_data[0] == 0x4D:  # 'M':
        byte_data = base64.b64decode(byte_data)

    if pem.detect(byte_data):
        file_type, headers, byte_data = pem.unarmor(byte_data)

        if file_type != 'CERTIFICATE':
            raise TypeError("CERTIFICATE expected, but got {}".format(file_type))

    if byte_data[0] != 0x30:
        raise TypeError("Leading byte is not 0x30 - this is not a certificate")

    if byte_data[1] & 0xF0 != 0x80:
        raise TypeError("Second byte is not 0x8n - this is not a certificate")

    x509cert = x509.Certificate.load(byte_data)
    x509cert.issuer  # forces lazy parse to occur now

    return x509cert


def parse_tbs_certificate(byte_data):
    """
    :param byte_data - certificate data to parse - can be pem or binary, a signed cert or a tbs cert:
    :return: x509.TbsCertificate
    """

    if not isinstance(byte_data, bytes):
        raise TypeError("byte_data must be a byte string")
    if len(byte_data) < 64:
        raise TypeError("byte_data too short to be a certificate")

    if byte_data[0] == 0x4D:  # 'M':
        byte_data = base64.b64decode(byte_data)

    if pem.detect(byte_data):
        file_type, headers, byte_data = pem.unarmor(byte_data)

        if file_type != 'CERTIFICATE':
            raise TypeError("CERTIFICATE expected, but got {}".format(file_type))

    if byte_data[0] != 0x30:
        raise TypeError("Leading byte is not 0x30 - this is not a certificate")

    if byte_data[1] & 0xF0 != 0x80:
        raise TypeError("Second byte is not 0x8n - this is not a certificate")

    tag = byte_data[2 + (byte_data[1] & 0x0F)]
    if tag == 0x30:
        x509cert = x509.Certificate.load(byte_data)
        tbs_certificate = x509cert['tbs_certificate']
    elif tag == 0xA0:
        tbs_certificate = x509.TbsCertificate.load(byte_data)
    else:
        raise TypeError("Data is not a Certificate nor a TbsCertificate")

    tbs_certificate['serial_number']  # forces lazy parse to occur now

    return tbs_certificate


def get_5280_method_1_key_id(cert):
    """
    :param cert: x509.Certificate
    :return: rfc5280 method 1 key id
    """
    if not cert.public_key.sha1 == cert['tbs_certificate']['subject_public_key_info'].sha1:
        print('hmmmmm')

    return cert.public_key.sha1


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


def get_extension_list(tbs_cert, oid=None):
    if oid and not isinstance(oid, str):
        raise TypeError("oid must be dotted oid string")

    if not isinstance(tbs_cert, x509.TbsCertificate):
        raise TypeError("cert must be x509.TbsCertificate")

    extensions = tbs_cert['extensions']
    extension_list = list()

    for e in extensions:
        if oid is None or e['extn_id'].dotted == oid:
            extension_list.append([e, e['critical'].native])

    return extension_list


def get_extension_and_criticality(tbs_cert, oid):
    if not isinstance(oid, str):
        raise TypeError("oid must be dotted oid string")

    ext_list = get_extension_list(tbs_cert, oid)

    if len(ext_list) == 0:
        return None, False

    return ext_list[0][0], ext_list[0][1]


def is_name_type_in_dn(oid_string, x509_name):
    if not isinstance(x509_name, x509.Name):
        raise TypeError("name must be an x509.Name")

    rdn_seq = x509_name.chosen
    if len(rdn_seq):
        for rdn in rdn_seq:
            for name in rdn:
                if name['type'].dotted == oid_string:
                    return True

    return False


def get_rdn_values_from_dn(oid_string, x509_name):
    if not isinstance(x509_name, x509.Name):
        raise TypeError("name must be an x509.Name")

    rdn_values = []

    rdn_seq = x509_name.chosen
    if len(rdn_seq):
        for rdn in rdn_seq:
            for name in rdn:
                if name['type'].dotted == oid_string:
                    rdn_values.append(name)

    return rdn_values


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


def get_abstract_string_type(abstract_string):

    if isinstance(abstract_string, PrintableString):
        string_type = 'Printable'
    elif isinstance(abstract_string, UTF8String):
        string_type = 'UTF8'
    elif isinstance(abstract_string, IA5String):
        string_type = 'IA5'
    elif isinstance(abstract_string, BMPString):
        string_type = 'BMP'
    elif isinstance(abstract_string, VisibleString):
        string_type = 'Visible'
    elif isinstance(abstract_string, TeletexString):
        string_type = 'Teletex'
    elif isinstance(abstract_string, UniversalString):
        string_type = 'Universal'
    elif isinstance(abstract_string, GeneralString):
        string_type = 'General'
    elif isinstance(abstract_string, NumericString):
        string_type = 'Numeric'
    else:
        string_type = abstract_string.__class__.__name__
        print('No case for ' + string_type + ' in get_abstract_string_type')

    return string_type


def get_name_type_string(name):
    if not isinstance(name, x509.NameTypeAndValue):
        return 'Error - get_name_string_type takes x509.NameTypeAndValue'

    value = name['value']

    if isinstance(value, x509.DirectoryString):
        return _directory_string_type_display_map.get(value.name, 'Undefined DirectoryString Type!?')

    if isinstance(value, Any):
        if value.parsed and isinstance(value.parsed, AbstractString):
            return get_abstract_string_type(value.parsed)

    string_type = 'Unknown'

    try:
        string_type = get_abstract_string_type(value)
    except:
        pass

    return string_type


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
                if s:
                    s += rdn_separator
                s += get_pretty_dn_name_component(name2['type'])
                if include_oid is True:
                    s += ' ({})'.format(name2['type'])

                if include_string_type is True:
                    string_type = '({}) '.format(get_name_type_string(name2))

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
    'other_name_piv_fasc_n': 'FASC-N',
    'uniform_resource_identifier_chuid': 'UUID',
    'uniform_resource_identifier_http': 'HTTP URI',
    'uniform_resource_identifier_ldap': 'LDAP URI',
    'uniform_resource_identifier_https': 'HTTPS URI',
    'uniform_resource_identifier_ldaps': 'LDAPS URI',
}

other_name_display_map = {
    '1.3.6.1.4.1.311.20.2.3': 'UPN',
    '2.16.840.1.101.3.6.6': 'FASC-N',
}

other_name_type_map = {
    '1.3.6.1.4.1.311.20.2.3': '_upn',
    '2.16.840.1.101.3.6.6': '_piv_fasc_n',
}


import urllib.parse


def get_general_name_string(general_name, multiline=None, indent_string=None, type_separator=None, include_string_type=None):
    if multiline is None:
        multiline = False
    if indent_string is None:
        indent_string = '    '
    if type_separator is None:
        type_separator = ' = '
    if include_string_type is None:
        include_string_type = False


    general_name_string = "{}: ".format(general_name_display_map.get(general_name.name, "Unknown Name Type"))

    if general_name.name == 'uniform_resource_identifier':

        if general_name.native[0:9] == 'urn:uuid:':
            general_name_string += "(UUID) " + general_name.native
        else:
            general_name_string += urllib.parse.quote(general_name.native, safe="%/:=&?~#+!$,;'@()*[]")

    elif general_name.name == 'directory_name':

        rdn_separator = ", "

        if multiline is True:
            general_name_string += '\n'
            general_name_string += indent_string
            rdn_separator = ",{}{}".format('\n', indent_string)

        general_name_string += get_pretty_dn(general_name.chosen, rdn_separator, type_separator, False, include_string_type)

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
        'name',
        'email_address',
        'given_name',
        'surname',
        '0.9.2342.19200300.100.1.1',
        'serial_number',
        'street_address',
        'organizational_unit_name',
        'organization_name',
        'locality_name'
    ]

    if len(name.contents) <= 2:
        return "NULL"

    for rdn in rdns:
        if rdn in name.native:
            tmp_name = name.native[rdn]
            if isinstance(tmp_name, list):
                return tmp_name[len(tmp_name) - 1]
            else:
                return tmp_name

    return name.native[next(reversed(name.native))]


def get_short_name_from_cert(cert, name_for_subject=True):

    if isinstance(cert, x509.Certificate):
        cert = cert['tbs_certificate']

    if name_for_subject:
        name = cert['subject']
    else:
        name = cert['issuer']

    if len(name.contents) > 2:
        return get_short_name_from_dn(name)

    # try the alt name...
    alt_name_value = None

    if name_for_subject:
        extension, critical = get_extension_and_criticality(cert, '2.5.29.17')
        if extension is not None:
            alt_name_value = extension['extn_value'].parsed

    else:
        extension, critical = get_extension_and_criticality(cert, '2.5.29.18')
        if extension is not None:
            alt_name_value = extension['extn_value'].parsed

    alt_name_string = "NULL"

    if alt_name_value:

        desired_alt_names = [
            'dns_name',
            'rfc822_name',
            'other_name_upn',
            'uniform_resource_identifier_chuid',
            'other_name_piv_fasc_n',
            'uniform_resource_identifier_http',
            'uniform_resource_identifier_https',
            'uniform_resource_identifier_ldap',
            'uniform_resource_identifier_ldaps',
            'uniform_resource_identifier',
            'directory_name',
        ]

        if len(alt_name_value) > 0:
            general_name = alt_name_value[0]
            alt_name_string = get_general_name_type(general_name)

        if len(alt_name_value) == 1:
            return alt_name_value

        for desired_type in desired_alt_names:
            for general_name in alt_name_value:
                if desired_type == get_general_name_type(general_name):
                    return get_general_name_string(general_name)

    return alt_name_string
