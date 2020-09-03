import base64
from asn1crypto import pem, x509
from fpkilint.name_utils import get_general_name_string, get_general_name_type, get_short_name_from_dn


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
