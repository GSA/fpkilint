import warnings
from asn1crypto import x509
from fpkilint.display_maps import *
import textwrap
import urllib.parse

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
    return dn_name_component_display_map.get(name_type.native, name_type.native)


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


class type_and_value(Sequence):
    _fields = [
        ('oid', ObjectIdentifier, {}),
        ('value', Any, {})
    ]


def get_name_type_and_value_string_type(nameTypeAndValue):
    if not isinstance(nameTypeAndValue, x509.NameTypeAndValue):
        raise TypeError('Expected asn1crypto.x509.NameTypeAndValue')

    string_type, value = split_name_type_and_value(nameTypeAndValue)
    return string_type


def split_name_type_and_value(nameTypeAndValue):
    if not isinstance(nameTypeAndValue, x509.NameTypeAndValue):
        raise TypeError('Expected asn1crypto.x509.NameTypeAndValue')

    # this code side steps any auto correcting that is happening in asn1crypto
    # example: auto correcting EmailAddress encoded as printable string to IA5
    name_type_and_value = type_and_value.load(nameTypeAndValue.dump())
    value = name_type_and_value['value'].parsed

    if isinstance(value, AbstractString):
        return get_abstract_string_type(value), value
    else:
        warnings.warn('NameTypeAndValue did not contain an AbstractString?')

    return 'Unknown', value


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
                    string_type = '({}) '.format(get_name_type_and_value_string_type(name2))

                s += '{}{}{}'.format(type_value_separator, string_type, name2.native['value'])
    else:
        s = "None"

    return s


other_name_type_map = {
    '1.3.6.1.4.1.311.20.2.3': '_upn',
    '2.16.840.1.101.3.6.6': '_piv_fasc_n',
}


def get_general_name_string(general_name, multiline=None, indent_string=None, type_separator=None, include_string_type=None, value_only=None):
    if multiline is None:
        multiline = False
    if indent_string is None:
        indent_string = '    '
    if type_separator is None:
        type_separator = ' = '
    if include_string_type is None:
        include_string_type = False
    if value_only is None:
        value_only = False

    if value_only is False:
        general_name_string = "{}: ".format(general_name_display_map.get(general_name.name, "Unknown Name Type"))
    else:
        general_name_string = ''

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


def binary_to_hex_string(byte_value, multi_line=None):
    if not isinstance(byte_value, bytes):
        return "You must pass in bytes..."

    hex_string = ""

    if multi_line is not True:
        hex_string += ''.join('%02X' % c for c in byte_value)
    else:
        hex_string += textwrap.fill(' '.join('%02X' % c for c in byte_value), 43)

    return hex_string


def get_der_display_string(byte_value, preface=None, multi_line=None):
    if not isinstance(byte_value, bytes):
        return "You must pass in bytes..."

    if preface is None:
        der_display_string = "DER: "
    else:
        der_display_string = preface

    if multi_line is not True:
        der_display_string += binary_to_hex_string(byte_value)
    else:
        der_display_string += '\n'
        der_display_string += binary_to_hex_string(byte_value, True)

    return der_display_string
