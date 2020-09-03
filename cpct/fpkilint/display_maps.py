from collections import OrderedDict


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

directory_string_type_display_map = {
    'printable_string': 'Printable',
    'utf8_string': 'UTF8',
    'bmp_string': 'BMP',
    'teletex_string': 'Teletex',
    'universal_string': 'Universal',
    'ia5_string': 'IA5',
}

dn_name_component_display_map = {
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
}

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
    '1.3.6.1.4.1.311.3.10.3.1': 'Microsoft Signer of CTLs',
    '1.3.6.1.4.1.311.3.10.3.2': 'Microsoft Signer of TimeStamps',
    '1.3.6.1.4.1.311.3.10.3.3': 'Microsoft Can use strong encryption in export environment',
    '1.3.6.1.4.1.311.3.10.3.4': 'Microsoft Can use encrypted file systems (EFS)',
    '1.3.6.1.4.1.311.3.10.3.5': 'Microsoft Can use Windows Hardware Compatible (WHQL)',
    '1.3.6.1.4.1.311.3.10.3.6': 'Microsoft Signed by the NT5 Build Lab',
    '1.3.6.1.4.1.311.3.10.3.7': 'Microsoft Signed by an OEM of WHQL',
    '1.3.6.1.4.1.311.3.10.3.8': 'Microsoft Signed by the Embedded NT',
    '1.3.6.1.4.1.311.3.10.3.9': 'Microsoft Signer of a CTL containing trusted roots',
    '1.3.6.1.4.1.311.3.10.3.10': 'Microsoft Key Recovery',
    '1.3.6.1.4.1.311.3.10.3.11': 'Microsoft Key Recovery',
    '1.3.6.1.4.1.311.3.10.3.12': 'Microsoft Document Signing',
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
