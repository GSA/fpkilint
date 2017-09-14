from cert_helpers import *

if __name__ == "__main__":

    filePath = "testcerts/matt.cer"
    with open(filePath, 'rb') as thefile:
        encoded = thefile.read()

    cert = None

    try:
        cert = parse_cert(encoded)
    except:
        # todo add proper exception handlers
        print("Failed to parse the certificate")

    if cert is None:
        exit(0)

    print("\nSubject:  {}\n".format(get_pretty_dn(cert.subject)))
    print("Issuer:\n{}\n".format(get_pretty_dn(cert.issuer, "\n", " = ")))

    if cert.certificate_policies_value is not None and is_policy_in_policies("2.16.840.1.101.3.2.1.3.13",
                                                                             cert.certificate_policies_value) is True:
        print("2.16.840.1.101.3.2.1.3.13 (piv auth) is in the policy extension\n")

    tbs_cert = cert['tbs_certificate']

    serial_number = tbs_cert['serial_number'].contents
    print('Serial Number:  {} ({} octets)\n'.format(' '.join('%02X' % c for c in serial_number), len(serial_number)))

    nb = tbs_cert['validity']['not_before']
    na = tbs_cert['validity']['not_after']
    s = "Not Before:  [{}]\n {} ({})\n".format(nb.name, nb.chosen, nb.native)
    s += "Not After:  [{}]\n {} ({})\n".format(na.name, na.chosen, na.native)
    print(s)

    if cert.basic_constraints_value is not None:
        print("CA={}".format(cert.basic_constraints_value.native['ca']))
        print("PathLengthConstraint={}".format(cert.basic_constraints_value.native['path_len_constraint']))
        if cert.basic_constraints_value.native['ca'] is False and len(cert.basic_constraints_value.contents) > 0:
            print("Basic Constraints DEFAULT value was encoded: {}".format(cert.basic_constraints_value.contents))
    else:
        print("Basic Constraints is not present\n")

    cn_oid = '2.5.4.3'
    surname_oid = '2.5.4.4'

    if is_name_type_in_dn(cn_oid, cert.subject) is True:
        print("Certificate subject contains common name")

    if is_name_type_in_dn(surname_oid, cert.subject) is False:
        print("Certificate subject does not contain surname")
