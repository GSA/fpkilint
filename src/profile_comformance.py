from cert_helpers import *
import json


#compare profile against cert leaf
def compare_leaf(peofil_leaf, cert_leaf):
    if profil_leaf['Type'] == "OID":
          cert_value = cert_leaf[profile_leaf.Name]
    elif profil_leaf['Type'] == "Binary":
          contents = cert_leaf[profile_leaf.Name].contents
          cert_value = '{}'.format('%02X' % c for c in contents)
    elif profil_leaf['Type'] == "String":
          cert_value = cert_leaf['version'].native
    else:
          print("\"WARNING: Unknow Leaf Type\"")
          return

    if profil_leaf['Require'] == "0" and profile_leaf['Vaue'] <> cert_value:
      print("\"WARNING: optional value is not valid\"")
    elif profil_leaf['Require'] == "1" and profile_leaf['Vaue'] == cert_value:
      print("\"ERROR: value is not allowed\"")
    elif profil_leaf['Require'] == "2" and profile_leaf['Vaue'] <> cert_value:
      print("\"ERROR: required value is not valid\"")
    else:
      print("\"OK\"")
    return

#recursive iterator of json data tree
def recursive_iter(obj, cert, indent):
    if isinstance(obj, dict):
        for item in obj.items():
            if item.key == "Leaf":
                compare_leaf(item.value, cert)
            else:
                print("{}{\"{}\": ", indent, item.key)
                recursive_iter(item.value, cert[item.key], indent+" ")
                print("{}}", indent)
    elif any(isinstance(obj, t) for t in (list, tuple)):
        first = 1
        print("{}[", indent)
        for item in obj:
            if(first == 1):
               first = 0
            else:
               print(", ")
            recursive_iter(item, cert, indent+" ")
        print("{}]", indent)
    return

if __name__ == "__main__":

    filePath = "testcerts/matt.cer"
    with open(filePath, 'rb') as cert_file:
        encoded = cert_file.read()
    input_cert = None

    try:
        input_cert = parse_cert(encoded)
    except:
        # todo add proper exception handlers
        print("Failed to parse the certificate", file=sys.stderr)

    if input_cert is None:
        exit(0)

    print("\nSubject:\n{}\n".format(get_pretty_dn(input_cert.subject, "\n", "=")), file=sys.stderr)
    print("Issuer:\n{}\n".format(get_pretty_dn(input_cert.issuer, "\n", "="))), file=sys.stderr

    with open('profiles/template.json') as json_data:
        json_profile = json.load(json_data)


    try:
        indent = "\n"
        recursive_iter(json_profile, input_cert, indent)
    except:
        # todo add proper exception handlers
        print("Failed to parse the profile", file=sys.stderr)
