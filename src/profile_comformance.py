from cert_helpers import *
import json
import sys


#compare profile against cert leaf
def compare_leaf(profile_leaf, cert_leaf):
    if profile_leaf['Type'] == "OID":
          cert_value = cert_leaf[profile_leaf.Name]
    elif profile_leaf['Type'] == "Binary":
          contents = cert_leaf[profile_leaf.Name].contents
          cert_value = '{}'.format('%02X' % c for c in contents) 
    elif profile_leaf['Type'] == "String":
      	  cert_value = cert_leaf[profile_leaf.Name].native
    elif profile_leaf['Type'] == "DateTime":
      	  cert_value = cert_leaf[profile_leaf.Name]
    elif profile_leaf['Type'] == "List":
      	  cert_value = cert_leaf[profile_leaf.Name]
    elif profile_leaf['Type'] == "Bool":
      	  cert_value = cert_leaf[profile_leaf.Name]
    elif profile_leaf['Type'] == "Tuple":
      	  cert_value = cert_leaf[profile_leaf.Name]
    elif profile_leaf['Type'] == "OrderedDict":
      	  cert_value = cert_leaf[profile_leaf.Name]
    else:
          print("\"WARNING: Unknow Leaf Type\"")
          return

    if profile_leaf['Require'] == "0" and not (profile_leaf['Vaue'] == cert_value):
      print("\"WARNING: optional value is not valid\"", end="")
    elif profile_leaf['Require'] == "1" and profile_leaf['Vaue'] == cert_value:
      print("\"ERROR: value is not allowed\"", end="")
    elif profile_leaf['Require'] == "2" and not(profile_leaf['Vaue'] == cert_value):
      print("\"ERROR: required value is not valid\"", end="")
    else:
      print('"PASS"', end="")
    return

#recursive iterator of json data tree
def recursive_iter(obj, cert, indent):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "Leaf":
                compare_leaf(v, cert)
            else:
                print(indent+'{', '"'+k+'": ', end="")
                if k in cert:
                    yield from recursive_iter(v, cert[k], indent+" ")
                else:
                    print('"'+ "WARNING -- the following key does not exist in provided certificate: " + k + '"', end="")
                print(indent + '}')
    elif any(isinstance(obj, t) for t in (list, tuple)):
        first = 1
        print(indent+'[')
        for item in obj:
            if first == 1:
               first = 0
            else:
               print(", ")
            yield from recursive_iter(item, cert, indent+" ")
        print(indent+']')
    yield obj

if __name__ == "__main__":

    filePath = "testcerts/test.cer"
    with open(filePath, 'rb') as cert_file:
        encoded = cert_file.read()

    input_cert = None

    try:
        input_cert = parse_cert(encoded)
    except:
        # todo add proper exception handlers
        print("Failed to parse the certificate", sys.stderr)

    if input_cert is None:
        exit(0)

    print("\nSubject:\n{}\n".format(get_pretty_dn(input_cert.subject, "\n", "=")), sys.stderr)
    print("Issuer:\n{}\n".format(get_pretty_dn(input_cert.issuer, "\n", "=")), sys.stderr)

    with open('profiles/template.json') as json_data:
        json_profile = json.load(json_data)


    try:
        indent = "\n"
        for item in recursive_iter(json_profile, input_cert, indent):
            print(item)
    except:
        # todo add proper exception handlers
        print("Failed to parse the profile", sys.stderr)
 
