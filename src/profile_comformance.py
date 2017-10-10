from cert_helpers import *
import json
import sys


#compare profile against cert leaf
def compare_leaf(obj, cert):
    profile_leaf = obj['Leaf']
    result = conformance_check_functions[profile_leaf['function']](cert, profile_leaf)

    """
    if profile_leaf['Type'] == "OID":
    elif profile_leaf['Type'] == "Binary":
          cert_value = '{}'.format('%02X' % c for c in cert_value) 
    elif profile_leaf['Type'] == "String":
      	  cert_value = cert[profile_leaf.Name].native
    elif profile_leaf['Type'] == "DateTime":
      	  cert_value = cert[profile_leaf.Name]
    elif profile_leaf['Type'] == "List":
    elif profile_leaf['Type'] == "Bool":
      	  cert_value = cert[profile_leaf.Name]
    elif profile_leaf['Type'] == "Tuple":
      	  cert_value = cert[profile_leaf.Name]
    elif profile_leaf['Type'] == "OrderedDict":
      	  cert_value = cert[profile_leaf.Name]
    else:
          print("\"WARNING: Unknow Leaf Type\"")
          return
   

    if profile_leaf['Require'] == "0" and not (profile_leaf['Value'] == cert_value):
      result = "WARNING: optional value is not valid"
    elif profile_leaf['Require'] == "1" and profile_leaf['Value'] == cert_value:
      result = "ERROR: value is not allowed - " + cert_value 
    elif profile_leaf['Require'] == "2" and not(profile_leaf['Value'] == cert_value):
      result = "ERROR: required value is not valid - "  + cert_value
    elif profile_leaf['Require'] == "PROFILE_IN_CERT" and not( set(profile_leaf['Value']) <= set(cert_value) ):
      result = "Failed with cert value: " + cert_value
    elif profile_leaf['Require'] == "CERT_IN_PROFILE" and not(set(cert_value) <=set(profile_leaf['Value'])):
      result = "Failed with cert value: " + cert_value 
    else:
      result = "PASS"
     """
    del obj['Leaf']
    obj.update({"Result": result})
    return

#recursive iterator of json data tree
def recursive_iter(obj, cert):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "Leaf":
                compare_leaf(obj, cert)
            else:
                yield from recursive_iter(v, cert)

    elif any(isinstance(obj, t) for t in (list, tuple)):
        first = 1
        for item in obj:
            if first == 1:
               first = 0
            else:
               print(", ")
            yield from recursive_iter(item, cert)
    yield obj

def sigature_algorithm_func(self, pleaf):
    cert_value = [self['signature_algorithm']['algorithm'].native]
    if pleaf['Require'] == "2" and not( set(cert_value) <= set(pleaf['Value'] or cert_value == self['tbs_certificate']['signature']['algorithm'].native)):
      result = "Failed with cert value: " + cert_value
    else:
      result ="PASS"
    return  result

def subject_func(self, pleaf):
    cert_value = list(self.subject.native.keys())
    if pleaf['Require'] == "2" and not( set(pleaf['Value']) <= set(cert_value) ):
      result = "Failed with cert value: " + cert_value
    else:
      result ="PASS"
    return  result

def certificate_policies_func(self, pleaf):
    cert_value = [self.certificate_policies_value.native[0]['policy_identifier']]
    if pleaf['Require'] == "2" and not( set(cert_value) <= set(pleaf['Value'])) and not( set(['any_policy']) <= set(pleaf['Value'])):
      result = "Failed with cert value: " + cert_value
    else:
      result ="PASS"
    return  result

conformance_check_functions = {
    "sigature_algorithm_func": sigature_algorithm_func,
    "subject_func": subject_func,
    "certificate_policies_func": certificate_policies_func
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
        print("Failed to parse the certificate", sys.stderr)

    if input_cert is None:
        exit(0)

    print("\nSubject:\n{}\n".format(get_pretty_dn(input_cert.subject, "\n", "=")), sys.stderr)
    print("Issuer:\n{}\n".format(get_pretty_dn(input_cert.issuer, "\n", "=")), sys.stderr)

    with open('profiles/template.json') as json_data:
        json_profile = json.load(json_data)

    json_profile["Basic Certificate Fields"]["Certificate Fields"]["signatureAlgorithm"]["Leaf"].update({"function": "sigature_algorithm_func"})
    json_profile["Basic Certificate Fields"]["Certificate Fields"]["Subject"]["Leaf"].update({"function": "subject_func"})
    json_profile["Certificate Extensions"]["Standard Extensions"]["Certificate Policies"]["Leaf"].update({"function": "certificate_policies_func"})
    try:
        for item in recursive_iter(json_profile, input_cert):
            print(item)
    except:
        # todo add proper exception handlers
        print("Failed to parse the profile", sys.stderr)
    json.dump(json_profile, sys.stdout, indent = 2)
 
