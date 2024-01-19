# FPKI Lint Change Log
Updated: 01/12/2024

## Updates and modifications 

- Updated version numbers for Common-SSP v2.1, 2.2, and FBCA v2.0 to correct version.
- Updated dropdown list to reflect correct version number.
- Updated each `more_info_url` to the url of profile's PDF document.

## Common Profile v2.2

| Profiles Affected | Common Profile Changes |
|:--------------------------|:---------------|
| All profiles except Worksheet 1 | Authority Information Access & Certificate Revocation List Distribution Point - Require HTTP URI first |
| All profiles except worksheet 1 | Authority Information Access - Allow .cer |
| All Profiles | DN Encoding: Allow only printableString and/or UTF8 |
| Worksheet 1-3 | <ul><li>Key Usage - Remove digital signature and non-repudiation bits from CA profiles</li><li>Removes ability to perform direct OCSP signing by a CA; delegated OCSP signing only</li></ul> |
| Worksheet 6-11, 16-17 | Allow Subject Directory Attributes (e.g., citizenship) |
| Worksheet 3 | Cross Certificate: <ul><li>Clarify appropriate use of requireExplicitPolicy</li><li>inhibitPolicyMapping, Offer distinction from the Intermediate CA Certificate profile (new)</li></ul> |
| Worksheet 4 | Intermediate Certificate (new profile):<ul><li>Prohibit policy mappings</li><li>Policy constraints are optional</li><li>Subject Information Access extension is required, unless the CA certificate includes path length constraint of 0</li></ul> |
| Worksheet 13 | OCSP Responder Certificate, EKU must be marked critical |
| Worksheet 8,9 | Signature Certificates and Key Management Certificates <ul><li>For PIV, id-kp-emailProtection must be included</li><li>rfc822Name is required if id-kp-emailProtection is asserted in Extended Key Usage</li></ul> |

## Bridge Profile v2.0

| Profiles Affected | Bridge Profile Changes |
|:--------------------------|:----------------------|
|  Worksheet 8, 9 | <ul><li>Profiles under PIV-I should be merged with FBCA as new profiles</li><li>Worksheet 9 (PIV-I Authentication Certificate change</li><li>Delete the following profiles (do not merge with FBCA):<ul><li>PIV-I Signature profile</li><li>PIV-I Key Management Profile</li><li>PIV-I Self Signed</li><li>PIV-I Cross Certificate PIVA-I</li></ul></li></ul> |
| Worksheet 4-7 and Worksheet 10-17 | Several new profiles were drafted to include: <ul><li>Intermediate/Signing CA Certificate</li><li>Authentication Certificate (non-PIV-I)</li><li>Device Certificate</li></ul>
| All except Worksheet 1 | <ul><li>Authority Information Access & Certificate Revocation List</li><li>Distribution Point - Require HTTP URI first</li></ul>
| All except Worksheet 1 | Authority Information Access - Allow .cer |
| All Worksheets | DN Encoding: Allow only printableString and/or UTF8 |
| Worksheet 6,7,11,16 | Optionally allow Subject Directory Attributes (e.g., citizenship) for authentication certificates (General, PIV-I, PIV-I card authentication) |
| Worksheet 3, 4 | Cross Certificate Clarify appropriate use of requireExplicitPolicy and inhibitPolicyMapping |
| Worksheet 13 | OCSP Responder Certificate EKU must be marked critical |
| None | Section 8 References – removed and FBCA CP Appendix D is linked |

