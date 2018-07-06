---
layout: default
title: Certificate Profile Conformance Tool (CPCT)
collection: docs
permalink: docs/userguide/
---

## What is the Certificate Profile Conformance Tool (CPCT)?
(Background - summary of the tool)


### How Will CPCT Help Me? (Use Cases?)

We developed CPCT in response to two? Federal PKI community needs:

1. Annual Audit requirement (from IDM) Federal Public Key Infrastructure (FPKI) Certification Authorities (CAs) are audited annually to ensure their compliance with the requirements outlined in the _X.509 Certificate Policy for the U.S. Federal PKI Common Policy Framework_ and Certificate Policies and the _X.509 Certificate Policy for the Federal Bridge Certification Authority (FBCA)_. These annual audits also ensure the Federal PKI CAs compliance with the two policies' X.509 Certificate and Certificate Revocation List (CRL) Profiles and their associated X.509 Certificate Profiles....<!--Add more, edit-->
2. xxx

### How Does It Work?/How Do I Test a Certificate?
(How to use the tool section.  Describe the meaning and purpose of each of the drop-down lists (Policy, Version, Profile<!--NOTE - Version number applies to Profile, but because it follows "Policy," drop-down, it appear to apply to Policy. Suggest switching order of drop-downs so Version follows Profile.-->)

#### Select Policy, Profile, and Version
1. Navigate to [CPCT](https://cpct.app.cloud.gov/){:target="_blank"} website. <!--Will a login to CPCT be required once it is up and running?-->
2. From the first drop-down, choose a Federal PKI **X.509 Certificate Policy**. <!--Related to your certificate type?--> The policy you select contains the requirements mandated for the Federal PKI Certification Authority (CA) that issued the certificate.
3. From the second drop-down, choose the **Version** of the **Certificate Profile** that applies to your certificate.
4. From the third drop-down, choose the **Certificate Profile** that applies to your certificate.

#### Upload a Certificate

* Describe different ways to upload a certificate (text, file upload, drag-and-drop)
1. Text
2. Upload
3. Drag-and-drop

## Report section?

* Step through the different sections of the report and provide details
<!--Sample output doesn't look like the current Certificate Profile Worksheets. Research further.-->

## Troubleshooting and Feature Request

* Guide folks to use the GitHub issues page for requests.
* Provide our icam at gsa.gov email address for any help or feature requests.

## What If I Can't Resolve an Issue?

If you experience an issue:  

Provide some steps folks will need to take if they experience issues. 

For instance, email your certificate to icam at gsa.gov (will need to rename cert to .txt file extensions) or submit an issue and attach the file to the issue (user will need to create a github account in order to do this). 
* I say the submit an issue and attach the file is the preferred approach.

Provide steps if there is a discrepancy with the results (what happens if there is a false-positive or false-negative). 
* Why might you see a discrepancy?  A few possible causes:  
* Probably follow similar approach as bullet above.
