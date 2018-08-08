---
layout: default
title: Certificate Profile Conformance Tool (CPCT)
collection: docs
permalink: docs/userguide/
---

## What is the Certificate Profile Conformance Tool (CPCT) and How Can It Help Me?
(Matt) (Background - summary of the tool)

## Who Should Use CPCT?
*[2 Use Cases?]*
CPCT will help you if:

1. Your agency is undergoing an annual Federal PKI Audit<!--from IDM-->:  Federal Public Key Infrastructure (FPKI) Certification Authorities (CAs) are audited annually to ensure their compliance with the requirements outlined in the _X.509 Certificate Policy for the U.S. Federal PKI Common Policy Framework_ and Certificate Policies and the _X.509 Certificate Policy for the Federal Bridge Certification Authority (FBCA)_. These annual audits also ensure the Federal PKI CAs' compliance with the policies' X.509 Certificate and Certificate Revocation List (CRL) Profiles and associated X.509 Certificate Profiles....<!--Add more, edit-->

## How Can CPCT Help Me? (Maybe combine with "What is the CPCT?" above)

CPCT analyzes an uploaded certificate for conformance with its applicable X.509 Certificate Policy and Certificate Profile. You won't need to do any manual comparisons, so it will save you time and effort. You'll see the analysis results within 1-2 minutes(?) If the certificate is successfully conformant, save the test results as a .pdf? for submission to ...? If the certificate doesn't conform in any way, the CPCT's displayed report clearly calls out what field or extension needs to be corrected.

2. xxx

### How Does This Work?
(Matt) How to use the tool section.  Describe the meaning and purpose of each of the drop-down lists (Policy, Version, Profile
<**(CB) NOTE - Version number applies to Profile, but because it follows "Policy," drop-down, it appear to apply to Policy. Suggest switching order of drop-downs so Version follows Profile.**>)

With CPCT, you'll never have to manually analyze a certificate for conformance again. (etc.)    

#### 1. Select Policy, Profile, and Version
1. Navigate to the [CPCT](https://cpct.app.cloud.gov/) website. <!--Will a login to CPCT be required once it is up and running?-->
2. From the **Select a Policy** drop-down, choose the Federal PKI **X.509 Certificate Policy** that applies to your test certificate. <!--Related to your certificate type?--> The policy you select contains the requirements mandated for the Federal PKI Certification Authority (CA) that issued the certificate.
3. From the **Version** drop-down, choose the **_Certificate Profile Version_** that applies to your test certificate.
4. From the **Profile** drop-down, choose the **Certificate Profile** that applies to your test certificate.

#### 2. Upload a Certificate

* (Matt) Describe different ways to upload a certificate (text, file upload, drag-and-drop)

You can upload a test certificate in 3 ways:
1. Drag-and-drop - <**How does this work?**>
     - Go to the certificate you want to upload and click on it.
     - Drag and drop it to anywhere on the main CPTC screen.  <**Can CPCT give a system upload acknowledgment like "Certificate Uploaded!" or "Got it!" or "Uploaded!" to tell the user that the certificate has been uploaded?**>
2. Text Option???
3. Click the **Upload Certificate** button. Navigate to your certificate and double-click it. [System message: _what happens?_]


## Report section?

* (Matt) Step through the different sections of the report and provide details
<**(CB) Sample output doesn't look like the current Certificate Profile Worksheets. Research further.**>

## Troubleshooting and Feature Request

* (Matt) Guide folks to use the GitHub issues page for requests.
* (Matt) Provide our icam@gsa.gov email address for any help or feature requests.  (CB) Use fpki@gsa.gov??

## Troubleshooting:  

### What If I Can't Resolve an Issue?

Email us at fpki@gsa.gov!

(Matt) Provide some steps folks will need to take if they experience issues. 

* Email your certificate to fpki@gsa.gov?? (will need to rename cert to .txt file extensions)
* Submit a GitHub issue and attach the certificate file to the issue. (User will need to create a github account in order to do this.)

* (Matt) I say the submit an issue and attach the file is the preferred approach.  [CB: What's our estimated response time on this one?  As soon as possible?]

(Matt) Provide steps if there is a discrepancy with the results (what happens if there is a false-positive or false-negative). 
* How does user identify a discrepancy?  By knowing that CPCT is showing a result that CAN'T BE Right?  Or how?
* What does a False Positive look like?  (Says the field or extension IS comformant when IT'S NOT??) (How would this occur?  How will user know it's a False Positive?)
* What does a False Negative look like? (Says the field or extension IS NOT conformant when IT IS??) (How would this occur?  How will the user know that it's a False Negative?)
* (Matt) Why might you see a discrepancy?  A few possible causes:  
     - A
     - B
     - C
* (Matt) Probably follow similar approach as bullet above.
