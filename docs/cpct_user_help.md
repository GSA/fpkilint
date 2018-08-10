---
layout: default
title: Certificate Profile Conformance Tool (CPCT)
collection: docs
permalink: docs/userguide/
---
<**STILL DRAFTING -- DRAFT --- DRAFT**>

<!--Question: CPCT only for government or SSPs?-->

## What is the Certificate Profile Conformance Tool (CPCT)?
(Matt) (Background - summary of the tool)<br>
  
The CPCT is a certificate analysis tool that quickly tests whether a certificate conforms to FPKI Certificate Policies and Profiles. CPCT will save you both time and resources, because it analyzes an uploaded certificate for you, rapidly displays the test results, and gives you a downloadable, formatted report. 

## How Does It Work?

* You upload a certificate to CPCT that you want to test. For example, you could test a certificate for conformance with:<br><br>
     o **Certificate Policy**: _X.509 Certificate Policy for the U.S. Federal PKI Common Policy Framework_<br>
     o **Certificate Profile and Version**: _FPKI X.509 Certificate and CRL Extensions Profile_, Version 1.8<br>
     o **Common Card Authentication** Profile<br>
* CPCT analyzes the certificate against the selected certificate policy, profile, and profile version. You won't need to waste time doing manual checks. 
* The certificate test report displays within seconds. 
* The report clearly shows each Field and Extension values and whether they Passed (checkmark) or Failed (_FAIL_) with explanations.
* You can re-test a certificate as many times as needed until a failure(s) has been resolved. 
* The test report can be downloaded as a .pdf or .xlsx to retain and/or submit with an FPKI Annual Review package. 

## Application Requirements
* Any application/system requirements to use the tool?
* Do recommend certain browsers for using the tool? (Displays may differ...?)

## Who Should Use CPCT?

Use Cases:

1. Agencies/organizations preparing submissions for FPKI Annual Reviews of FPKI CAs<!--Following text from IDM.gov for possible re-use-->FPKI CAs are audited annually to ensure their compliance with the requirements outlined in the _X.509 Certificate Policy for the U.S. Federal PKI Common Policy Framework_ and Certificate Policies and the _X.509 Certificate Policy for the Federal Bridge Certification Authority (FBCA)_. These annual audits also ensure the Federal PKI CAs' compliance with the policies' X.509 Certificate and Certificate Revocation List (CRL) Profiles and associated X.509 Certificate Profiles....<!--Add more, edit-->
2. PIV or SSL Certificate Issuers - As part of a QA process, you may want to test certificates you're issuing to ensure they conform to the Certificate Policies and Profiles.
3. Subscribers - You may want to find the cause of a certificate failure and whether you or the issuer needs to resolve it.

### Detailed Steps
(Matt) How to use the tool section.  Describe the meaning and purpose of each of the drop-down lists (Policy, Version, Profile

<!--Adding additional information from session with Ryan.-->

#### 1. Select Policy, Profile, and Version
1. Navigate to the [CPCT](https://cpct.app.cloud.gov/) website. 
2. At the main screen, pick an **X.509 Certificate Policy** from the **Select a Policy** drop-down, choose the Federal PKI that applies to your test certificate. <!--Related to your certificate type?--> The policy you select contains the requirements mandated for the Federal PKI Certification Authority (CA) that issued the certificate.
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
