---
layout: default
title: Certificate Profile Conformance Tool (CPCT)
collection: docs
permalink: docs/userguide/
---
<**STILL DRAFTING -- DRAFT --- DRAFT**>

## What is the Certificate Profile Conformance Tool (CPCT)?
(Matt) (Background - summary of the tool)<br>

Do you need to analyze certificates for conformance to X.509 FPKI Certificate Policies and Profiles? Welcome to CPCT--your friendly tool for analyzing a certificate. CPCT dramatically reduces the time it takes to manually analyze every field and extension. And it couldn't be easier to use. It immediately tells you what issues need to be fixed in a certificate. Best of all (and what a relief), it gives you a formatted certificate report to download for submission with annual FPKI audits or archive.
**OR**
Other Snippet:  Do you need to analyze certificates for conformance to Federal PKI certificate profiles? We don't have to tell you how time-consuming that can be. CPCT will make your life so much easier.  Using it is a piece of cake, and it instanteously does what previously demanded too much of your time. Not only that, but it shows you the cause for any nonconformant field or extension. Best of all (and what a relief), it gives you a formatted test report to download for submission with annual FPKI audits or archive. 

## Use Cases - Who Should Use CPCT?

If you analyze FPKI CA-issued certificates for conformance to FPKI X.509 Certificate Policies and Profiles, CPCT is for you. 

Some typical Use Cases are below. You _might_ be a member of one of these groups, but it's not needed to use CPCT. 

1. **Agencies and organizations preparing FPKI Annual Review Packages -** For details, see [FPKI annual review information](#https://www.idmanagement.gov/fpki-cas-audit-info/#annual-audit-reqs-all-cas){:target="_blank"}
2. **PIV or SSL/TLS Certificate Issuers** - As part of a QA process, you may want to test certificates that you're issuing to ensure conformance.
3. **Subscribers** - Subscribers may need to find the cause of a certificate failure and which organization needs to resolve it.

## How Does This Work?

**Use the simplest explanations for this section**

CPCT couldn't be easier to use. Got a certificate to analyze? You simply upload it to CPCT and select a X.509 Certificate Policy, Profile, and version. CPCT analyzes the certificate and displays the test results. The results will show any are non-conformances, and you can retest the certificate if needed. You can download a final test report (.pdf or .xlsx) for submission as part of an FPKI Annual Review package or for archive. 

## Application Requirements 
* Any application/system requirements to use the tool?
* Do recommend certain browsers for using the tool? (Displays may differ...?)

### Detailed Steps
(Matt) How to use the tool section.  Describe the meaning and purpose of each of the drop-down lists (Policy, Version, Profile

<!--Adding additional information from session with Ryan.-->

From above for reuse:
* Got a certificate to analyze?  You simply upload it to CPCT via drag-and-drop, straight file upload, or use **text??**.  
* Then, select:<br><br>
     o **a Certificate Policy**: for example, _X.509 Certificate Policy for the U.S. Federal PKI Common Policy Framework_<br>
     o **Version Number**: for example, **v1.8** for the _FPKI X.509 Certificate and CRL Extensions Profile_<br>
     o **Certificate Profile**:  for example, **Common Card Authentication** Profile
* CPCT analyzes the certificate against the requirements within seconds. **_The test result display._**
* The results show whether each Field and Extension Passed (_checkmark_) or Failed (_FAIL_) with explanations.
* You can re-test a certificate as many times as needed until all test results achieve Passed (_checkmark_). 
* A formatted test report can be downloaded (.pdf or .xlsx) to submit with an FPKI Annual Review package or to archive. 

#### 1. Select Policy, Profile, and Version
1. Navigate to the [CPCT](https://cpct.app.cloud.gov/) website. <!--They're going to already be at the website, right?-->
2. At the main CPCT screen: 
- From the **Select a Policy** drop-down, pick the **X.509 Certificate Policy**. (The policy you select contains the requirements mandated for the Federal PKI Certification Authority (CA) that issued the certificate.)<br>
- From the **Version** drop-down, choose the **_Certificate Profile Version_** that applies to your test certificate.<br>
- From the **Profile** drop-down, choose the **Certificate Profile** that applies to your test certificate.<br>

#### 2. Upload a Certificate

* (Matt) Describe different ways to upload a certificate (text, file upload, drag-and-drop)

You can upload a test certificate in 3 ways:
1. Drag-and-drop
     - Go to the certificate you want to upload and click on it.
     - Drag and drop it to anywhere on the main CPTC screen.  
<**Can CPCT give a system upload acknowledgment like "Certificate Uploaded!" or "Got it!" or "Uploaded!" to tell the user that the certificate has been uploaded?**>
2. File upload - **explain**
3. Text Option??? - **How does the "text" option work?**
3. Click the **Upload Certificate** button. Navigate to your certificate and double-click it. [System message: _what happens?_]

## Report section?

* (Matt) Step through the different sections of the report and provide details
<**(CB) Sample output doesn't look like the current Certificate Profile Worksheets. Research further.**>

***CB ADD NEW TEXT TO BELOW FROM MS WORD FILE - 8/17/2018***

## Troubleshooting and Feature Request

* (Matt) Guide folks to use the GitHub issues page for requests.
* (Matt) Provide our icam@gsa.gov email address for any help or feature requests.  (CB) Use fpki@gsa.gov??

## Troubleshooting:  

### What If I Can't Resolve an Issue?

(Matt) Provide some steps folks will need to take if they experience issues. 

* Email your certificate to fpki@gsa.gov?? (will need to rename cert to .txt file extensions)
* Submit a GitHub issue and attach the certificate file to the issue. (User will need to create a github account in order to do this.)

* (Matt) I say the submit an issue and attach the file is the preferred approach.  [CB: What's our estimated response time on this one?  As soon as possible?]

* Email us at fpki@gsa.gov. We will respond as soon as possible.

(Matt) Provide steps if there is a discrepancy with the results (what happens if there is a false-positive or false-negative). 
* How does user identify a discrepancy?  By knowing that CPCT is showing a result that CAN'T BE Right?  Or how?
* What does a False Positive look like?  (Says the field or extension IS comformant when IT'S NOT??) (How would this occur?  How will user know it's a False Positive?)
* What does a False Negative look like? (Says the field or extension IS NOT conformant when IT IS??) (How would this occur?  How will the user know that it's a False Negative?)
* (Matt) Why might you see a discrepancy?  A few possible causes:  
     - A
     - B
     - C
* (Matt) Probably follow similar approach as bullet above.
