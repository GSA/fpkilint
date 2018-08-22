---
layout: default
title: Certificate Profile Conformance Tool (CPCT) Help
collection: docs
permalink: docs/userguide/
---

STILL DRAFTING -- DRAFT --- DRAFT

## What is the Certificate Profile Conformance Tool (CPCT)?
(Matt) (Background - summary of the tool)<br>

If you analyze certificates for conformance to Federal PKI Certificate Profiles, then CPCT will make your life so much easier. CPCT instantaneously does what previously demanded too much of your time. Not only that, but it clearly explains the cause for any nonconforming field or extension. Best of all (and what a relief), you can download a test report to submit or archive. 

* [Who Needs CPCT?](#who-needs-cpct)
* [How Does This Work?](#how-does-this-work)
* [System and Application Requirements](#system-and-application-requirements)
* [Detailed Steps](#detailed-steps)
* [Test Reports](#test-reports)
* [Troubleshooting](#troubleshooting]
* [Feature Request](#feature-request)

## Who Needs CPCT?

We invite you to use CPCT if your agency/organization needs to analyze FPKI certificates for conformance. Some groups that might find CPCT very useful are:

1. **Agencies/organizations preparing FPKI Annual Review Packages -** You can test certificates and download formatted CPCT test reports to submit in an FPKI Annual Review package.  (See [FPKI Annual Reviews](#https://www.idmanagement.gov/fpki-cas-audit-info/#annual-audit-reqs-all-cas){:target="_blank"} for more details.)
2. **PIV or SSL/TLS Certificate Issuers** - As part of a QA process, you can test your certificates for conformance.
3. **Subscribers** - You can view test report failures to determine which organization needs to correct them.

## How Does This Work?

If you regularly work with certificates, CPCT will not be complex. (**Note:**&nbsp;&nbsp;To use CPCT, you will need to be familiar with exporting certificates, certficate details, profile types, worksheets, fields, and extensions, etc.) If you work less frequently with certificates and need additional help, please contact us at fpki@gsa.gov.

Here's how it works:

* Simply upload a certificate and select a **Profile Document** (e.g., _FPKI X.509 Certificate and CRL Extensions Profile_), **Document Version**, and **Certificate Profile** title. 

* CPCT analyzes your certificate and displays the test results. Each **field and extension** will show _PASS_ or _FAIL with explanations_. <**CB: Check to see whether "Extensions" exist in the test results form.**>

* CPCT explains each failure so you can correct it. (Retests are unlimited.)

* When you want to submit test reports for FPKI Annual Reviews or archive them, you can download a test report in .pdf or .xls. 

## System and Application Requirements

* Any operating system or application requirements to use CPCT?  <**Windows and macOS both work?**>
* Do recommend certain browsers for using the tool? (Displays may differ...?)

### Detailed Steps
(Matt) How to use the tool section.  Describe the meaning and purpose of each of the drop-down lists (Policy, Version, Profile



#### 1. Select Policy, Profile, and Version

1. Have your exported certificate (.cer) file ready to upload to CPCT.
1. Navigate to the [CPCT](https://cpct.app.cloud.gov/) website. 

---Main Screen capture here?---

1. At the main CPCT screen:  from the top drop-down, pick the governing **Profile Document** related to your test certificate (for example, **_Common Policy SSP Program_** [short name]).<br>
1. At the second drop-down, pick the **Profile Document _Version_** number (for example, **_v1.8_**).<br>
1. At the third drop-down, pick the **Certificate Profile** that applies to the certificate (for example, **_PIV Authentication_**).<br>

#### 2. Upload a Certificate

* (Matt) Describe different ways to upload a certificate (text, file upload, drag-and-drop)

Once you've picked the selections above, you can upload a test certificate in 3 ways:
1. **Drag-and-drop:**  Go to the exported certificate saved on your computer. Drag and drop it to anywhere on the CPCT main screen. 
2. **File upload:** Click on the **Upload Certificate** button.  Navigate via Windows Explorer to the exported certificate saved on your computer. Click it and then click **Open.**
3. **Text option**??? - **How does the "text" option work?**
> In all 3 cases, the certificate test results appear. 

----screen capture here?----

## Test Results

* (Matt) Step through the different sections of the [results? and...] report and provide details.
1. **CB:  Step through the test results in non-download results file.**

## Test Report for Download
1. While viewing the certificate test results, you can download a certificate test report for submission. Click on the **XLS** or **PDF** button (upper left of test results).
> The test report appears in a compact format.
<**CB:  step through test report sections and provide details**>
1. Save the test report to your preferred download location.
<**(CB) Sample test report doesn't resemble the current Certificate Profile Worksheets. Explain? Note that here is a line wrap problem with very long lines--see CRL Distribution Points field. All in left-hand column are labeled as "Field"; none are labeled "Extension," yet extensions exist within this list.**>

## Troubleshooting

* (Matt) Guide folks to use the GitHub issues page for requests.
* (Matt) Provide our icam@gsa.gov email address for any help or feature requests.  (CB) Use fpki@gsa.gov??

(Matt) Provide steps if there is a discrepancy with the results (what happens if there is a false-positive or false-negative). 
* How does user identify a discrepancy?  By knowing that CPCT is showing a result that CAN'T BE Right because the user knew a field would FAIL?  Or how?
* What does a False Positive look like?  (Test Report says the field or extension IS conformant when IT'S NOT?? How would this occur? The user knows that it doesn't conform? How will user know it's a False Positive?)
* What does a False Negative look like? (Test Report says the field or extension IS NOT conformant when IT IS?? How would this occur?  How will the user know that it's a False Negative? The user knows that it is conformant and so knows the test and result are wrong?)
* (Matt) Why might you see a discrepancy?  A few possible causes: <**Matt: I don't know what the causes would be. Please provide causes.**> 
     - A
     - B
     - C
* <!--(Matt) Probably follow similar approach as bullet above.-->If you can't resolve an issue with the test results, see [What If I Can't Resolve an Issue](#what-if-i-cant-resolve-an-issue) below.

### What If I Can't Resolve an Issue?

* (Matt) Provide some steps folks will need to take if they experience issues. I say the submit an issue and attach the file is the preferred approach. 
 
* Submit a GitHub issue [CPCT Repository](https://github.com/GSA/fpkilint){:target="_blank"} and attach the certificate file to the issue. **Note:**&nbsp;&nbsp;You'll need a GitHub account to do this. If you don't have an account:  [Add Create a GitHub account link](#www.github.com?).<br>
**_OR_**<br>
* Email us at fpki@gsa.gov and attach your certificate. (**Note:**&nbsp;&nbsp;Please rename your certificate with **.txt** file extension.) 

We will respond as soon as possible.

## Feature Request

To request a new feature for CPCT:

* Submit a GitHub issue to request a new feature: [CPCT Repository](https://github.com/GSA/fpkilint){:target="_blank"}.<br>
**_OR_**<br>
* Email us at fpki@gsa.gov. 
