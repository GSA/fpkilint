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
* [System and Application Requirements](#system-and-application-requirements)
* [How Does This Work?](#how-does-this-work)
* [Detailed Steps](#detailed-steps)
* [Download Test Report](#download-test-report)
* [Troubleshooting](#troubleshooting]
* [Feature Request](#feature-request)

## Who Needs CPCT?

We invite you to use CPCT if your agency/organization needs to analyze FPKI certificates for conformance. Some groups that might find CPCT especially useful are:

1. **Agencies/organizations preparing FPKI Annual Review Packages -** You can test certificates and download formatted CPCT test reports to submit in an FPKI Annual Review package.  (See [FPKI Annual Reviews](#https://www.idmanagement.gov/fpki-cas-audit-info/#annual-audit-reqs-all-cas){:target="_blank"} for more details.)
2. **PIV or SSL/TLS Certificate Issuers** - As part of a QA process, you can test your certificates for conformance.
3. **Subscribers** - You can view test report failures to determine which organization needs to correct them.

## System and Application Requirements

* Any operating system or application requirements to use CPCT?  <**Windows and macOS both work?**>
* Do recommend certain browsers for using the tool? (Displays may differ...?)

## How Does This Work?

{% include alert-info.html content="To use CPCT, you should be knowledeable about certificates and certificate profiles. If you have questions, please email us at fpki@gsa.gov." %}

Here's how it works:

* Export a certificate to a location on your computer.

* From CPCT's main screen, click through the 3 drop-downs. Pick the related **Profile Document** (e.g., _FPKI X.509 Certificate and CRL Extensions Profile_), **Document Version** (e.g., v1.8), and **Certificate Profile** (e.g., PIV Authentication).

* You can upload a certificate in 3 ways:
     o Browse to your certificate; then drag-and-drop it to anywhere on the CPCT screen to upload.<br>
     **OR**<br>
     o Click the **Upload Certificate** button; browse to your certificate; and double-click it to upload.
     o **Text** method - <**How does this method work?**>

* CPCT analyzes your certificate and displays the test results. Each field and extension displays a **checkmark** for _PASS_ **OR** a **_FAIL_** (with explanation). 

* You can download a test report (.pdf or .xls) to submit with an FPKI Annual Review package or to archive. 

### Detailed Steps
(Matt) How to use the tool section.  Describe the meaning and purpose of each of the drop-down lists.

1. Have an exported certificate (.cer) ready to upload.
1. Navigate to [CPCT](https://cpct.app.cloud.gov/). 

#### 1. Pick Related Profile Documents

1. From the first drop-down, pick the **Profile Document** related to your certificate (for example, **_Common Policy SSP Program_** [short name]).<br>
1. At the second drop-down, pick the **Profile Document _Version_** number (for example, **_v1.8_**).<br>
1. At the third drop-down, pick the **Certificate Profile** that applies to the certificate (for example, **_PIV Authentication_**).<br>

---Main Screen capture here?---

#### 2. Upload a Certificate

* (Matt) Describe different ways to upload a certificate (text, file upload, drag-and-drop)

Once you've picked the profile documents, you can upload a certificate in 3 ways:

1. **Drag-and-drop:** Browse to the exported certificate on your computer. Drag-and-drop it to anywhere on the CPCT main screen. 
2. **File upload:** Click on the **Upload Certificate** button.  Navigate via Windows Explorer to the exported certificate saved on your computer. Click it and then click **Open.**
3. **Text option**??? - **How does this option work?**
> In all 3 cases, the certificate test results appear. 

----screen capture here?----

## Test Results

* (Matt) Step through the different sections of the [results? and...] report and provide details.

**CB:  Step through the test results in non-download results file.**

{% include alert-info.html content="Notice that the CPCT drop-downs appear at the top of the **Test Results** screen. You can use these to upload additional certificates without going back to the main CPCT screen." %}

----screen capture here?----

Details about the **Test Results** screen:
1. The certificate name displays at the top line, followed by the the Certificate Profile Document and Profile name you picked on the main screen for upload.  A hyperlink to the Certificate Profile Document enables you to quickly refer to it.
1. The green bar states how many Profile fields were tested, as well as "_No problems detected_" or "_X number of failures_". <**What does the message say if there are failures? Need a test certificate that will show failures to see this.**>
1. The **PDF** and **XLS** download buttons appear below the green bar. To download a test report, click the button for the format you want.
1. The **Field** column lists the attribute names, which match those in the related Certificate Profile. <**Only Field, no Extension label...?**>
1. The **Content** column.... <**Describe attribute details?**>
1. The **Analysis** column... <**Need HTML code for checkmark symbol to reproduce here**>


## Download Test Report

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
