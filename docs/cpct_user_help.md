---
layout: default
title: Certificate Profile Conformance Tool (CPCT) Help
collection: docs
permalink: docs/userguide/
---

DRAFT -- DRAFT --- DRAFT

## What is the Certificate Profile Conformance Tool (CPCT)?
(Matt) (Background - summary of the tool)<br>

How often do you manually analyze certificates to see if they conform to Federal PKI certificate policies and profiles? If your answer is "often," then CPCT is for you. CPCT instantaneously does what previously demanded too much of your time. Not only that, but it clearly explains the cause for any nonconforming field/extension. Best of all (and what a relief), you can download a tidy Test Report (.xls or .pdf) to submit as part of an FPKI Annual Review (Audit) package or for QA archiving.

* [Who Needs CPCT?](#who-needs-cpct)
* [System and Application Requirements](#system-and-application-requirements)
* [How Does This Work?](#how-does-this-work)
* [Detailed Steps](#detailed-steps)
* [Download Test Report](#download-test-report)
* [Troubleshooting](#troubleshooting)
* [Feature Request](#feature-request)

## Who Needs CPCT?

If you analyze Federal PKI certificates, then you need CPCT. Some groups that might find it especially useful are:

1. **Agencies/organizations preparing FPKI Annual Review Packages -** You can use CPCT to test certificates and download Test Reports to submit in an FPKI Annual Review package.  (See [FPKI Annual Review requirements](#https://www.idmanagement.gov/fpki-cas-audit-info/#annual-audit-reqs-all-cas){:target="_blank"} for more details.)
2. **PIV or SSL/TLS Certificate Issuers** - You can test certificates as part of your Quality Assurance process.
3. **Subscribers** - You can determine which organization needs to correct certificate failures.

## System and Application Requirements

* Windows - No special requirements <**Windows 10 best?**>
* macOS - No special requirements
* Android Devices - Not recommended for CPCT use
* iOS Devices - Not recommended for CPCT use
<**Any other system or application requirements?**>
<**Do recommend/not recommend certain browsers for using the tool?**> (Displays may differ...?)

## How Does This Work?

{% include alert-info.html content="CPCT use requires in-depth familiarity with certificate profiles and certificates." %}

Here's how CPCT works:

**THIS IDEA BETTER?**
* From the CPCT main screen, you need to first select the applicable profile document, version, and certificate profile against which to test your certificate. Then, upload the certificate. CPCT immediately produces on-screen, compliance test results with a _pass_ (checkmark) or _FAIL (with explanation)_ status for each field and extension. CPCT offers a formatted Test Report (.xls or .pdf) for download. You can submit the Test Report with a Federal PKI Annual Review package or use/retain it for your organization's needs. 

**OR THIS IDEA BETTER?**

* From the [CPCT main screen](https://cpct.app.cloud.gov/){:target="_blank"}, first select the document and profile related to the certificate you want to test. Then, upload the certificate using drag-and-drop or the **Upload** button. 

* CPCT instantaneously shows you the detailed test results. A green status bar summarizes the test outcome--either _Tested [n] fields: No Problems detected_ or _Tested [n] fields: [n] problems detected_. 

* In the **Analysis** column, a checkmark is shown for _passed_ or the word, _FAIL (with explanation)_, if there was problem.

* Retesting is unlimited. Once you've completed testing, you can download a Test Report (e.g., to submit with an Federal PKI Annual Review package), use/retain it as part of your QA process, or use it for your organization's specific needs. 

* CPCT analyzes your certificate and displays the test results instantaneously. Each field and extension displays either a **checkmark** for _PASS_ **OR** a _FAIL (with explanation)_. 

* You can download a Test Report (.xls or .pdf) to submit with an FPKI Annual Review package or to archive. 

### Detailed Steps
(Matt) How to use the tool section.  Describe the meaning and purpose of each of the drop-down lists.

CPCT is a friendly tool that provides instantaneous results.  What more could you ask for?  Just follow the steps below.  If you need help, please [Contact Us](https://github.com/GSA/fpkilint/blob/dev/docs/cpct_contact_us.md){:target="_blank"}_.

#### 1. Select Profile Documents

a. Have an exported certificate ready to upload. _Your certificate type should be .ctr, .pem, .cer, or .der._
b. Navigate to [CPCT](https://cpct.app.cloud.gov/). Select from the 3 drop-downs:<br><br>
     o **Profile Document** related to your certificate (e.g., _Common Policy SSP Program_) (short name for the _X.509 Certificate and Certificate Revocation List [CRL] Extensions Profile for the Shared Service Providers [SSP] Program_.<br>
     o **Document Version** (e.g., _v1.8_).<br>
     o **Certificate Profile** (e.g., _PIV Authentication_)<br>

---Main Screen capture here?---

#### 2. Upload a Certificate

* (Matt) Describe different ways to upload a certificate (text, file upload, drag-and-drop)

Upload your certificate in one of 3 options:

1. **Drag-and-drop:** Browse to the exported certificate on your computer. Drag-and-drop it to anywhere on the CPCT main screen. _CPCT uploads the certificate and displays the test results._
2. **File upload:** Click on the **Upload Certificate** button.  Browse to the exported certificate. Click the certificate and then **Open.** _CPCT uploads the certificate and displays the test results._
3. **Text option:** - <**How does this option work?**>
> **Note:** After you upload a certificate, notice that the CPCT drop-downs are now at the top of the test results screen. You can use these options to upload more certificates. (No need to return to the main screen.) 

Insert screen capture -> test_results_top_of_screen_no_name.png

## Test Results

* (Matt) Step through the different sections of the [results? and...] report and provide details.

Details about the **Test Results** screen:

1. The certificate name displays at the top line, followed by the related Certificate Profile Document title and Profile name. A link to the Certificate Profile Document enables you to quickly reference it.
1. The green status bar states: _Tested [n] fields: No Problems detected_ or _Tested [n] fields: [n] problems detected_. 
>_When corrections to a certificate are needed, retests are unlimited._
1. To download a formatted Test Report, click the **XLS** or **PDF** button below the green status bar. _The downloadable Test Report displays. Save it to your computer.
1. The **Field** column lists the attribute names.  _These match the fields listed in the certificate profile._ <**Only Field, no Extension label...**>
1. The **Content** column lists the detailed certificate contents of each field or extension.
1. The **Analysis** column shows either a checkmark (i.e., _passed_) or _FAIL (with an explanation)_ for each field or extension.


## Download Test Report

1. While at the Test Results screen, you can download a formatted Test Report. Click on the **XLS** or **PDF** button below the green status bar.
> _The Test Report displays. **Note:** It will not resemble the Certificate Profile Worksheet format.
<**Matt?  (CB) Step through test report sections and provide details also in addition to test results screen?**>
1. Save the test report to your preferred download location.
<**(CB) Should we explain that the sample test report doesn't resemble the current Certificate Profile Worksheets.**> 

## Troubleshooting

* (Matt) Guide folks to use the GitHub Issues page for requests.
* (Matt) Provide our icam@gsa.gov email address for any help or feature requests.  (CB) Use fpki@gsa.gov??

### CPCT Error Messages

Some system errors you might encounter:

* _You can't upload files of this type_. **Cause:** CPCT doesn't recognize the certificate file type that you're trying to upload. CPCT accepts: **.crt**, **.cer**, **.pem**, and **.der** file types.
* <**Any other system errors that might appear?**>

### Certificate Errors

* _[X number of] problems detected_ (Test Results display's green banner). **Possible causes:** either _X number of_ fields (and/or extensions) do not conform to the selected profile, _OR_ the selected Profile Document, Document Version, and/or Profile do not correlate to this certificate.

### Possible Discrepancies
(Matt) Provide steps if there is a discrepancy with the results (what happens if there is a false-positive or false-negative). 
----
**Questions for Matt:**
* How does a user identify a discrepancy? 
* What does a False Positive look like?  (Test Report says the field or extension IS conformant when IT'S NOT? How would this occur? The user knew before the test that it didn't conform?)
* What does a False Negative look like? (Test Report says the field or extension IS NOT conformant when IT IS? How would this occur?  The user is certain that it is conformant and so knows the test result is wrong?)

<**(Matt) Why might you see a discrepancy?  A few possible causes:**>
<**These are guesses for the user. Others?**>
     - A - One or more drop-down selections might be incorrect. _Please check your selections for Profile Document, Document Version, or Profile drop-downs._
     - B - CPCT doesn't recognize the test certificate's file type. _Accepted file types are .ctr, .pem, cer., or .der._
     - C - The test certificate is expired. _Please check the certificate's Validity Period._
     - D - **Other reasons?**
     - E - Possible CPCT application error.  _Please [Contact Us](https://github.com/GSA/fpkilint/blob/dev/docs/cpct_contact_us.md){:target="_blank"}_.
* <!--(Matt) Probably follow similar approach as bullet above.-->If you can't resolve an issue and need help, please see [What If I Can't Resolve an Issue](#what-if-i-cant-resolve-an-issue).

If you think a Test Result may be incorrect (e.g., a "false positive" or "false negative"), please [Contact Us](https://github.com/GSA/fpkilint/blob/dev/docs/cpct_contact_us.md){:target="_blank"}. 

### What If I Can't Resolve an Issue?

* (Matt) Provide some steps folks will need to take if they experience issues. I say the submit an issue and attach the file is the preferred approach. 
 
* Submit a GitHub issue [CPCT Repository](https://github.com/GSA/fpkilint){:target="_blank"} and attach the certificate file to the issue. **Note:**&nbsp;&nbsp;You'll need a GitHub account to do this. If you don't have an account:  [Add Create a GitHub account link](#www.github.com?).<br>
**_OR_**<br>
* Email us at fpki@gsa.gov and attach your certificate. (**Note:**&nbsp;&nbsp;Please rename your certificate with **.txt** file extension.) 

We will respond as soon as possible.

## Feature Request

If you would like to request a new CPCT feature, please [Contact Us](https://github.com/GSA/fpkilint/blob/dev/docs/cpct_contact_us.md){:target="_blank"}.
