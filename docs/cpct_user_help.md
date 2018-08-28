---
layout: default
title: Certificate Profile Conformance Tool (CPCT) Help
collection: docs
permalink: docs/userguide/
---
**NEW NEW CHANGES 8-28-2018 1812 – CELESTE PRIOR TO GITHUB CRASH RECOVERED FROM MS WORD FILE**
**CB - VALIDATE CHANGES ON 9/4/2018 UPON RETURN FROM PTO**

## What is the Certificate Profile Conformance Tool (CPCT)?

Do you manually analyze Federal PKI certificates to see if they conform to certificate profiles? If you do, then the Certificate Profile Conformance Tool (CPCT) is for you. 

CPCT instantaneously does what previously demanded too much of your time&nbsp;&mdash;&nbsp;manual analysis. Not only that, but CPCT clearly explains the cause for any nonconformance in a certificate. Best of all (and what a relief), you can download a formatted Test Report (.xls or .pdf) to submit as part of an FPKI Annual Review (Audit) package or for agency/organization-specific needs.

* [Who Needs CPCT?](#who-needs-cpct)
* [System and Application Requirements](#system-and-application-requirements)
* [How Does This Work?](#how-does-this-work)
* [Detailed Steps](#detailed-steps)
* [Download Test Report](#download-test-report)
* [Troubleshooting](#troubleshooting)
* [Feature Request](#feature-request)

## Who Needs CPCT?

These groups may find CPCT especially useful: 

1. _Agencies/organizations preparing FPKI Annual Review Packages_ - CPCT will help you to test certificates and download Test Reports to submit in an FPKI Annual Review package.  (See [FPKI Annual Review requirements](#https://www.idmanagement.gov/fpki-cas-audit-info/#annual-audit-reqs-all-cas){:target="_blank"} for more details.)
2. _PIV or SSL/TLS Certificate Issuers_ - CPCT will help you to test certificates as part of a Quality Assurance process.
3. _Subscribers_ - CPCT will help you to determine which organization needs to correct certificate failures.

## System and Application Requirements - Is this needed?

* Android Devices - Not recommended for CPCT use
* iOS Devices - Not recommended for CPCT use
<**Browsers for best display?**>

## How Does This Work?

{% include alert-info.html content="In-depth experience with Federal PKI certificates and certificate profiles is recommended." %}

CPCT analyzes a certificate in just a few simple steps:  

* From the CPCT main screen, pick from the 3 drop-downs the Profile Document, Document Version, and Certificate Profile related to your certificate. Then, upload your certificate. 

* CPCT immediately displays the certificate's test results. Each field and extension shows a _PASS_ (a checkmark) or _FAIL (with explanation)_. (See the [Detailed Steps](#detailed-steps) for more information.)

* At any time, you can download a formatted Test Report (.xls or .pdf). Test Reports can be submitted with Federal PKI Annual Review packages or retained for your organization's needs. 

## Detailed Steps

1. Navigate to [CPCT](https://cpct.app.cloud.gov/). 
2. From the 3 drop-downs, pick:<br>
     o    **Profile Document** (e.g., Common Policy SSP Program) (short name for the _X.509 Certificate and Certificate Revocation List [CRL] Extensions Profile for the Shared Service Providers [SSP] Program_).<br>
     o    **Document Version** (e.g., v1.8).<br>
     o    **Certificate Profile** (e.g., PIV Authentication)<br>

---Main Screen capture here?---

3. Next, upload your certificate (as a .ctr, .pem, .cer, or .der file) using one of these options:

     o **Drag-and-drop** your certificate to anywhere on the CPCT main screen.<br> 
     > CPCT uploads the certificate and displays the test results.<br>
     o Click the **Upload Certificate** button, browse to the certificate, and click it. Then, click **Open.**<br> 
     > CPCT uploads the certificate and displays the test results.<br>
     
{% include alert-info.html content="Notice that CPCT's 3 main drop-downs appear at the top of the Test Results screen. You can use these to easily test additional certificates." %}

---Insert test_results_top_of_screen_no_name.png?--

4. Review your certificate's Test Results.

{% include alert-info.html content="The test results do not visually resemble the Certificate Profile Worksheet; however, all Worksheet requirements are addressed." %}

At the top of the Test Results screen, the status bar (green for "conformant"; red for "has a problem") gives the summary test result: 

* **Tested [n] fields: No Problems detected** 
_OR_ 
* **Tested [n] fields: [n] problems detected**

The Test Results columns are:

* **Field** - Lists the field and extensions.
* **Content** - Lists the certificate details for each field or extension.
* **Analysis** - For each field and extension, shows a checkmark (for _PASS_) or the word, _FAIL_ (with an explanation), for each field and extension.

6. If the certificate's test results are conformant, you may want to download a formatted Test Report.

7. Click the **XLS** or **PDF** button below the green status bar. 

8. Save the displayed Test Report to your preferred location.

<!--(CB) Compare test results screen with downloadable Test Report to see differences-->

## Troubleshooting

### Error Messages

You could encounter these system error messages:

* **You can't upload files of this type.** 
> **Cause:** CPCT doesn't recognize the certificate file type. The allowable file types are: .crt, .cer, .pem, and .der.
* <**Any other system errors that could appear?**>

### Certificate Errors

* **Tested [n] fields: [n] problems detected** displayed in the Test Results' red banner. 
> **Possible causes:** one or more fields or extensions do not conform, _OR_ the selected Profile Document, Document Version, and/or Certificate Profile do not pertain to this certificate.
* _FAIL (with explanation)_
> **Cause:** This message appears in the **Analysis** column when a field/extension does not conform.

### Other Problems/Discrepancies

If you encounter a problem or discrepancy, please review this list for corrective actions:

* The selected Profile Document, Document Version, or Certificate Profile may be incorrect for your certificate.
* CPCT doesn't recognize the certificate's file type. (Allowable file types are: .ctr, .pem, cer., and .der.)
* The test certificate has expired. Please check the certificate's Validity Period.
* Possible CPCT application error.  Please [contact us](https://github.com/GSA/fpkilint/blob/dev/docs/cpct_contact_us.md){:target="_blank"}.

If you think a test result may be incorrect (e.g., a "false positive" or "false negative"), please [contact us](https://github.com/GSA/fpkilint/blob/dev/docs/cpct_contact_us.md){:target="_blank"}. 

### What If I Can't Resolve an Issue?
 
* Create a GitHub issue in the [CPCT Repository](https://github.com/GSA/fpkilint){:target="_blank"} and attach the certificate to the issue. (**Note:**&nbsp;&nbsp;You'll need a GitHub account to do this. If you don't have an account, see [Add Create a GitHub account link](#www.github.com?).)<br>
_OR_<br>
* Email us at fpki@gsa.gov and attach your certificate. (**Note:**&nbsp;&nbsp;Please rename your certificate with **.txt** file extension.) 

We will respond as soon as possible.

## Feature Request

If you would like to request a new CPCT feature, please [contact us](https://github.com/GSA/fpkilint/blob/dev/docs/cpct_contact_us.md){:target="_blank"}.





------
OLDER VERSION FROM 8-28-2018 1337 PRIOR TO GITHUB CRASH
## What is the Certificate Profile Conformance Tool (CPCT)?
<**(Matt) Background - summary of the tool**>

How often do you manually analyze Federal PKI certificates to see if they conform to certificate policies and profiles? If your answer is _often_, then the Certificate Profile Conformance Tool (CPCT) is for you. 

CPCT instantaneously does what previously demanded too much of your time&nbsp;&mdash;&nbsp;analyzing certificates for conformance. Not only that, but CPCT clearly explains the cause for any nonconforming field or extension in a certificate. Best of all (and what a relief), you can download a formatted Test Report (.xls or .pdf) to submit as part of an FPKI Annual Review (Audit) package or for agency/organization-specific needs.

* [Who Needs CPCT?](#who-needs-cpct)
* [System and Application Requirements](#system-and-application-requirements)
* [How Does This Work?](#how-does-this-work)
* [Detailed Steps](#detailed-steps)
* [Download Test Report](#download-test-report)
* [Troubleshooting](#troubleshooting)
* [Feature Request](#feature-request)

## Who Needs CPCT?

If you analyze Federal PKI certificates for conformance, then CPCT is for you. These groups may find CPCT especially useful:

1. **Agencies/organizations preparing FPKI Annual Review Packages -** CPCT will help you to test certificates and download Test Reports to submit in an FPKI Annual Review package.  (See [FPKI Annual Review requirements](#https://www.idmanagement.gov/fpki-cas-audit-info/#annual-audit-reqs-all-cas){:target="_blank"} for more details.)
2. **PIV or SSL/TLS Certificate Issuers** - CPCT will help you to test certificates as part of a Quality Assurance process.
3. **Subscribers** - CPCT will help you to determine which organization needs to correct certificate failures.

## System and Application Requirements

* Windows - No special requirements <**Windows 10 best?**>
* macOS - No special requirements
* Android Devices - Not recommended for CPCT use
* iOS Devices - Not recommended for CPCT use
<**Any other application or browser requirements? Browsers for best display?**>

## How Does This Work?

{% include alert-info.html content="In-depth experience is recommended when working with Federal PKI certificates and certificate profiles." %}

CPCT is a friendly tool that analyzes a certificate in just a few simple steps:  

* From the CPCT main screen, you pick from the 3 drop-downs: a Certificate Profile Document, Version number, and Certificate Profile against which to test a certificate. Then, upload your certificate. 

* CPCT immediately displays on-screen, test results. Each field and extension shows a _PASS_ (a checkmark) or _FAIL (with explanation)_. (See the [Detailed Steps](#detailed-steps) for more information.)

* At any time, you can download a formatted Test Report (.xls or .pdf). Successful Test Reports can be submitted with a Federal PKI Annual Review package or retained for your organization's needs. 

### Detailed Steps
<**(Matt) How to use the tool section.  Describe the meaning and purpose of each of the drop-down lists.**>

#### 1. Select Profile Documents

a. First, have an exported certificate ready to upload. _Your certificate type should be .ctr, .pem, .cer, or .der._<br>
b. Then, navigate to [CPCT](https://cpct.app.cloud.gov/). From the 3 drop-downs on the main screen, pick:<br><br>
     o    a **Profile Document** related to your certificate (e.g., _Common Policy SSP Program_) (short name for the _X.509 Certificate and Certificate Revocation List [CRL] Extensions Profile for the Shared Service Providers [SSP] Program_.<br>
     o    a **Document Version** (e.g., _v1.8_).<br>
     o    a **Certificate Profile** (e.g., _PIV Authentication_)<br>

---Main Screen capture here?---

#### 2. Upload a Certificate

* (Matt) Describe different ways to upload a certificate (text, file upload, drag-and-drop)

Next, you can upload your certificate by using any of these options:

1. **Drag-and-drop:** Browse to the exported certificate on your computer. Drag-and-drop it to anywhere on the CPCT main screen. _CPCT uploads the certificate and displays the test results._
2. **File upload:** Click on the **Upload Certificate** button.  Browse to the exported certificate. Click the certificate and then **Open.** _CPCT uploads the certificate and displays the test results._
3. **Text option:** - <**How does this option work?**>
> **Note:** After you upload a certificate, notice that the CPCT drop-downs are now at the top of the test results screen. You can use these options to upload more certificates. (No need to return to the main screen.) 

Insert screen capture -> test_results_top_of_screen_no_name.png

## 3. Review Test Results and Make Corrections (as needed)

<**(Matt) Step through the different sections of the results? and report and provide details.**>

{% include alert-info.html content="Notice that CPCT's 3 main drop-downs appear at the top of the screen. You can use these to easily test additional certificates. A quick reference link is also given to your certificate's Certificate Profile Document." %}

*  
* Your _certificate name_ also appears, as well as the related _Certificate Profile Document_ and _Profile names_. 
* A handy link is provided to the _Certificate Profile Document_ for quick reference.

### Test Results Details

{% include alert-info.html content="The test results do not visually resemble the Certificate Profile Worksheet format; however, all Worksheet requirements are addressed." %}

* The green status bar (i.e., test outcome) states either:<br><br> 
     o **_Tested [n] fields: No Problems detected_**<br> 
     _OR_<br> 
     o **_Tested [n] fields: [n] problems detected_**<br><br>
* **Field** column - lists attribute names.  _These match the fields and extensions listed in the certificate profile._
* **Content** column - lists certificate details for each field or extension.
* **Analysis** column - shows either a checkmark (_PASS_) or _FAIL (with an explanation)_ for each field and extension.

**Note:**&nbsp;&nbsp;Any _FAIL (with explanation)_ shown in the **Analysis** column must be corrected and the certificate retested. _A conformant certificate will have a **checkmark** (PASS) in the **Analysis** column for every field and extension, and the green status bar will state: **Tested [n] fields: No Problems detected**._

## Download Test Report

<!--(CB) Compare test results screen with downloadable Test Report to see if differences-->

If the certificate's test results all look good, you may want to download a formatted Test Report. 

1. Click the **XLS** or **PDF** button below the green status bar. _The downloadable Test Report displays. Save it to your computer.
1. Save the test report to your preferred download location.

## Troubleshooting

* (Matt) Guide folks to use the GitHub Issues page for requests.
* (Matt) Provide our icam@gsa.gov email address for any help or feature requests.  (CB) Use fpki@gsa.gov??

### Error Messages

Some system errors you might encounter:

* _You can't upload files of this type_. **Cause:** CPCT doesn't recognize the certificate file type that you're trying to upload. CPCT accepts: **.crt**, **.cer**, **.pem**, and **.der** file types.
* <**Any other system errors that might appear?**>

### Certificate Errors

* _[X number of] problems detected_ (Test Results display's green banner). **Possible causes:** either _X number of_ fields (and/or extensions) do not conform to the selected profile, _OR_ the selected Profile Document, Document Version, and/or Profile do not correlate to this certificate.
* _FAIL (with explanation)_ - **Cause:** This message appears in the test results' **Analysis** column if a field or extension does not conform to the Certificate Profile Document and/or Certificate Profile Worksheet.

### Other Problems/Discrepancies
<**(Matt) Provide steps if there is a discrepancy with the results (what happens if there is a false-positive or false-negative). (Matt) Why might you see a discrepancy?  A few possible causes**>

If you encounter a problem or discrepancy, please review this list for corrective actions:

* One or more drop-down selections might be incorrect. _Please check your selections for Profile Document, Document Version, or Profile drop-downs._
* CPCT doesn't recognize the test certificate's file type. _Accepted file types are .ctr, .pem, cer., or .der._
* The test certificate has expired. _Please check the certificate's Validity Period._
* Possible CPCT application error.  _Please [Contact Us](https://github.com/GSA/fpkilint/blob/dev/docs/cpct_contact_us.md){:target="_blank"}_.
* You think a test result may be incorrect (e.g., a "false positive" or "false negative"). _Please [Contact Us](https://github.com/GSA/fpkilint/blob/dev/docs/cpct_contact_us.md){:target="_blank"}._ 

### What If I Can't Resolve an Issue?

* (Matt) Provide some steps folks will need to take if they experience issues. I say the submit an issue and attach the file is the preferred approach. 
 
* Submit a GitHub issue [CPCT Repository](https://github.com/GSA/fpkilint){:target="_blank"} and attach the certificate file to the issue. **Note:**&nbsp;&nbsp;You'll need a GitHub account to do this. If you don't have an account:  [Add Create a GitHub account link](#www.github.com?).<br>
**_OR_**<br>
* Email us at fpki@gsa.gov and attach your certificate. (**Note:**&nbsp;&nbsp;Please rename your certificate with **.txt** file extension.) 

We will respond as soon as possible.

## Feature Request

If you would like to request a new CPCT feature, please [Contact Us](https://github.com/GSA/fpkilint/blob/dev/docs/cpct_contact_us.md){:target="_blank"}.
