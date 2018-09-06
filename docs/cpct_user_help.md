---
layout: default
title: Certificate Profile Conformance Tool (CPCT) Help
collection: docs
permalink: docs/userguide/
---

## What is the Certificate Profile Conformance Tool (CPCT)?

Do you often need to analyze Federal PKI certificates for conformance to certificate profiles? If your answer is _yes_, then the Certificate Profile Conformance Tool (CPCT) is for you.

CPCT is a friendly tool that instantaneously analyzes a certificate and displays its conformance results. Not only that&nbsp;-&nbsp;CPCT clearly explains the reason for any nonconformance. What's more (and what a relief), you can download a formatted Test Report (.xls or .pdf) to submit as part of an Federal PKI Annual Review package or retain for specific needs. 

* [Who Needs CPCT?](#who-needs-cpct)
* [Operating System Requirements](#operating-system-requirements)
* [How Does This Work?](#how-does-this-work)
* [Detailed Steps](#detailed-steps)
* [Troubleshooting](#troubleshooting)
* [Feature Request](#feature-request)

## Who Needs CPCT?

These organizations may find CPCT especially useful: 

1. **Agencies/organizations preparing FPKI Annual Review Packages** can test certificates and download Test Reports to submit.
2. **PIV or SSL/TLS Certificate Issuers** can test certificates as part of a QA process.
3. **Subscribers** can determine who should correct certificate failures.

## Operating System Requirements
* Windows or macOS
* iOS - Not recommended for CPCT
* Android - Not recommended for CPCT

## How Does This Work?

{% include alert-info.html content="In-depth experience with Federal PKI certificates and certificate profiles is recommended." %}

CPCT analyzes a certificate in just a few simple steps:  

* From the CPCT main screen, pick from the 3 drop-downs the **Profile Document**, **Document Version**, and **Certificate Profile** related to a certificate. Then, upload the certificate. 

* CPCT displays the certificate's test results. The results status bar will be either _green_ (conforms) or _red_ (doesn't conform). Each field and extension will show either a _PASS_ (a checkmark) or _FAIL (with explanation)_. 

* You can download a formatted Test Report (.xls or .pdf) to submit as part of an Federal PKI Annual Review packages or to retain for specific needs. 

## Detailed Steps
<!--The short names aren't ideal. "Common Policy" doesn't appear in the actual policy's title, as well as "Federal Bridge" doesn't appear in actual policy's title. For normal publications, prior to use or at least in a footnote, short names should be defined as full titles first, followed by "(short name: xxxx)". Here, I've added footnotes with actual titles for clarity and publications correctness of referencing.-->
#### Select Profile Documents
* Navigate to [CPCT](https://cpct.app.cloud.gov/). 
* From the 3 drop-downs, pick:<br>
     o    **Profile Document** (The options are short names for the Profile Documents: _Common Policy SSP Program_<sup>[1](#1)</sup>; _Federal PKI/Federal Bridge_<sup>[2](#2)</sup>; _PIV Interoperable (PIV-I)_<sup>[3](#3)</sup>.)<br>
     o    **Document Version** (The most recent Version will set automatically when you select the Profile Document.)<br>
     o    **Certificate Profile** (e.g., PIV Authentication)<br>

#### Upload a Certificate
* Next, upload your certificate (as a .ctr, .pem, .cer, or .der file) using either of these options:

     o **Drag-and-drop** your certificate to anywhere on the CPCT main screen. _Test results display for the uploaded certificate._<br>
     o Click the **Upload Certificate** button, browse to the certificate, and click it. Then, click **Open.** _Test results display for the uploaded certificate.<br>
     
{% include alert-info.html content="Notice that the Test Result screen includes the CPCT drop-downs so you can easily upload more certificates." %}

#### Review Certificate Test Results

* At the top of the Test Results screen, a status bar will be _green_ (conformant) or _red_ (nonconformant). The status bar will also tell you the overall result: 

* **Tested [n] fields: No Problems detected** 
_OR_ 
* **Tested [n] fields: [n] problems detected**

The Test Results columns are:

* **Field** - Lists fields AND extensions.
* **Content** - Lists field and extension details.
* **Analysis** - For each field and extension, this column shows a checkmark (for _PASS_) or _FAIL (with an explanation)_.

#### Download a Test Report
* To download a formatted Test Report, click the **XLS** or **PDF** button below the status bar. 

## Troubleshooting

### Certificate Errors

* **Tested [n] fields: [n] problems detected**. _1. One or more fields or extensions do not conform; 2. The wrong Profile Document, Document Version, and/or Certificate Profile were selected._; or 3. Another problem exists.
* **FAIL (with explanation)** shown in the **Analysis** column. _The field or extension doesn't conform._

### Possible Error Messages

* **You can't upload files of this type.** _CPCT doesn't recognize the certificate file type. The allowable file types are: .crt, .cer, .pem, and .der._

### Other Problems or Discrepancies

If you encounter a problem or discrepancy:

* Check to make sure that you selected the right Profile Document, Document Version, and Certificate Profile.
* CPCT doesn't recognize the certificate file type. _Allowable file types are: .ctr, .pem, cer., and .der._
* Check the certificate's Validity Period. The test certificate may have expired.<!--Would this show up as a "problem" in the status bar with a "FAIL" for Validity Period"?--> 
* Think there might be an application error?  Please [contact us](https://github.com/GSA/fpkilint/blob/dev/docs/cpct_contact_us.md){:target="_blank"}.
* Think a test result may be incorrect (e.g., "false positive" or "false negative")? Please [contact us](https://github.com/GSA/fpkilint/blob/dev/docs/cpct_contact_us.md){:target="_blank"}. 

### What If You Can't Resolve an Issue?
 
* Create a GitHub issue in the [CPCT Repository](https://github.com/GSA/fpkilint){:target="_blank"} and attach the certificate to the issue. (**Note:**&nbsp;&nbsp;You need a GitHub account to do this. To create one: [Add Create a GitHub account link](#www.github.com?).)<br>
_OR_<br>
* Email us at fpki@gsa.gov and attach your certificate. (**Note:**&nbsp;&nbsp;Please rename your certificate with **.txt** file extension.) 

We will respond as soon as possible.

## Feature Request

If you would like to request a new CPCT feature, please [contact us](https://github.com/GSA/fpkilint/blob/dev/docs/cpct_contact_us.md){:target="_blank"}.

 for _X.509 Certificate and Certificate Revocation List [CRL] Extensions Profile for the Shared Service Providers [SSP] Program_
 
-------
<a name="1">1</a>. Short name for _X.509 Certificate and Certificate Revocation List (CRL) Extensions Profile for the Shared Service Providers (SSP) Program Policy_.<br>
<a name="2">2</a>. Short name for _Federal Public Key Infrastructure (PKI) X.509 Certificate and CRL Extensions Profile_.<br>
<a name="3">3</a>. Short name for _X.509 Certificate and Certificate Revocation List (CRL) Extensions Profile for Personal Identity Verification Interoperable (PIV-I) Cards_.<br>
