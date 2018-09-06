---
layout: default
title: Certificate Profile Conformance Tool (CPCT) Help
collection: docs
permalink: docs/userguide/
---

<h2>What is the Certificate Profile Conformance Tool (CPCT)?</h2>

<p>Do you often need to analyze Federal PKI certificates for conformance to certificate profiles? If your answer is _yes_, then the Certificate Profile Conformance Tool (CPCT) is for you.</p>

<p>CPCT is a friendly tool that instantaneously analyzes a certificate and displays its conformance results. Not only that&nbsp;-&nbsp;CPCT clearly explains the reason for any nonconformance. What's more, you can download a formatted Test Report (.xls or .pdf) to submit as part of an Federal PKI Annual Review package or retain for your organization's needs.</p> 

<h2>Unordered List with Disc Bullets</h2>

<ul style="list-style-type:disc">
<li>[Who Needs CPCT?](#who-needs-cpct)</li>
<li>[Operating System Requirements](#operating-system-requirements)</li>
<li>[How Does This Work?](#how-does-this-work)</li>
<li>[Detailed Steps](#detailed-steps)</li>
<li>[Troubleshooting](#troubleshooting)</li>
<li>[Feature Request](#feature-request)</li>
</ul> 
<br>
<ol>
<li><b>Agencies/organizations preparing FPKI Annual Review Packages</b> - Use it to test certificates and download Test Reports.</li>
<li><b>PIV or SSL/TLS Certificate Issuers</b> - Use it to test certificates as part of a QA process.</li>
<li><b>Subscribers</b> - Use it to determine who should correct certificate failures.</li>
<li><b>Anyone who analyzes FPKI certificates for conformance</b>.</li>
</ol> 
<br>
<h2>Operating System Requirements</h2>

<ul style="list-style-type:disc"> 
<li>Windows or macOS</li>
<li>iOS - Not recommended for CPCT</li>
<li>Android - Not recommended for CPCT</li>
</ul> 

<h2>How Does This Work?</h2>

{% include alert-info.html content="In-depth experience with Federal PKI certificates and certificate profiles is recommended." %}

<p>The basic steps are:</p>  

<ul style="list-style-type:disc">
<li>At the [CPCT main screen](https://cpct.app.cloud.gov/{:target="_blank"}, pick the <b>Profile Document</b>, <b>Document Version</b>, and <b>Certificate Profile</b> related to a certificate you want to test. Then, upload the certificate.</li> 

<li>CPCT displays the certificate's test results. A status banner displays as <i>green</i> (if the certificate conforms) or <i>red</i> (if the certificate doesn't conform). Each field and extension will show either a <i>PASS</i> (a checkmark) or <i>FAIL (with explanation)</i>.</li> 

<li>You can download a formatted Test Report (.xls or .pdf) to submit as part of an Federal PKI Annual Review packages or to retain for your organization's needs.</li> 
</ul> 

<h2>Detailed Steps</h2>
<!--The short names aren't ideal. Neither "Common Policy" nor "Federal Bridge" appear in the actual policies' titles. For normal publications, ideally prior to short name use (or at least in a footnote as I have added at the end), the full titles should be defined.-->
<h4>#### Select Profile Documents</h4>

* Navigate to [CPCT](https://cpct.app.cloud.gov/){:target="_blank"}.
* From the 3 drop-downs, pick:
     o    **Profile Document** (The options are short names for the Profile Documents: _Common Policy SSP Program_<sup>[1](#1)</sup>; _Federal PKI/Federal Bridge_<sup>[2](#2)</sup>; _PIV Interoperable (PIV-I)_<sup>[3](#3)</sup>.)<br>
     o    **Document Version** (The most recent Version will set automatically when you select the Profile Document.)<br>
     o    **Certificate Profile** (e.g., PIV Authentication)<br>

#### Upload a Certificate
* Next, upload your certificate (as a .ctr, .pem, .cer, or .der file) using either of these options:

     o **Drag-and-drop** your certificate to anywhere on the CPCT main screen. _Test results display for the uploaded certificate._<br>
     o Click the **Upload Certificate** button and browse to the certificate. Click it, and then click **Open.** _Test results display for the uploaded certificate._<br>
     
{% include alert-info.html content="Notice that the Test Results screen includes the CPCT drop-downs for easy upload of more certificates." %}

#### Review Certificate Test Results

* At the top of the Test Results screen, a status banner in _green_ (conforms) or _red_ (doesn't conform) banner gives the test summary: 

* **Tested [n] fields: No Problems detected** 
_OR_ 
* **Tested [n] fields: [n] problems detected**

The Test Results columns are:

* **Field** - Lists fields AND extensions.
* **Content** - Lists field and extension details.
* **Analysis** - For each field and extension, this column shows a checkmark (for _PASS_) or _FAIL (with an explanation)_.

#### Download a Test Report
* To download a formatted Test Report, click the **XLS** or **PDF** button below the status banner. 

<h2>Troubleshooting</h2>

### Certificate Errors

* **Tested [n] fields: [n] problems detected**. _1. One or more fields or extensions do not conform; 2. The wrong Profile Document, Document Version, and/or Certificate Profile were selected._; or 3. Another problem exists.
* **FAIL (with explanation)** shown in the **Analysis** column. _The field or extension doesn't conform._

### Possible Error Messages

* **You can't upload files of this type.** _CPCT doesn't recognize the certificate file type. The allowable file types are: .crt, .cer, .pem, and .der._

### Other Problems or Discrepancies

<p>If you encounter a problem or discrepancy:</p>

* Check to make sure that you selected the right Profile Document, Document Version, and Certificate Profile.
* CPCT doesn't recognize the certificate file type. _Allowable file types are: .ctr, .pem, cer., and .der._
* Check the certificate's Validity Period. The test certificate may have expired.<!--Would this show up as a "problem" in the status banner with a "FAIL" for Validity Period"?--> 
* Think there might be an application error?  Please [contact us](https://github.com/GSA/fpkilint/blob/dev/docs/cpct_contact_us.md){:target="_blank"}.
* Think a test result may be incorrect (e.g., "false positive" or "false negative")? Please [contact us](https://github.com/GSA/fpkilint/blob/dev/docs/cpct_contact_us.md){:target="_blank"}. 

### What If I Can't Resolve an Issue?
 
* Create a GitHub issue in the [CPCT Repository](https://github.com/GSA/fpkilint){:target="_blank"} and attach the certificate to the issue. (**Note:**&nbsp;&nbsp;You need a GitHub account to do this. To create one: [Add Create a GitHub account link](#www.github.com?).)<br>
_OR_<br>
* Email us at fpki@gsa.gov and attach your certificate. (**Note:**&nbsp;&nbsp;Please rename your certificate with **.txt** file extension.) 

<p>We will respond as soon as possible.</p>

<h2>Feature Request</h2>

<p>If you would like to request a new CPCT feature, please [contact us](https://github.com/GSA/fpkilint/blob/dev/docs/cpct_contact_us.md){:target="_blank"}.</p>
 
-------
<a name="1">1</a>. Short name for _X.509 Certificate and Certificate Revocation List (CRL) Extensions Profile for the Shared Service Providers (SSP) Program Policy_.<br>
<a name="2">2</a>. Short name for _Federal Public Key Infrastructure (PKI) X.509 Certificate and CRL Extensions Profile_.<br>
<a name="3">3</a>. Short name for _X.509 Certificate and Certificate Revocation List (CRL) Extensions Profile for Personal Identity Verification Interoperable (PIV-I) Cards_.<br>
