---
layout: default
title: Certificate Profile Conformance Tool (CPCT) Help
collection: docs
permalink: docs/userguide/
---
<html>
<body>
<h2 id="what">What is the Certificate Profile Conformance Tool (CPCT)?</h2>

<p>Do you often need to analyze Federal PKI certificates for conformance to certificate profiles? If your answer is <i>yes</i>, then the Certificate Profile Conformance Tool (CPCT) is for you.</p>

<p>CPCT is a friendly tool that instantly analyzes a certificate and displays conformance test results. Not only that&nbsp;-&nbsp;CPCT clearly explains the reason for any nonconformance. What's more, you can download a formatted Test Report (.xls or .pdf) to submit as part of a Federal PKI Annual Review package or retain for your organization's needs.</p>

<ul style="list-style-type:disc">
<li><a href="#who">Who Needs CPCT?</a>
<li><a href="#operating">Operating System Requirements</a>
<li><a href="#how">How Does This Work?</a>
<li><a href="#detailed">Detailed Steps</a>
<li><a href="#troubleshooting">Troubleshooting</a>
<li><a href="#feature">Feature Request</a>
</ul>

<h2 id="who">Who Needs CPCT?</h2>

<ol>
<li><b>Agencies/organizations submitting FPKI Annual Review Packages</b> - Use it to test certificates and download Test Reports.</li>
<li><b>PIV or SSL/TLS Certificate Issuers</b> - Use it to test certificates as part of a QA process.</li>
<li><b>Subscribers</b> - Use it to determine who should correct certificate failures.</li>
<li><b>Anyone who analyzes FPKI certificates for conformance</b>.</li>
</ol>

<h2 id="operating">Operating System Requirements</h2>

<ul style="list-style-type:disc"> 
<li>Windows or macOS</li>
<li>iOS - Not recommended for CPCT</li>
<li>Android - Not recommended for CPCT</li>
</ul>

<h2 id="how">How Does This Work?</h2>

<p style="color:blue;"><b><i>Note:&nbsp;&nbsp;In-depth experience with Federal PKI certificates and certificate profiles is recommended.</b></i></p>

<p>The basic steps are:</p>

<ul style="list-style-type:disc">
<li>At the <a href="https://cpct.app.cloud.gov/" target="_blank">CPCT main screen</a>, pick the <b>Profile Document</b>, <b>Document Version</b>, and <b>Certificate Profile</b> related to a specific certificate that you need to test. Then, upload the certificate.</li> 

<li>CPCT displays the certificate's test results. A status banner will be <i>green</i> if the certificate conforms to the Certificate Profile or <i>red</i> if it doesn't. The <b>Analysis</b> column will display a <b>checkmark</b> for <i>"PASS"</i> or state <b>"FAIL" (with explanation)</b> for each field and extension.</li> 

<li>You can download a formatted Test Report (.xls or .pdf) to submit as part of a Federal PKI Annual Review package or to retain for your organization's needs.</li> 
</ul>

<h2 id="detailed">Detailed Steps</h2>
<!--The short names aren't ideal. "Common Policy" and "Federal Bridge" don't appear in the actual policies' titles. For normal publications, ideally prior to short name use (or at least in a footnote as I have added at the end), the full titles should be defined.-->

<h4>1. Select Profile Documents</h4>

<ol type="a">
<li>Navigate to <a href="https://cpct.app.cloud.gov/" target="_blank">CPCT</a>.

<li>From the 3 drop-downs, pick:</li></ol>
<ul style="list-style-type:disc">
<li><b>Profile Document -</b> This list contains short names for the FPKI Profile Documents: <i>Common Policy SSP Program</i><sup><a href="#1">1</a></sup>; <i>Federal PKI/Federal Bridge</i><sup><a href="#2">2</a></sup>; and <i>PIV Interoperable (PIV-I)</i><sup><a href="#3">.3</a></sup>
<li><b>Document Version -</b> The most recent Version is automatically set when you select the Profile Document.
<li><b>Certificate Profile -</b> For example, PIV Authentication.</li>
</ul>

<h4>2. Upload a Certificate</h4>

<ol type="a">
<li>Next, upload a certificate (.ctr, .pem, .cer, or .der file) using either of these options:</ol>
<ul style="list-style-type:disc">
<li><b>Drag-and-drop</b> your certificate to anywhere on the CPCT main screen. <i>The Test Results display for the uploaded certificate.</i><br>
<li>Click the <b>Upload Certificate</b> button and browse to the certificate. Click it, and then click <b>Open</b>. <i>The Test Results display for the uploaded certificate.</i><br></li>
</ul>

<h4>3. Review Certificate Test Results</h4>
<p style="color:blue;"><b><i>Note:&nbsp;&nbsp;The Test Results screen includes the CPCT drop-downs so you can easily upload more certificates.</i></b></p>

<p>The status banner will be <i>green</i> (certificate conforms) or <i>red</i> (doesn't conform) and will give a test summary:</p>

<ul style="list-style-type:disc">
<li><b>Tested [n] fields: No Problems detected</b>
<li><b>Tested [n] fields: [n] problems detected</b></li>
</ul>

<p>The Test Results columns provide the following:</p>
<ul>
<li><b>Field -</b> Lists fields AND extensions.
<li><b>Content -</b> Lists field and extension details.
<li><b>Analysis -</b> Displays a <b>checkmark</b> for <i>"PASS"</i> or state <b>"FAIL" (with explanation)</b> for each field and extension.</li>
</ul>

<h4>4. Download a Test Report</h4>

<ul>
<li>To download a formatted Test Report, click the <b>XLS</b> or <b>PDF</b> button below the status banner. </li>
</ul>

<h2 id="troubleshooting">Troubleshooting</h2>

<h3>Certificate Failures</h3>

<ul>
<li> Please check to ensure that the right <b>Profile Document</b>, <b>Document Version</b>, and <b>Certificate Profile</b> have been selected.
<li> If you have questions about a certificate failure explanation, or you believe that it could be a "false positive"/"false negative," please <a href="https://github.com/GSA/fpkilint/blob/dev/docs/cpct_contact_us.md" target="_blank">contact us</a>.
</li>
</ul>

<h3>Application Error Messages</h3>

<ul>
<li><i>You can't upload files of this type.</i> The allowable file types are: .crt, .cer, .pem, and .der.</li>
</ul>

<h3>What If I Can't Resolve an Issue?</h3>

<ul>
<li>Create a GitHub issue in the <a href="https://github.com/GSA/fpkilint" target="_blank">CPCT Repository</a> and attach the certificate to the issue. (<strong>Note:</strong>&nbsp;&nbsp;You will need a GitHub account to do this: <a href="https://github.com/join" target="_blank">create a GitHub account link</a>.)</li></ul>
<i>OR</i><br>
<ul>
<li>Email us at fpki@gsa.gov and attach your certificate. (<b>Note:</b>&nbsp;&nbsp;Please rename your certificate with <b>.txt</b> file extension.) </li>
</ul>

<p>We will respond as soon as possible.</p>

<h2 id="feature">Feature Request</h2>

<p>If you would like us to request a new CPCT feature, please <a href="https://github.com/GSA/fpkilint/blob/dev/docs/cpct_contact_us.md" target="_blank">contact us</a>.</p>

<p><b>____________</b></p>
<p><a name="1">1</a>. Short name for <em>X.509 Certificate and Certificate Revocation List (CRL) Extensions Profile for the Shared Service Providers (SSP) Program Policy</em>.<br>
<a name="2">2</a>. Short name for <em>Federal Public Key Infrastructure (PKI) X.509 Certificate and CRL Extensions Profile</em>.<br>
<a name="3">3</a>. Short name for <em>X.509 Certificate and Certificate Revocation List (CRL) Extensions Profile for Personal Identity Verification Interoperable (PIV-I) Cards</em>.<br></p>

</body>
</html>
