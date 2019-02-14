### Below is a design example, not actual tool output

| **Field** | **Content** | **Analysis** |
| :-------- | :------------------------------- | :------------------------------------------------------ |
| Version | v3 | PASS |
| Serial Number | 5B 25 58 A5 <BR> (4 octets) | PASS |
| Signature Algorithm | sha256-rsa (1.2.840.113549.1.1.11) | PASS |
| Issuer DN | OU (2.5.4.11) = (Printable) Entrust Managed Services SSP CA, <BR> OU (2.5.4.11) = (Printable) Certification Authorities, <BR> O (2.5.4.10) = (Printable) Entrust, <BR> C (2.5.4.6) = (Printable) US | PASS |
  | Validity Period | Not Before: 2018-11-06 15:42:17+00:00 <BR> [utc_time] 181106154217Z <BR><BR> Not After: 2021-11-04 16:09:59+00:00 <BR> [utc_time] 211104160959Z <BR><BR> Validity period of 1094 days, 0:27:42 <BR> Expires in 994 days, 0:43:14 | PASS |
| Subject DN | User ID (0.9.2342.19200300.100.1.1) = (Printable) 47001003572981, <BR> CN (2.5.4.3) = (Printable) JOHN RYAN (Affiliate), <BR> OU (2.5.4.11) = (Printable) General Services Administration, <BR> O (2.5.4.10) = (Printable) U.S. Government, <BR> C (2.5.4.6) = (Printable) US | PASS |
| Subject Public Key | RSA-2048 (1.2.840.113549.1.1.1) <BR><BR> 30 82 01 0A 02 82 01 01 00 A2 01 56 E3 51 52 74 DB A7 C8 F7 DA 6D B7 FD 0D 0A 7B DE B4 C0 8A D3 71 40 0B 7A 5F 06 F3 3B DE CF C7 80 9E 1D 8C 8C 2B C2 C5 95 39 1D A3 3A F5 B7 0F 75 89 0B E1 2C 39 A2 46 16 AE 69 FD 14 B0 D6 FA AA 2B BF 55 66 B8 CF 1D EE 5A E8 D0 97 FE B8 F9 AE 43 7C 0D 7F C2 54 5B B1 3E 22 71 C0 A8 86 94 5F 92 E3 2E DA EC 1B 72 DC 6C 17 79 50 43 02 3E 25 B3 29 69 E7 C6 BA 56 94 FA 17 85 8D E4 EC 8F F7 FC CD 02 08 8A 55 17 DD D4 C5 C4 36 90 CE 3D CC 1C FC 9B B5 AA F6 91 7D 23 C1 AE 22 5F 61 1C A7 48 52 83 CA 5D C2 B8 7C 1F F7 E7 CF 73 29 D1 12 CD 09 5A DE E1 E7 03 61 88 02 4F E4 85 2C 59 F5 8D CD 4B 3B 9E 93 19 CA F3 DA A0 05 00 F5 AC 02 89 D0 CA 91 CD A9 85 68 5E 33 CC EE F7 3A 53 5F B4 3B D2 63 EF FD 59 9B CC 2D D9 1C 21 C6 E3 9D 63 DF BA BA F5 58 0B 7E 19 C3 5D AB D3 02 03 01 00 01 | PASS |
| Key Usage | Critical = TRUE <BR> digitalSignature (0) | PASS |
| Extended Key Usage | Client Authentication (1.3.6.1.5.5.7.3.2) <BR> Microsoft Smart Card Logon (1.3.6.1.4.1.311.20.2.2) <BR> Any Extended Key Usage (2.5.29.37.0) | PASS |
| Subject Key Identifier | Key ID: 6FC5CBBE574013F7C60596AC59C54F79BC0F3E55 | PASS |
| Authority Key Identifier | Key ID: 55B46C333FE3601AA7FFC3EDB4F7E404DA29D063 | PASS |
| Subject Alternate Name | Other Name: UPN: 9195225091@GSA.GOV <BR> Other Name: FASCN: <BR> D1 38 10 D8 21 09 2D CC D4 53 45 A1 68 5A 01 0E 6B C4 4C 59 81 38 10 D7 FA <BR> URI: (UUID) urn:uuid:7b878890-1001-014a-a8a3-53b5e15d43d1 | PASS |
| CRL Distribution Points | [1] Distribution Point <BR> Full Name <BR> URI: http://sspweb.managed.entrust.com/CRLs/EMSSSPCA2.crl <BR> URI: ldap://sspdir.managed.entrust.com/cn=WinCombined2,ou=Entrust Managed Services SSP CA,ou=Certification Authorities,o=Entrust,c=US?certificateRevocationList;binary <BR> [2] Distribution Point <BR> Full Name <BR> Directory Name: <BR> CN = CRL13296, <BR> OU = Entrust Managed Services SSP CA, <BR> OU = Certification Authorities, <BR> O = Entrust, <BR> C = US | PASS |
| Authority Information Access | [1] Certification Authority Issuers: <BR> URI: http://sspweb.managed.entrust.com/AIA/CertsIssuedToEMSSSPCA.p7c <BR> [2] Certification Authority Issuers: <BR> URI: ldap://sspdir.managed.entrust.com/ou=Entrust Managed Services SSP CA,ou=Certification Authorities,o=Entrust,c=US?cACertificate;binary,crossCertificatePair;binary <BR> [3] On-line Certificate Status Protocol: <BR> URI: http://ocsp.managed.entrust.com/OCSP/EMSSSPCAResponder | PASS |
| Certificate Policies | [1] 2.16.840.1.101.3.2.1.3.13 <BR> (id-fpki-common-authentication) | PASS |
| PIV NACI | BOOLEAN { FALSE } | PASS |
