### Below is a design example, not actual tool output

| **Field** | **Content** | **Analysis** |
| :-------- | :------------------------------- | :------------------------------------------------------ |
| Version | V3 (2) | PASS |
| Serial Number | 05 9B 1B 57 9E 8E | PASS |
| Issuer Signature Algorithm | sha256WithRSAEncryption (1 2 840 113549 1 1 11) | PASS |
| Issuer Distinguished Name | CN = Example CA<br/>OU = Example Unit<br/>DC = Example<br/>DC = US | DC name component is not permitted |
| Not Before | 130801120000Z [utc_time]<br/> (2013-08-01 12:00:00+00:00) | PASS |
| Not After | 140901120000Z [utc_time]<br/> (2014-09-01 12:00:00+00:00) | Exceeds maximum allowed validity period |
| Subject Distinguished Name | CN = Example Sub CA<br/>OU = Example Unit<br/>DC = Example<br/>DC = US | DC name component is not permitted |
| Subject Public Key | Public Key:  RSA-1024<br/>30 82 02 0A 02 82 02 01 00 BF E6 90 73 68<br/>DE BB E4 5D 4A 3C 30 22 30 69 33 EC C2 A7<br/>25 2E C9 21 3D F2 8A D8 59 C2 E1 29 A7 3D<br/>58 AB 76 9A CD AE 7B 1B 84 0D C4 30 1F F3<br/>1B A4 38 16 EB 56 C6 97 6D 1D AB B2 79 F2<br/>CA 11 D2 E4 5F D6 05 3C 52 0F 52 1F C6 9E<br/>15 A5 7E BE 9F A9 57 16 59 55 72 AF 68 93<br/>70 C2 B2 BA 75 99 6A 73 32 94 D1 10 44 10<br/>2E DF 82 F3 07 84 E6  | RSA-1024 is not permitted |
| Issuer Signature | sha256WithRSAEncryption (1 2 840 113549 1 1 11) | PASS |

| **Extension** | **Value** | **Analysis** |
| :-------- | :------------------------------- | :------------------------------------------------------ |
| Subject Key Identifier | 61 97 03 a7 7b 33 63 c1 f9 40 51 94 3e 3b 4f 10 3d 18 3c 45 | Not created using RFC5280 method 1 |
| Key Usage | Critical; keyCertSign |  cRLSign |  DigitalSignature |  nonRepudiation | DigitalSignature not premitted. nonRepudiation not permitted. |
| Basic Constraints | Critical; cA=True; path length constraint absent | PASS |
