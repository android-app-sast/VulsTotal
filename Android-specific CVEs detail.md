# Android-specific CVEs detail
To construct a comprehensive benchmark aligned with the supported vulnerabilities across 11 tools, covering diverse vulnerability types for a thorough evaluation of Android SAST tools, 
we further refined 2,033 entries. Based on the taxonomy and the unique vulnerability types supported by each tool, we labeled the corresponding vulnerability types for these CVEs based on their descriptions and supplementary information. 
To avoid potential bias in the labeling process, detailed information on each CVE was rigorously reviewed and independently labeled by three co-authors. In case of disagreement, the final decision was made by majority voting.
In total, we assigned 2,050 labels to 2,033 CVEs (since a CVE may have multiple vulnerability types) with 1,722 vulnerability labels within the study's scope, while 328 were deemed beyond scope. 
Based on the identified 2,050 labels, we incorporated them and 46 CVEs without specified application versions (involving 47 labels) into our discussion scope. We categorized these labels (i.e., vulnerability types) into two groups: _**Supported types**_, included in the set of vulnerability types supported by the 11 tools, and **_Unsupported types_**.
The vulnerability types and the corresponding quantitative details contained in these two categories are shown in the following table.
#### Supported Vulnerability Type
| **_Vulnerability Type Name_** | **_CVE Num_** |
| --- | --- |
| Use Invalid Server/Hostname Verification | 1449 |
| Hardcoded Sensitive Data Exposure | 59 |
| Using HTTP Issue | 34 |
| Exported Not Protected Components | 28 |
| Webview JavaScript Execution | 23 |
| Logging Data Exposure | 23 |
| External/Internal Data Exposure | 20 |
| Misuse Implicit Intent Issue | 18 |
| Custom URL Scheme Issue | 15 |
| SQL Injection | 9 |
| Misuse Empty Pending Intent Issue | 9 |
| Webview Local File Access | 6 |
| Runtime Command Execution Issue | 5 |
| Manifest Backup Issue | 4 |
| SQLite Data Exposure | 4 |
| ContentProvider Permissions Issue | 3 |
| WebView Insecure  URL Loading | 3 |
| Improper Handle AES Encryption | 3 |
| Webview Java Objects Exposure | 2 |
| Improper Handle DES Encryption | 2 |
| Improper Handle Insecure Hash | 2 |
| Use Insecure Random | 2 |
| Task Affinity Issue | 2 |
| Clipboard Data Exposure | 2 |
| Mode World Storage Writable Issue | 2 |
| Rooted Device Detection | 2 |
| Manifest Debug Issue | 1 |
| Hardcoded IV Issue | 1 |
| Improper Handle  RC4 Encryption | 1 |
| Inadequate File Deletion Handling | 1 |
| Temp File Data Exposure | 1 |
| Weak CBC Cipher Modes | 1 |
| Manifest Screenshot Harvest | 1 |
| Recent Activity Issue | 1 |
| Dynamic Code Loading Issue | 1 |
| Cache Data Disclosure | 1 |

#### Unsupported Vulnerability Type
| **_Vulnerability Type Name_** | **_CVE Num_** |
| --- | --- |
| Inadequate Authentication and Authorization | 39 |
| Path Traversal | 27 |
| Improper Access Control | 27 |
| Denial of Service | 21 |
| Not Protected Data | 18 |
| Cross-Site Scripting (XSS) | 16 |
| Improper SharePreference Access Control | 13 |
| Information Disclosure | 13 |
| Incorrect Implementation of WebView Class | 12 |
| Design Flaw | 12 |
| Improper Database Access Control | 12 |
| Address Bar Spoofing | 11 |
| Improper URL Restrictions | 7 |
| Logic Flaw | 7 |
| Password Bypass | 7 |
| Incorrect Input Validation | 6 |
| Bypassing Lock Protections | 6 |
| bypass a URL whitelist protection mechanism | 5 |
| XML External Entity Injection | 5 |
| Same-Origin Policy Issue | 4 |
| Incomplete Clearance of Sensitive Data | 4 |
| Inadequate Permission Settings | 4 |
| Weak Obfuscation | 4 |
| IDN (Internationalized Domain Name) Spoofing | 3 |
| Improper Implementation of Intent URL | 3 |
| Improper Intent Validation | 3 |
| One-Time Password (OTP) Vulnerability | 3 |
| SharePreference File Leakage | 3 |
| Improper Handling of Unicode Characters | 3 |
| TLS Misuse Issue | 2 |
| Security Screen Flaw | 2 |
| Insufficient Encryption Risks | 2 |
| Lack of Certificate Pinning | 2 |
| Network Communication Integrity and Authenticity Checks | 1 |

