# Android-specific CVEs detail

To construct a comprehensive benchmark aligned with the supported vulnerabilities across 11 tools, covering diverse vulnerability types for a thorough evaluation of Android SAST tools, we further refined the 1,997 entries. Based on the taxonomy and the unique vulnerability types supported by each tool, we label the corresponding vulnerability types for these CVEs based on their descriptions and supplementary information. 

In total, we assigned 2,022 labels to 1,997 CVEs (since a CVE may have multiple vulnerability types) with 1,712 vulnerability labels within the study's scope (which represented by 'Supported'), while 310 were deemed beyond scope (which represented by 'Unsupported'). 

The vulnerability types and the corresponding quantitative details contained in these two categories are shown in the following table.

#### Supported Vulnerability Type

| Vulnerability Type Name                  | CVE Num |
| ---------------------------------------- | ------- |
| Use Invalid Server/Hostname Verification | 1446    |
| Hardcoded Sensitive Data Exposure        | 59      |
| Using HTTP Issue                         | 29      |
| Exported Not Protected Components        | 27      |
| Logging Data Exposure                    | 22      |
| External/Internal Data Exposure          | 19      |
| Webview JavaScript Execution             | 18      |
| Misuse Implicit Intent Issue             | 17      |
| Custom URL Scheme                        | 15      |
| SQL injection                            | 9       |
| Empty Pending Intent                     | 8       |
| Webview Local File Access                | 7       |
| Runtime Command Execution Issue          | 5       |
| Manifest Backup Issue                    | 4       |
| WebView Insecure URL Loading             | 3       |
| Clipboard Data Exposure                  | 2       |
| Mode World Storage Writable Issue        | 2       |
| Rooted Device Detection                  | 2       |
| ContentProvider Permissions Issue        | 2       |
| Task Hijacking                           | 2       |
| Improper Handle AES Encryption           | 2       |
| Improper Handle DES Encryption           | 2       |
| Manifest Debug Issue                     | 1       |
| Cache Data Disclosure                    | 1       |
| Manifest Screenshot Harvest              | 1       |
| Recent Activity Vulnerability            | 1       |
| Inadequate File Deletion Handling        | 1       |
| Webview Java Objects Exposure            | 1       |
| Improper Handle RC4 Encryption           | 1       |
| Weak CBC Cipher Modes                    | 1       |
| Hardcoded IV Issue                       | 1       |
| Improper Handle Insecure Hash            | 1       |

#### Unsupported Vulnerability Type

| Vulnerability Type Name                                 | CVE Num |
| ------------------------------------------------------- | ------- |
| Inadequate Authentication and Authorization             | 36      |
| Path Traversal                                          | 32      |
| Other                                                   | 29      |
| Improper Access Control                                 | 20      |
| Denial of Service                                       | 19      |
| Not Protected Data                                      | 19      |
| Improper Database Access Control                        | 15      |
| Improper SharePreference Access Control                 | 13      |
| Information Disclosure                                  | 12      |
| Incorrect Implementation of WebView Class               | 12      |
| Design Flaw                                             | 11      |
| Cross-Site Scripting (XSS)                              | 11      |
| Address Bar Spoofing                                    | 9       |
| Password Bypass                                         | 7       |
| Logic Flaw                                              | 7       |
| Improper URL Restrictions                               | 7       |
| Bypassing Lock Protections                              | 6       |
| Incorrect Input Validation                              | 6       |
| Insufficient Encryption Risks                           | 4       |
| Incomplete Clearance of Sensitive Data                  | 4       |
| Weak Obfuscation                                        | 4       |
| Improper Handling of Unicode Characters                 | 3       |
| SharePreference File Leakage                            | 3       |
| One-Time Password (OTP) Vulnerability                   | 3       |
| Improper Intent Validation                              | 3       |
| Improper Implementation of Intent URL                   | 3       |
| IDN (Internationalized Domain Name) Spoofing            | 3       |
| Inadequate Permission Settings                          | 2       |
| Security Screen Flaw                                    | 2       |
| Lack of Certificate Pinning                             | 2       |
| Insecure Random Function                                | 2       |
| Network Communication Integrity and Authenticity Checks | 1       |

