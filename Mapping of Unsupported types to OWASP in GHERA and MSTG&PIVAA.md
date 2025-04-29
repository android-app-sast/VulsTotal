# Mapping of Unsupported types to OWASP in GHERA and MSTG&PIVAA
We mapped the unsupported vulnerability types by any of the selected tools in GHERA and MSTG&PIVAA to the OWASP Mobile Top 10 2024 and found that they all correspond to at least one category in the OWASP Top 10.
It is noteworthy that each threat in the OWASP Top 10 encompasses a range of specific vulnerability types. Therefore, even if certain types in these benchmarks are not covered by any tools, it does not necessarily mean that the corresponding Top 10 threats are neglected, as other related vulnerabilities are still supported by the tools.
The mapping table is as follows.

| **The Unsupported types in GHERA** | **Corresponding OWASP Categories** |
| --- | --- |
| CheckPermission-PrivilegeEscalation-Lean-benign | M8: Security Misconfiguration |
| DynamicCodeLoading-CodeInjection-Lean-benign | M4: Insufficient Input/Output Validation |
| EnforceCallingOrSelfPermission-PrivilegeEscalation-Lean-benign | M8: Security Misconfiguration |
| EnforcePermission-PrivilegeEscalation-Lean-benign | M8: Security Misconfiguration |
| ExposedCredentials-InformationExposure-Lean-benign | M1: Improper Credential Usage |
| InsecureSSLSocket-MITM-Lean-benign | M5: Insecure Communication |
| InternalStorage-DirectoryTraversal-Lean-benign | M4: Insufficient Input/Output Validation |
| InternalToExternalStorage-InformationLeak-Lean-benign | M9: Insecure Data Storage |
| MergeManifest-UnintendedBehavior-Lean-benign | M8: Security Misconfiguration |
| NoValidityCheckOnBroadcastMsg-UnintendedInvocation-Lean-benign | M8: Security Misconfiguration |
| OrderedBroadcast-DataInjection-Lean-benign | M4: Insufficient Input/Output Validation |
| OutdatedLibrary-DirectoryTraversal-Lean-benign | M2: Inadequate Supply Chain Security |
| TaskAffinityAndReparenting-PhishingAndDoSAttack-Lean-benign | M3: Insecure Authentication/Authorization |
| TaskAffinity-LauncherActivity-PhishingAttack-Lean-benign | M3: Insecure Authentication/Authorization |
| UnEncryptedSocketComm-MITM-Lean-benign | M5: Insecure Communication |
| UnhandledException-DOS-Lean-benign | M8: Security Misconfiguration |
| UnpinnedCertificates-MITM-Lean-benign | M5: Insecure Communication |
| UnprotectedBroadcastRecv-PrivEscalation-Lean-benign | M8: Security Misconfiguration |
| UnsafeIntentURLImpl-InformationExposure-Lean-benign | M4: Insufficient Input/Output Validation |
| WeakChecksOnDynamicInvocation-DataInjection-Lean-benign | M4: Insufficient Input/Output Validation |
| WebView-CookieOverwrite-Lean-benign | M4: Insufficient Input/Output Validation |
| WebView-NoUserPermission-InformationExposure-Lean-benign | M6: Inadequate Privacy Controls |
| WebViewProceed-UnauthorizedAccess-Lean-benign | M3: Insecure Authentication/Authorization |


| **The Unsupported types in MSTG&PIVAA** | **Corresponding OWASP Categories** |
| --- | --- |
| Self-signed CA enabled in WebView | M5:Insecure Communication |
| Usage of banned API functions | M8: Security Misconfiguration |
| Predictable Random Number Generator | M10: Insufficient Cryptography |
| Path Traversal | M4: Insufficient Input/Output ValidationM4 |
| Untrusted CA acceptance | M5 - Insecure Communication |
| Cleartext SQLite database | M9: Insecure Data Storage |
| Object deserialization found | M3: Insecure Authentication/Authorization |
| Missing tapjacking protection | M8: Security Misconfiguration |
| OMTG_CODING_003_Best_Practice | M10: Insufficient Cryptography |
| OMTG_DATAST_001_KeyChain | M9: Insecure Data Storage |
| OMTG_DATAST_001_SQLite_Not_Encrypted | M9: Insecure Data Storage |
| OMTG_DATAST_006_Clipboard | M9: Insecure Data Storage |
| OMTG_DATAST_011_Memory | M9: Insecure Data Storage |
| OMTG_NETW_004_SSL_Pinning | M5 - Insecure Communication |
| OMTG_NETW_004_SSL_Pinning_Certificate | M5 - Insecure Communication |
| OMTG_DATAST_001_SharedPreferences | M9: Insecure Data Storage |


