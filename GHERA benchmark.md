# GHERA benchmark

​By referring to the evaluation and comparison results in [1], we choose GHERA [2] as one synthetic benchmark because it is more comprehensive than others by maintaining more vulnerability types. Moreover, it also provides both the vulnerable version and the corresponding fixed version.

​According to the type of vulnerability supported by GHERA and the type of vulnerability supported by 8 selected tools, we show detailed information on the type of vulnerability corresponding to the tool detection capability in GHERA. 

|                                                         | The selected groudtruth label                | Overlapped or Unique? |
| ------------------------------------------------------- | -------------------------------------------- | --------------------- |
| BlockCipher-ECB-InformationExposure-Lean                | Improper Handle AES Encryption               | Overlapped            |
| BlockCipher-NonRandomIV-InformationExposure-Lean        | Hardcoded IV  issue                          | Overlapped            |
| CheckValidity-InformationExposure-Lean                  | Use Invalid Server Verification              | Overlapped            |
| ClipboardUse-InformationExposure-Lean                   | Android Clipboard Issue                      | Unique:  MobSF        |
| ConstantKey-ForgeryAttack-Lean                          | Hardcoded String                             | Unique:  MobSF        |
| DynamicRegBroadcastReceiver-UnrestrictedAccess-Lean     | Misuse Dynamically Registered Receiver Issue | Overlapped            |
| EmptyPendingIntent-PrivEscalation-Lean                  | Misuse Empty Pending Intent Issue            | Overlapped            |
| ExternalStorage-DataInjection-Lean                      | External/Internal Data Disclosure            | Overlapped            |
| ExternalStorage-InformationLeak-Lean                    | External/Internal Data Disclosure            | Overlapped            |
| FragmentInjection-PrivEscalation-Lean                   | Fragment Injection                           | Overlapped            |
| HighPriority-ActivityHijack-Lean                        | High Priority Found                          | Unique:  MobSF        |
| HttpConnection-MITM-Lean                                | Using HTTP Issue                             | Overlapped            |
| ImplicitPendingIntent-IntentHijack-Lean                 | Implicit Intent issue                        | Overlapped            |
| InadequatePathPermission-InformationExposure-Lean       | Improper Content Provider Permissions        | Overlapped            |
| IncorrectHandlingImplicitIntent-UnauthorizedAccess-Lean | Misuse Implicit Intent Issue                 | Overlapped            |
| IncorrectHostNameVerification-MITM-Lean                 | Use Invalid Hostname Verification            | Overlapped            |
| InsecureSSLSocketFactory-MITM-Lean                      | Sticky Broadcast Intent Issue                | Overlapped            |
| InvalidCertificateAuthority-MITM-Lean                   | Use Invalid Server Verification              | Overlapped            |
| JavaScriptExecution-CodeInjection-Lean                  | Webview SetJavaScriptenabled Execution       | Overlapped            |
| PBE-ConstantSalt-InformationExposure-Lean               | Hardcoded String                             | Unique:  MobSF        |
| SQLite-execSQL-Lean                                     | Sql Injection                                | Overlapped            |
| SQLlite-RawQuery-SQLInjection-Lean                      | Sql Injection                                | Overlapped            |
| SQLlite-SQLInjection-Lean                               | Sql Injection                                | Overlapped            |
| StickyBroadcast-DataInjection-Lean                      | Sticky Broadcast Intent Issue                | Overlapped            |
| TaskAffinity-ActivityHijack-Lean                        | Task Affinity Set                            | Unique:  MobSF        |
| TaskAffinity-PhishingAttack-Lean                        | Task Affinity Set                            | Unique:  MobSF        |
| UnhandledException-DOS-Lean                             | NPE_CRASH                                    | Unique:  JAADAS       |
| UniqueIDs-IdentityLeak-Lean                             | Device ID Disclosure                         | Overlapped            |
| UnnecesaryPerms-PrivEscalation-Lean                     | Provide the right permissions                | Unique:  SPECK        |
| UnpinnedCertificates-MITM-Lean                          | Bypassed SSL Pinning issue                   | Overlapped            |
| UnprotectedBroadcastRecv-PrivEscalation-Lean            | Exported Not Protected Components            | Overlapped            |
| WeakChecksOnDynamicInvocation-DataInjection-Lean        | Exported Not Protected Content Provider      | Overlapped            |
| WeakPermission-UnauthorizedAccess-Lean                  | Exported Not Protected Components            | Overlapped            |
| WebViewAllowContentAccess-UnauthorizedFileAccess-Lean   | Webview Local File Access                    | Overlapped            |
| WebViewAllowFileAccess-UnauthorizedFileAccess-Lean      | Webview Local File Access                    | Overlapped            |
| WebViewIgnoreSSLWarning-MITM-Lean                       | Webview Invalid Certificate Authentication   | Overlapped            |







## REFERENCES

[1] Joydeep Mitra, Venkatesh-Prasad Ranganath, and Aditya Narkar. 2019. Bench-Press: Analyzing Android app vulnerability benchmark suites. In 2019 34th IEEE/ACM International Conference on Automated Software Engineering Workshop (ASEW). IEEE, 13–18.

[2] Joydeep Mitra and Venkatesh-Prasad Ranganath. 2017. Ghera: A repository of Android app vulnerability benchmarks. In Proceedings of the 13th International Conference on Predictive Models and Data Analytics in Software Engineering. 43–52.
