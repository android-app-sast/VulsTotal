# GHERA benchmark
By referring to the evaluation and comparison results in [1], we choose GHERA [2] as one synthetic benchmark since it is a representative benchmark maintaining more vulnerability types. Moreover, it also provides both benign and secure versions for each vulnerability type.
According to the type of vulnerability supported by GHERA and the type of vulnerability supported by 11 selected tools, we show detailed information on the type of vulnerability corresponding to the tool detection capability in GHERA. 

|  | The selected groud-truth label | Overlapped or Unique? |
| --- | --- | --- |
| **BlockCipher-ECB-InformationExposure-Lean** | Improper Handle AES Encryption | Overlapped |
| **BlockCipher-NonRandomIV-InformationExposure-Lean** | Hardcoded IV  issue | Overlapped |
| **CheckValidity-InformationExposure-Lean** | Use Invalid Server Verification | Overlapped |
| **InvalidCertificateAuthority-MITM-Lean** | Use Invalid Server Verification | Overlapped |
| **ClipboardUse-InformationExposure-Lean** | Clipboard Data Exposure | Overlapped |
| **ConstantKey-ForgeryAttack-Lean** | Hardcoded Sensitive Data Exposure | Overlapped |
| **PBE-ConstantSalt-InformationExposure-Lean** | Hardcoded Sensitive Data Exposure | Overlapped |
| **DynamicRegBroadcastReceiver-UnrestrictedAccess-Lean** | Misuse Dynamically Registered Receiver Issue | Overlapped |
| **EmptyPendingIntent-PrivEscalation-Lean** | Misuse Empty Pending Intent Issue | Overlapped |
| **ExternalStorage-DataInjection-Lean** | External/Internal Data Disclosure | Overlapped |
| **ExternalStorage-InformationLeak-Lean** | External/Internal Data Disclosure | Overlapped |
| **FragmentInjection-PrivEscalation-Lean** | Fragment Injection | Overlapped |
| **HttpConnection-MITM-Lean** | Using HTTP Issue | Overlapped |
| **ImplicitPendingIntent-IntentHijack-Lean** | Implicit Intent issue | Overlapped |
| **InadequatePathPermission-InformationExposure-Lean** | Improper Content Provider Permissions | Overlapped |
| **IncorrectHandlingImplicitIntent-UnauthorizedAccess-Lean** | Misuse Implicit Intent Issue | Overlapped |
| **IncorrectHostNameVerification-MITM-Lean** | Use Invalid Hostname Verification | Overlapped |
| **InsecureSSLSocketFactory-MITM-Lean** | Sticky Broadcast Intent Issue | Overlapped |
| **JavaScriptExecution-CodeInjection-Lean** | Webview SetJavaScriptenabled Execution | Overlapped |
| **OpenSocket-InformationLeak-Lean** | Use Insecure Socket | Overlapped |
| **SQLite-execSQL-Lean** | Sql Injection | Overlapped |
| **SQLlite-RawQuery-SQLInjection-Lean** | Sql Injection | Overlapped |
| **SQLlite-SQLInjection-Lean** | Sql Injection | Overlapped |
| **StickyBroadcast-DataInjection-Lean** | Sticky Broadcast Intent Issue | Overlapped |
| **UniqueIDs-IdentityLeak-Lean** | Device ID Disclosure | Overlapped |
| **UnprotectedBroadcastRecv-PrivEscalation-Lean** | Exported Not Protected Components | Overlapped |
| **WeakPermission-UnauthorizedAccess-Lean** | Exported Not Protected Components | Overlapped |
| **WebViewAllowContentAccess-UnauthorizedFileAccess-Lean** | Webview Local File Access | Overlapped |
| **WebViewAllowFileAccess-UnauthorizedFileAccess-Lean** | Webview Local File Access | Overlapped |
| **WebViewIgnoreSSLWarning-MITM-Lean** | Webview Invalid Certificate Authentication | Overlapped |
| **WebViewInterceptRequest-MITM-Lean** | The instances of URL Loading in WebViews | Unique: APKHunt |
| **WebViewOverrideUrl-MITM-Lean** | The instances of URL Loading in WebViews | Unique: APKHunt |
| **CheckCallingOrSelfPermission-PrivilegeEscalation-Lean** | The Custom Permissions | Unique: APKHunt |
| **HighPriority-ActivityHijack-Lean** | High Priority Found | Unique:  MobSF |
| **TaskAffinity-ActivityHijack-Lean** | Task Affinity Set | Unique:  MobSF |
| **TaskAffinity-PhishingAttack-Lean** | Task Affinity Set | Unique:  MobSF |
| **WebViewLoadDataWithBaseUrl-UnauthorizedFileAccess-Lean** | WebView Insecure URL Loading | Overlapped |

## REFERENCES
[1] Joydeep Mitra, Venkatesh-Prasad Ranganath, and Aditya Narkar. 2019. Bench-Press: Analyzing Android app vulnerability benchmark suites. In 2019 34th IEEE/ACM International Conference on Automated Software Engineering Workshop (ASEW). IEEE, 13–18.
[2] Joydeep Mitra and Venkatesh-Prasad Ranganath. 2017. Ghera: A repository of Android app vulnerability benchmarks. In Proceedings of the 13th International Conference on Predictive Models and Data Analytics in Software Engineering. 43–52.
