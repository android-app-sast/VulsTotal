# MSTG&PIVAA Benchmark
Many industry companies and institutions developed insecure apps by manually injecting vulnerabilities. From this side, we take the MSTG app and PIVAA app into account, where MSTG is maintained by OWASP and the latter one is developed by an industry company named High-Tech Bridge. 
The MSTG serves as a comprehensive resource for mobile app security testing, providing valuable insights into identifying and addressing potential vulnerabilities. Meanwhile, the PIVAA app showcases real-world security issues and serves as an educational tool to enhance app developers' understanding of secure coding practices.
According to the type of vulnerability supported by these two apps and the type of vulnerability supported by 11 selected tools, we show detailed information on the type of vulnerability corresponding to the tool detection capability in MSTG&PIVAA.

| APK name | The selected groudtruth label | Overlapped or Unique? |
| --- | --- | --- |
| PIVAA | Using temp file issue | Overlapped |
|  | Hardcoded Sensitive Data Exposure | Overlapped |
|  | AES encryption misuse | Overlapped |
|  | Improper Handle Insecure Hash Function | Overlapped |
|  | Weak CBC Cipher Modes | Overlapped |
|  | Hardcoded IV Issue | Overlapped |
|  | Exported not protected components | Overlapped |
|  | Exported not protected Content Provider | Overlapped |
|  | Backup issue | Overlapped |
|  | Debug issue | Overlapped |
|  | MODE WRITABLE | Overlapped |
|  | Sensitive functionality (DexClassLoader) | Overlapped |
|  | SQL injection | Overlapped |
|  | Use http issue | Overlapped |
|  | Use invalid hostname verification | Overlapped |
|  | Webview JavaScript Execution | Overlapped |
|  | Webview Insecure Load Plugin | Overlapped |
|  | WebView Insecure URL Loading | Overlapped |
| MSTG | Logging data leakage | Overlapped |
|  | SD card/Internal data leakage | Overlapped |
|  | Base64 encryption issue | Overlapped |
|  | Improper Handle Package Hardcoded | Overlapped |
|  | Sensitive functionality (DexClassLoader) | Overlapped |
|  | SQL injection | Overlapped |
|  | Webview Java Objectes Exposure | Overlapped |
|  | WebView local file access | Overlapped |
|  | Use http issue | Overlapped |
|  | The Keyboard Cache instances | Unique:  APKHunt |

