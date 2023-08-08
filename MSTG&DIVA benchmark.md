# MSTG&DIVA Benchmark

​Many industry companies and institutions developed insecure apps by manually injecting vulnerabilities. From this side, we take the MSTG app and DIVA app into account, where MSTG is maintained by OWASP and the latter is developed by an industry company named Payatu. The MSTG serves as a comprehensive resource for mobile app security testing, providing valuable insights into identifying and addressing potential vulnerabilities. Meanwhile, the DIVA app showcases real-world security issues and serves as an educational tool to enhance app developers' understanding of secure coding practices.

​According to the type of vulnerability supported by these two apps and the type of vulnerability supported by 8 selected tools, we show detailed information on the type of vulnerability corresponding to the tool detection capability in MSTG&DIVA.

| APK name | The selected groudtruth label         | Overlapped or Unique? |
| -------- | ------------------------------------- | --------------------- |
| DIVA     | Logging Data Disclosure               | Overlapped            |
|          | Hardcoded String                      | Unique:  MobSF        |
|          | SharedPreference Disclosure           | Unique:  AUSERA       |
|          | SQL Data Disclosure                   | Unique:  AUSERA       |
|          | Handle Temp File Issue                | Overlapped            |
|          | External/Internal Data Disclosure     | Overlapped            |
|          | Sql Injection                         | Overlapped            |
| MSTG     | SharedPreference Disclosure           | Overlapped            |
|          | Improper Handle Base64 Encryption     | Overlapped            |
|          | Logging Data Disclosure               | Overlapped            |
|          | Use Sqlcipher Issue                   | Overlapped            |
|          | SQLite Not Encrypted                  | Unique:  AndroBugs    |
|          | Sql Injection                         | Overlapped            |
|          | External/Internal Data Disclosure     | Overlapped            |
|          | Sensitive Functionality (loadlibrary) | Overlapped            |
|          | Webview Addjsinterface Execution      | Overlapped            |
|          | Webview Local File Access             | Overlapped            |
|          | Bypassed SSL Pinning issue            | Overlapped            |
