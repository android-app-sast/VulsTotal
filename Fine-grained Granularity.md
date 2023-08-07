# Fine-grained Granularity 

​	According to our analysis, there are a total of 13 types of vulnerabilities with different tool detection granularity, and we divide them into three categories according to their specific conditions.

​	a. For most data disclosure types (7.41%, 4/54) in the vulnerability category of “Sensitive Data Disclosure Risks” like “Logging Data Disclosure” and “SMS Data Disclosure”, SUPER and MobSF rely on simple pattern matching for vulnerable APIs without confirming the sensitivity of the leaked data. In contrast, AUSERA adds custom sensitive data labels to validate sensitivity after matching leak APIs like *Log.e()* and *sendTextMessage()*

​	b. For vulnerabilities only trigger in certain preconditions, we find that different tools have different detection granularity. For example, the vulnerable API *setJavaScriptenabled(‘true’)* in the “WebView SetJavaScriptenabled Execution” vulnerability only triggers below min SDK version 17 while only AUSERA couples API matching with further validation of the min SDK version. In addition, the “Misuse Empty Pending Intent” vulnerability only triggers when matching the vulnerable API under the premise of the exported corresponding component. There are 5 vulnerability types that have added the constraints of preconditions, accounting for 9.26% (5/54).

​	c. For vulnerabilities with multiple vulnerable APIs involving the same vulnerability type, differences manifest in tools omitting certain vulnerable APIs from the analysis. For example, most tools only check for AES encryption misuse via *Cipher.getInstance(“AES/ECB”)*, while ignoring the implementation of *Cipher.getInstance (“AES”)* also uses the parameters *“AES/ECB/PKCS5padding”.* There are 4 types of vulnerability type in this case, accounting for 7.41% (4/54)

​	We show the specific types of vulnerabilities and the details of their categories in the following table.

| Vul Typ                                | QARK | AndroBugs | JAADAS | Marvine | SUPER | MobSF | SPECK | AUSERA | Categories |
| -------------------------------------- | ---- | --------- | ------ | ------- | ----- | ----- | ----- | ------ | ---------- |
| Logging Data Disclosure                |      |           |        |         | ☆     | ☆     |       | ★      | a          |
| External/Internal Data Disclosure      |      | ☆         |        |         | ☆     | ☆     | ☆     | ★      | a          |
| Handle Temp File Issue                 |      |           |        |         | ☆     | ☆     |       | ★      | a          |
| SMS Data Leakage                       |      | ☆         |        |         | ☆     | ☆     | ☆     | ★      | a          |
| Improper Handle AES Encryption         |      |           |        | ☆       | ☆     | ☆     | ☆     | ★      | c          |
| Improper Handle RSA Encryption         |      |           | ☆      |         | ☆     | ☆     | ☆     | ★      | c          |
| Improper Handle Package Hardcoded      | ☆    |           |        |         | ☆     | ☆     |       | ★      | b          |
| Use Sqlcipher Issue                    |      | ☆         |        |         |       | ★     |       |        | b          |
| Hardcoded IV issue                     |      |           |        | ★       |       | ☆     |       |        | c          |
| Misuse Empty Pending Intent Issue      | ☆    |           |        |         |       |       |       | ★      | b          |
| Webview SetJavaScriptenabled Execution | ☆    | ☆         |        |         | ☆     | ☆     | ☆     | ★      | b          |
| Webview Local File Access              | ☆    | ☆         | ☆      | ★       |       |       |       | ★      | b          |
| Rooted Device Detection                |      | ☆         |        |         | ★     | ★     |       |        | c          |