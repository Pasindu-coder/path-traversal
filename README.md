# path-traversal
Path traversal is a security vulnerability where an attacker manipulates file paths to access files and directories outside the intended directory. By exploiting improper input validation, they can gain unauthorized access to sensitive files or system data, potentially leading to data breaches or system compromise.
### Path Traversal

**Path Traversal**, also known as directory traversal, is a type of web security vulnerability where attackers manipulate user-controlled input to navigate outside the application's intended directory structure. This occurs when a web application allows users to specify file paths without proper validation or sanitization, giving attackers the opportunity to access files and directories that should be restricted.

By exploiting this vulnerability, attackers can gain unauthorized access to sensitive files, such as system configuration files, user credentials, application code, and other critical resources. In more severe cases, path traversal can lead to full system compromise if the attacker manages to execute arbitrary code or modify system files.

In this lab, the vulnerability is located in the URL, in order to exploit this you have to traverse two times and specify the secret file txt file path.
**Respective payload**
          "../../secret.txt" 
The resolved lab is displayed in the URL as this"**http://pasindu.infinityfreeapp.com/index.html?message=The+vulnerability+is+exploited+successfully%21+Flag%3A+FLAG%7Bpath_traversal_successful_secret_pass_key_12345%7D**"


### Key Points:

1. **Vulnerability Source**:
   - Path traversal arises when user-supplied input, like filenames or URLs, is directly used to access the file system without adequate filtering or checks. This is common in file upload/download functionalities, logging mechanisms, or dynamic file inclusion processes.
  
2. **Manipulation of Paths**:
   - Attackers use relative path sequences like `../` (dot-dot-slash) to "traverse" out of the current directory, moving up to higher-level directories to access unauthorized files.
   - Path traversal vulnerabilities affect both Windows (using `..\`) and Unix/Linux systems (using `../`).

3. **Consequences**:
   - Attackers can read sensitive files, modify configurations, gain access to user data, and, in certain cases, execute arbitrary code.
   - Commonly targeted files include `/etc/passwd` (password file on Unix systems), configuration files like `config.php`, or log files that may contain sensitive information.

4. **Common Entry Points**:
   - File upload/download functionality.
   - Log file access.
   - File inclusion functions (e.g., PHP’s `include()` or `require()`).
   - URL parameters that access files directly (e.g., `www.example.com/download?file=user.txt`).

5. **Severity**:
   - The severity of path traversal depends on the nature of the files that can be accessed. Reading critical system files or modifying configuration files can severely compromise a system’s security.



### Common Path Traversal Payloads:

Here are some examples of payloads that exploit path traversal vulnerabilities on different systems:

1. **Linux/Unix Systems**:
   - Access the system's password file:
     ```bash
     ../../../../etc/passwd
     ```

   - Access SSH private keys:
     ```bash
     ../../../../root/.ssh/id_rsa
     ```

   - Read the server's configuration file:
     ```bash
     ../../../../etc/apache2/apache2.conf
     ```

2. **Windows Systems**:
   - Access sensitive system configuration files:
     ```bash
     ..\..\..\..\windows\system32\config\SAM
     ```

   - Read registry backup files:
     ```bash
     ..\..\..\..\windows\system32\config\RegBack\SAM
     ```

3. **Null Byte Injection** (legacy systems):
   - In older systems, null byte (`%00`) can terminate file paths, allowing traversal:
     ```bash
     ../../../../etc/passwd%00
     ```

4. **Traversal Combined with File Extension Modification**:
   - If the application appends extensions like `.txt` or `.php` to user input, an attacker can attempt to bypass this:
     ```bash
     ../../../../etc/passwd%00.txt
     ```


### Mitigations:

To prevent path traversal attacks, it's critical to implement a multi-layered defense strategy that includes input validation, secure coding practices, and system-level protections. Here are some key mitigation strategies:

#### 1. **Input Validation and Sanitization**:
   - **Reject Invalid Input**: The first line of defense is ensuring that all user input is properly sanitized. Reject any input containing potentially dangerous characters such as `../`, `..\`, `/%`, or `\`.
   - **Canonicalization**: Use canonicalization methods to convert file paths into a standard form before processing. This ensures that malicious attempts to manipulate file paths are normalized.
   - **Whitelist Input**: Use a whitelist of allowed file paths or directories. Instead of allowing arbitrary file paths from users, only permit a pre-defined set of files that the application needs to access.

#### 2. **Use Secure API Functions**:
   - **Avoid Direct File Access**: Instead of directly accessing files based on user input, use platform-specific functions that prevent traversal outside designated directories.
   - **File APIs**: Use functions like `realpath()` in PHP or `Path.getCanonicalPath()` in Java to ensure the file path being accessed is within the allowed directory structure. These functions resolve relative paths and help avoid directory traversal.
   - **Virtual File Systems**: Implement virtual file systems or chroot environments, which limit the directory scope to a specific subset, preventing traversal beyond a safe boundary.

#### 3. **File Permission Controls**:
   - **Least Privilege**: Ensure that only necessary files have read, write, or execute permissions. The web server or application process should only have access to files it truly needs.
   - **Access Control Lists (ACLs)**: Use ACLs to enforce strict access permissions, especially on sensitive files and directories.
   - **Configuration Hardening**: Lock down access to critical system files like `/etc/passwd` or the Windows Registry, restricting them to privileged users only.

#### 4. **Error Handling and Logging**:
   - **Avoid Disclosing System Information**: Do not expose detailed error messages to users, such as full file paths or system configuration details, which could give attackers clues about the directory structure.
   - **Secure Logs**: Ensure that any logging mechanisms do not log sensitive file path information that could be used to craft attacks.

#### 5. **Web Application Firewalls (WAFs)**:
   - Use a WAF to detect and block path traversal attempts. Modern WAFs are equipped with rules that can detect common path traversal patterns and block them before they reach the web application.

#### 6. **Code Audits and Security Testing**:
   - **Static Code Analysis**: Use static code analysis tools to automatically detect insecure file access patterns.
   - **Penetration Testing**: Conduct regular penetration testing to discover path traversal vulnerabilities. Automated security scanners can also be helpful in identifying these weaknesses.
   - **Fuzzing**: Employ fuzzing techniques to test your application's resilience against malformed or unexpected inputs.

#### 7. **Framework and Library Security**:
   - **Stay Updated**: Keep your frameworks, libraries, and dependencies up to date with the latest security patches. Many frameworks provide built-in protection against path traversal vulnerabilities.
   - **Secure File Upload Handling**: Use secure libraries for handling file uploads, ensuring that user-provided file names are not used directly without validation.



### Conclusion:

Path traversal vulnerabilities can be extremely dangerous, as they allow attackers to access or manipulate sensitive files and configurations. By implementing strong input validation, using secure file handling APIs, enforcing strict file permissions, and leveraging tools like WAFs and code audits, you can protect your applications from these attacks. Proper mitigations are essential to safeguarding both system integrity and sensitive data from unauthorized access.
