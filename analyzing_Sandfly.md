# Analyzing Sandfly: An agentless Linux EDR solution

Most EDR solutions rely on installing agents on hosts to collect telemetry, enforce policies, and detect intrusions. Sandfly is an EDR solution which takes a fundamentally different approach, it is an agentless EDR designed for Linux environments. Unlike traditional EDR solutions that requires software running on protected hosts, Sandfly operates remotely via SSH to scan for potential threats across various Linux architectures. This unique design reduces the risk of attackers tampering with the detection system and is very lightweight for protected hosts. In this write-up, I will be analyzing Sandfly's internals primarily through static analysis, aiming to gain a better understanding of how it conducts scans for intrusions. The goal is to provide security researchers with a clearer understanding of how an agentless EDR solution works and the methods it uses to scan for suspicious activity. This analysis does not focus on evasion strategies or bypassing Sandfly, instead it serves as an educational resource for researchers looking to understand agentless EDR solutions.

# Static Analysis

**Sandfly's Scanning Nodes**

Upon opening the Sandfly scanning node binary in Binary Ninja, we can immediately see that it accepts three command-line flags. Two of these flags are related to debugging levels, while the third specifies the file path to the scanning node’s configuration file. This configuration file plays a crucial role in defining how the node operates, including concurrency settings, connection details to the Sandfly server, and CA certificates for authentication.

![Screenshot 2025-02-15 204645](https://github.com/user-attachments/assets/c5348011-89f5-4e52-b270-b8f8d9cf9f9e)

Once the configuration file is loaded from disk, the node begins polling the /v4/system/node API endpoint on the Sandfly server to retrieve scanning tasks. Before each request, the node first authenticates with the server via the /v4/auth/login API, ensuring that only authorized nodes can request tasks. During this polling process, it also initializes two flags. If both of these flags are set, the node sleeps for 15 seconds before making the next request to the API. This is likely for rate limiting to prevent excessive requests to the server when no new work is available.

![Screenshot 2025-02-15 204808](https://github.com/user-attachments/assets/34cb231b-692d-4791-9e44-85e125f80bc5)
![Screenshot 2025-02-15 204833](https://github.com/user-attachments/assets/4895ea14-0975-4b29-8708-c2bbdac6ffcf)
![Screenshot 2025-02-15 205107](https://github.com/user-attachments/assets/bff474fd-651a-44d0-9cd1-3bdbefa0daa3)

Once the scanning node receives work from the Sandfly server, it starts to process the information received, which contains details for connecting to remote hosts, credentials for authentication, and priority levels. The node first validates these details by ensuring that fields such as priority levels and SSH port numbers are within expected ranges. It also verifies the provided credentials, determining whether they are SSH keys or username/password combinations before attempting authentication.

![Screenshot 2025-02-15 205508](https://github.com/user-attachments/assets/854d67d5-bce3-47e4-91e4-3f8fab722929)
![Screenshot 2025-02-15 205716](https://github.com/user-attachments/assets/8cd1ad1e-32f3-4ebd-9400-95c21ac7a1e2)


With valid credentials, the scanning node establishes an SSH connection to the target host. Upon successful connection, it gathers system details using the following bash script:

```sh
echo "OS_BEGIN_DATA"; 

echo "OS_UID_USR_BIN=$(/usr/bin/id -u 2>/dev/null)"; 
echo "OS_UID_BIN=$(/bin/id -u 2>/dev/null)"; 
echo "OS_UID_ONLY=$(id -u 2>/dev/null)"; 
echo "OS_SYSTEM_UNAME_BIN=$(/bin/uname 2>/dev/null)"; 
echo "OS_SYSTEM_UNAME_USR_BIN=$(/usr/bin/uname 2>/dev/null)"; 
echo "OS_SYSTEM_UNAME_ONLY=$(uname 2>/dev/null)"; 
echo "OS_ARCH_UNAME_BIN=$(/bin/uname -m 2>/dev/null)"; 
echo "OS_ARCH_UNAME_USR_BIN=$(/usr/bin/uname -m 2>/dev/null)"; 
echo "OS_ARCH_UNAME_ONLY=$(uname -m 2>/dev/null)"; 
echo "OS_PWD_USR_BIN=$(/usr/bin/pwd 2>/dev/null)"; 
echo "OS_PWD_BIN=$(/bin/pwd 2>/dev/null)"; 
echo"OS_PWD_ONLY=$(pwd 2>/dev/null)"; 

echo "OS_ENDIAN_BIN=$(
    /bin/head -c6 /bin/ls 2>/dev/null | 
    ./bin/tail -c1 2>/dev/null | 
    ./bin/tr "\001\002" "LB" 2>/dev/null
)"

echo "OS_ENDIAN_USR_BIN=$(
    /usr/bin/head -c6 /usr/bin/ls 2>/dev/null | 
    /usr/bin/tail -c1 2>/dev/null | 
    /usr/bin/tr "\001\002" "LB" 2>/dev/null
)"

echo "OS_ENDIAN_ONLY=$(
    head -c6 /usr/bin/env 2>/dev/null | 
    tail -c1 2>/dev/null | 
    tr "\001\002" "LB" 2>/dev/null
)"

echo "OS_BITS_BIN=$(
    /bin/head -c5 /bin/ls 2>/dev/null | 
    ./bin/tail -c1 2>/dev/null | 
    ./bin/tr "\001\002" "36" 2>/dev/null
)"

echo "OS_BITS_USR_BIN=$(
    /usr/bin/head -c5 /usr/bin/ls 2>/dev/null | 
    ./usr/bin/tail -c1 2>/dev/null | 
    ./usr/bin/tr "\001\002" "36" 2>/dev/null
)"

echo "OS_BITS_ONLY=$(
    head -c5 /usr/bin/env 2>/dev/null | 
    tail -c1 2>/dev/null | 
    tr "\001\002" "36" 2>/dev/null
)"


echo "OS_CAT_PATH=$(
    if [ -x /usr/bin/cat ]; then 
        echo '/usr/bin/cat'
    elif [ -x /bin/cat ]; then 
        echo '/bin/cat'
    else 
        echo 'cat'
    fi
)"

echo "OS_LS_PATH=$(
    if [ -x /usr/bin/ls ]; then 
        echo '/usr/bin/ls'
    elif [ -x /bin/ls ]; then 
        echo '/bin/ls'
    else 
        echo 'ls'
    fi
)"

echo "OS_RM_PATH=$(
    if [ -x /usr/bin/rm ]; then 
        echo '/usr/bin/rm'
    elif [ -x /bin/rm ]; then 
        echo '/bin/rm'
    else 
        echo 'rm'
    fi
)"

echo "OS_SUDO_PATH=$(
    if [ -x /usr/bin/sudo ]; then 
        echo '/usr/bin/sudo'
    elif [ -x /bin/sudo ]; then 
        echo '/bin/sudo'
    elif [ -x /usr/local/bin/sudo ]; then 
        echo '/usr/local/bin/sudo'
    fi
)"
 
echo "OS_END_DATA"
```

The scanning node then ensures the host is running in a Linux environment and is on a supported architecture. 

![Screenshot 2025-02-15 210239](https://github.com/user-attachments/assets/46b393d4-689c-4901-9dd3-1ab0ea36d843)

The scanner then checks if it has sudo access and provides a password if prompted.

![Screenshot 2025-02-15 210358](https://github.com/user-attachments/assets/2f072f9f-6f01-44ec-b769-7dfdc87db678)
![Screenshot 2025-02-15 210451](https://github.com/user-attachments/assets/300bf5e8-1f7e-4239-8e35-85dfe8ed218f)
![Screenshot 2025-02-15 210507](https://github.com/user-attachments/assets/aa7ab8cd-0c36-422f-b3ab-057e803d96e2)

Once these checks are complete, the scanning node prepares to deploy the scanning engine. The scanning engine's binary is embedded within the scanning node at compile time using Go’s embed package. The node dynamically generates a random directory name on the target host, creates the directory, and transfers the scanner binary via the established SSH session. 

![Screenshot 2025-02-15 210643](https://github.com/user-attachments/assets/0c6aa3d3-c925-491a-ac0e-30d1cbc307f0)
![Screenshot 2025-02-15 210918](https://github.com/user-attachments/assets/5fb458e9-8e4d-4223-8e53-0608f275bb3c)
![Screenshot 2025-02-15 210943](https://github.com/user-attachments/assets/f88171d6-d50a-4027-a70e-cfc74d6f2a18)
![Screenshot 2025-02-15 211036](https://github.com/user-attachments/assets/92b1e206-9894-44f9-b514-181d7067ddcd)
![Screenshot 2025-02-15 211120](https://github.com/user-attachments/assets/fa290d5d-7c6c-47f1-a70f-800ca8b5f984)


After deploying the scanner, it executes the binary while passing additional information through stdin, this includes the formatted manifest and whitelisting data.

![Screenshot 2025-02-15 211639](https://github.com/user-attachments/assets/f4de2852-096c-42c3-823f-59b7a87292ba)
![Screenshot 2025-02-15 211652](https://github.com/user-attachments/assets/d3fb2143-cfff-4819-b0ee-f54bab202f0f)
![Screenshot 2025-02-15 211732](https://github.com/user-attachments/assets/9b8d1801-9b03-432a-b9a4-15e901d3a834)

The scanning engine runs its analysis and returns results through stdout and stderr. The scanning node captures this output, closes it's handle to stdin, retrieves the scanner’s exit status, and analyzes it for anomalies, any unexpected exit status could indicate tampering. Once the results are collected and formatted, the scanning node cleans up by deleting the dropped directory and binary from the target host. However, it also checks for a configuration setting that determines whether cleanup should be skipped, which allows for persistent deployment if needed, reducing the overhead of dropping the scanning engine on every scan. 

![Screenshot 2025-02-15 212733](https://github.com/user-attachments/assets/f304a045-3177-43fa-bc1b-a1c6c524c3b7)
![Screenshot 2025-02-15 213317](https://github.com/user-attachments/assets/0032dd14-dcf5-4bf0-9577-5e1a2e817704)
![Screenshot 2025-02-15 213420](https://github.com/user-attachments/assets/f8d30dd0-3640-482f-9fac-86bfbe672a56)
![Screenshot 2025-02-15 213748](https://github.com/user-attachments/assets/cdfcab5f-b15a-4518-b78b-ab330bf5c591)
![Screenshot 2025-02-15 214244](https://github.com/user-attachments/assets/ef49fbf3-82af-4cdf-a301-594fe3c84e2d)
![Screenshot 2025-02-15 214315](https://github.com/user-attachments/assets/c403ecc8-e429-43ec-b793-a75fe31cb274)

Finally, the scanning node reports errors to the Sandfly server via the /v4/errors API and submits scan results through /v4/system/results. 

![Screenshot 2025-02-15 215044](https://github.com/user-attachments/assets/532b614c-22ae-4aaf-9cf7-b8de5ed68262)
![Screenshot 2025-02-15 215138](https://github.com/user-attachments/assets/874ca0e8-9527-4fd5-ab1c-d5c21fd93c5d)


**Sandfly's Scanning Engine**

Upon opening Sandfly’s scanning engine in Binary Ninja, we can see that it processes several command line arguments to control its behavior. It accepts a flag to enable logging to a file, along with flags specifying whether the manifest data is provided via a file instead of stdin and the corresponding filepath. Additionally, it takes a flag which holds the filepath to a file that should be deleted, a flag specifying a basename for its pid and log files and is also the name of the binary it is instructed to run under (to make it harder for an intruder to detect and tamper with the process), a flag to set its process priority, a flag storing the filepath of where it should setup its root jail, and a flag which holds the filepath to an already existing pid file. 

![Screenshot 2025-02-19 023245](https://github.com/user-attachments/assets/d65c1928-72a4-4835-9bc5-81e8b521f0a4)

The execution begins by reading the already existing pid file if it's filepath is provided by the flag, terminating the process with that pid, and exiting.

![Screenshot 2025-02-19 023819](https://github.com/user-attachments/assets/ecbbe661-8d5d-4e79-a7d1-73186b08d2e3)

If the flag which provides the filepath to a file it should delete is set, it deletes the file and exits. 

![Screenshot 2025-02-19 024008](https://github.com/user-attachments/assets/42f6d7fc-5fb6-4f84-b4cb-3900c240a56d)

It then reads, validates, and parses the manifest data. 

![Screenshot 2025-02-19 024119](https://github.com/user-attachments/assets/20aeb032-49d4-4724-a04c-a25d15ae3b19)
![Screenshot 2025-02-19 024141](https://github.com/user-attachments/assets/0ecaa2d0-6a7f-4661-811e-5a96b43b51e6)
![Screenshot 2025-02-19 024312](https://github.com/user-attachments/assets/fab29a62-1e30-4298-940c-553c059ebf3c)

It then creates and writes its pid to a file named \<basename\>.pid (where \<basename\> is the value held by the flag which specifies the basename for the pid and log files). If logging is enabled, it also creates a log file named \<basename\>.log and writes its pid to it. 

![Screenshot 2025-02-19 030350](https://github.com/user-attachments/assets/22d76932-b043-4d05-acda-e465a2339c0f)
![Screenshot 2025-02-19 030413](https://github.com/user-attachments/assets/806355f1-65a5-4671-886d-8eb7b85e4bff)
![Screenshot 2025-02-19 030451](https://github.com/user-attachments/assets/54b6f27a-cb7d-4683-b147-a53c3c6f4aee)
![Screenshot 2025-02-19 030709](https://github.com/user-attachments/assets/f4ab4a69-5157-408e-983c-3a36960dd10e)

The process priority is then adjusted based on the provided flag. 

![Screenshot 2025-02-19 030749](https://github.com/user-attachments/assets/f5af4b9d-7c19-4e43-bcb9-30e75d53e44a)

If a root jail path is specified, the engine sets up the root jail and changes the working directory to it, ensuring an isolated execution environment before proceeding with its scanning operations.

![Screenshot 2025-02-19 030828](https://github.com/user-attachments/assets/ff8996fa-a6b6-4ab9-934e-e5df44692784)
![Screenshot 2025-02-19 030839](https://github.com/user-attachments/assets/71f480a4-b640-4a3c-ad2f-5caf53c48640)

After parsing the whitelist and manifest data, the engine compiles and executes the OS exclusion rules using Go's expr package, and then gathers various system details such as the OS version, release, system name, username, UUID, DMI data, uptime, platform, mounted filesystem information, CPU details, and wireless network information. It also checks for a tainted kernel, which can indicate the presence of an unsigned or potentially malicious LKM.

![Screenshot 2025-02-19 183234](https://github.com/user-attachments/assets/1b86e03c-8e72-43bc-b13d-692da0eb6202)
![Screenshot 2025-02-19 183246](https://github.com/user-attachments/assets/a330c033-7945-4b3d-884f-b41274c7993b)

The engine’s core capabilities such as detecting hidden files, identifying hidden processes, and performing password audits, are implemented as Go subroutines, which the compiled rules execute. It then compiles and runs the detection rules. Each rule’s output is formatted with an explanation and logged if logging is enabled. Finally, the scan results are formatted and outputted to be captured by the scanning node

![Screenshot 2025-02-19 185936](https://github.com/user-attachments/assets/e51bbe91-9b35-4464-bed8-bc9eb4760243)
![Screenshot 2025-02-19 190059](https://github.com/user-attachments/assets/3d480260-62a7-4755-bbcf-12287be0ce2f)
![Screenshot 2025-02-19 190357](https://github.com/user-attachments/assets/a158aaa6-1ff9-4d67-b44e-ae0ba9a6ae3f)
![Screenshot 2025-02-19 190524](https://github.com/user-attachments/assets/e233272b-73b9-49b6-8a4c-7d34de66de94)

# Infrastructure

Sandfly’s infrastructure consists of a web server that hosts the UI and API endpoints, scanning nodes that run on either the same or different machines as the server, and protected hosts. The UI allows users to view scan results, assign tasks to scanning nodes, and add protected hosts by providing connection details. This information is sent to an API on the server, which Sandfly nodes continuously poll for available work. Both the web server and scanning nodes run in Docker containers, providing a secure environment and allowing them to operate on the same machine efficiently.

When a scan is initiated, the nodes receive tasks from the server’s API. Upon receiving a task, they decrypt the credentials retrieved from the server and use the decrypted credentials to establish SSH connections to the protected hosts. These credentials are stored on the server encrypted with a public key and can only be decrypted by the nodes, ensuring that no one on the server can see them. Each node then deploys its scanning engine through this SSH session and provides a set of rules defining the security checks to perform. The engine compiles and executes these rules, conducts the scan, and reports the results, including passes, alerts, and errors back to the node. The nodes then post their results and any errors to dedicated API endpoints on the server. The scanning node then disposes of the decrypted credentials once the scan has completed and the results along with any errors have been reported. 

![diagram_black](https://github.com/user-attachments/assets/9a008af6-550a-4405-90fa-9a24f91ac754)

By acting as a proxy between the server and the host, the scanning node ensures minimal tampering by remotely verifying that the scanning engine executed as expected. For each request the node makes to the server, it must first authenticate, preventing unauthorized access. Any anomalies in the scanner's execution or the SSH connection between the node and the host indicate potential tampering. One key security advantage of Sandfly’s design is that the scanning node operates on a separate computer from the host it is monitoring, as it conducts it's monitoring remotely via SSH. This means that even if an intruder compromises the monitored host, they cannot directly access the scanning node’s memory or configuration files to steal authentication credentials used for communication with the Sandfly server. Because the node is isolated from the host, it can securely authenticate to the server and relay scan results without exposing its authentication tokens or session data to potential attackers residing on the monitored system. This architecture significantly enhances security by ensuring that even if the host is fully compromised, the attacker cannot interfere with or hijack the scanning node’s communication with the server. This allows the scanning node to reliably detect tampering and report it without risk of its own credentials being stolen. This gives the scanning node an advantage over intruders as it ensures that attempts at evasion or manipulation are logged and flagged while keeping the integrity of the Sandfly scanning infrastructure intact.

# Conclusion

Sandfly’s design minimizes its footprint on protected hosts while maintaining effective scanning capabilities. By leveraging SSH for remote scanning, it avoids direct agent installation, reducing attack surface. The scanning nodes act as a proxy between the server and the protected hosts, securely handling authentication, system enumeration, and scanner deployment while ensuring minimal exposure on the target system. This approach enhances security by preventing direct interaction between the Sandfly server and the scanned host, making it a unique method for Linux endpoint detection and response.
