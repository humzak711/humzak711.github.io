# Analyzing Sandfly: An agentless Linux EDR solution

Most EDR solutions rely on installing agents on hosts to collect telemetry, enforce policies, and detect intrusions. Sandfly is an EDR solution which takes a fundamentally different approach, it is an agentless EDR designed for Linux environments. Unlike traditional EDR solutions that requires software running on protected hosts, Sandfly operates remotely via SSH to scan for potential threats across various Linux architectures. This unique design reduces the risk of attackers tampering with the detection system and is very lightweight for protected hosts. In this write-up, I will be analyzing Sandfly's internals primarily through static analysis, aiming to gain a better understanding of how it conducts scans for intrusions. The goal is to provide security researchers with a clearer understanding of how an agentless EDR solution works and the methods it uses to scan for suspicious activity. This analysis does not focus on evasion strategies or bypassing Sandfly, instead it serves as an educational resource for researchers looking to understand agentless EDR solutions.

# Static Analysis

**Sandfly's Scanning Nodes**

Upon opening the Sandfly scanning node binary in Binary Ninja, we can immediately see that it accepts three command-line flags. Two of these flags are related to debugging levels, while the third specifies the file path to the scanning node’s configuration file. This configuration file plays a crucial role in defining how the node operates, including concurrency settings, connection details to the Sandfly server, and CA certificates for authentication.

![Screenshot 2025-02-15 204645](https://github.com/user-attachments/assets/dc998d93-322a-411d-8b06-bead3b5f3289)


Once the configuration file is loaded from disk, the node begins polling the /v4/system/node API endpoint on the Sandfly server to retrieve scanning tasks. Before each request, the node first authenticates with the server via the /v4/auth/login API, ensuring that only authorized nodes can request tasks. During this polling process, it also initializes two flags. If both of these flags are set, the node sleeps for 15 seconds before making the next request to the API. This is likely for rate limiting to prevent excessive requests to the server when no new work is available.

![Screenshot 2025-02-15 204808](https://github.com/user-attachments/assets/f0e36dcd-3d2d-4088-9289-ad06e198d3aa) 
![Screenshot 2025-02-15 204833](https://github.com/user-attachments/assets/9a72b729-a776-44bc-820f-c8ff72e6b367)
![Screenshot 2025-02-15 205107](https://github.com/user-attachments/assets/3328e24f-0d44-4a6b-8dbe-3c0a31131f45)

Once the scanning node receives work from the Sandfly server, it starts to process the information received, which contains details for connecting to remote hosts, credentials for authentication, and priority levels. The node first validates these details by ensuring that fields such as priority levels and SSH port numbers are within expected ranges. It also verifies the provided credentials, determining whether they are SSH keys or username/password combinations before attempting authentication.

![Screenshot 2025-02-15 205508](https://github.com/user-attachments/assets/4b5ba1ee-993d-413e-b783-04b23f8f577f)
![Screenshot 2025-02-15 205716](https://github.com/user-attachments/assets/01e5daec-8175-4b6b-8fab-7da9fed06d83)


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

![Screenshot 2025-02-15 210239](https://github.com/user-attachments/assets/078a3547-a9aa-427c-bd95-b743447d2a49)

The scanner then checks if it has sudo access and provides a password if prompted.

![Screenshot 2025-02-15 210358](https://github.com/user-attachments/assets/9a3e7eeb-adf6-4b89-83c3-1462b1d724d1)
![Screenshot 2025-02-15 210451](https://github.com/user-attachments/assets/ea1e1ce0-7a82-4b5f-8dd4-7cc5ba514c9c)
![Screenshot 2025-02-15 210507](https://github.com/user-attachments/assets/ed15d08c-4edf-4363-8a9c-b7e965bf69ea)


Once these checks are complete, the scanning node prepares to deploy the scanning engine. The scanning engine's binary is embedded within the scanning node at compile time using Go’s embed package. The node dynamically generates a random directory name on the target host, creates the directory, and transfers the scanner binary via the established SSH session. 

![Screenshot 2025-02-15 210643](https://github.com/user-attachments/assets/6c81becc-f107-44f4-9e2f-f3319cb9ad5d)
![Screenshot 2025-02-15 210918](https://github.com/user-attachments/assets/00d746bf-18fa-454a-a959-c062d76eca60)
![Screenshot 2025-02-15 210943](https://github.com/user-attachments/assets/e5939e15-71bd-4953-bf43-78af528be342)
![Screenshot 2025-02-15 211036](https://github.com/user-attachments/assets/1eeb8403-aea8-4b9a-a1eb-d95d4cd62bf5)
![Screenshot 2025-02-15 211120](https://github.com/user-attachments/assets/c912b751-a544-4d67-b104-23ea08c11689)

After deploying the scanner, it executes the binary while passing additional information through stdin, this includes the formatted manifest and whitelisting data.

![Screenshot 2025-02-15 211639](https://github.com/user-attachments/assets/fc35d076-8cc6-4838-a553-fe00c31b0dd8)
![Screenshot 2025-02-15 211652](https://github.com/user-attachments/assets/34b8db27-94f8-4d7f-98a5-c04a49d4ee84)
![Screenshot 2025-02-15 211732](https://github.com/user-attachments/assets/0c9c406e-f4bb-4ecb-be08-1d4d504ae900)

The scanning engine runs its analysis and returns results through stdout and stderr. The scanning node captures this output, closes it's handle to stdin, retrieves the scanner’s exit status, and analyzes it for anomalies, any unexpected exit status could indicate tampering. Once the results are collected and formatted, the scanning node cleans up by deleting the dropped directory and binary from the target host. However, it also checks for a configuration setting that determines whether cleanup should be skipped, which allows for persistent deployment if needed, reducing the overhead of dropping the scanning engine on every scan. 

![Screenshot 2025-02-15 212733](https://github.com/user-attachments/assets/c9cf0bdc-71db-4f2f-b8e1-deaf043feba1)
![Screenshot 2025-02-15 213317](https://github.com/user-attachments/assets/5aa0ea99-46a9-4230-9ea7-134fc9e2c53c)
![Screenshot 2025-02-15 213420](https://github.com/user-attachments/assets/f2d6b00f-fb59-449f-a1c4-888d8adff6b0)
![Screenshot 2025-02-15 213748](https://github.com/user-attachments/assets/5ade6240-842b-469f-9c91-0e8e1ade2438)
![Screenshot 2025-02-15 214244](https://github.com/user-attachments/assets/312890e6-672a-411f-9c4f-bfeb6ed43ff1)
![Screenshot 2025-02-15 214315](https://github.com/user-attachments/assets/ff4cfaa0-724b-4882-9666-f5ba7d0d1f08)

Finally, the scanning node reports errors to the Sandfly server via the /v4/errors API and submits scan results through /v4/system/results. 

![Screenshot 2025-02-15 215044](https://github.com/user-attachments/assets/23a2c263-a90e-448d-97dc-0d27dfe3566f)
![Screenshot 2025-02-15 215138](https://github.com/user-attachments/assets/0c937156-1c1e-4496-83cc-c62a6130f452)

**Sandfly's Scanning Engine**

Upon opening Sandfly’s scanning engine in Binary Ninja, we can see that it processes several command line arguments to control its behavior. It accepts a flag to enable logging to a file, along with flags specifying whether the manifest data is provided via a file instead of stdin and the corresponding filepath. Additionally, it takes a flag which holds the filepath to a file that should be deleted, a flag specifying a basename for its pid and log files and is also the name of the binary it is instructed to run under (to make it harder for an intruder to detect and tamper with the process), a flag to set its process priority, a flag storing the filepath of where it should setup its root jail, and a flag which holds the filepath to an already existing pid file. 

![Screenshot 2025-02-19 023245](https://github.com/user-attachments/assets/e09a4b6b-4b9b-499b-b581-494fc56bd158)

The execution begins by reading the already existing pid file if it's filepath is provided by the flag, terminating the process with that pid, and exiting.

![Screenshot 2025-02-19 023819](https://github.com/user-attachments/assets/01619821-8ec8-4ade-b006-9190e0fd1330)

If the flag which provides the filepath to a file it should delete is set, it deletes the file and exits. 

![Screenshot 2025-02-19 024008](https://github.com/user-attachments/assets/4320abf1-d843-47e3-a99f-543c8cf84e9f)


It then reads, validates, and parses the manifest data. 

![Screenshot 2025-02-19 024119](https://github.com/user-attachments/assets/88346154-e0b8-4569-a75e-1def4051ab2f)
![Screenshot 2025-02-19 024141](https://github.com/user-attachments/assets/3c663cb7-59bd-4ecf-8c84-5680215f882e)
![Screenshot 2025-02-19 024312](https://github.com/user-attachments/assets/0f0280fb-0dba-4e4a-b804-e62bf26fc015)

It then creates and writes its pid to a file named \<basename\>.pid (where \<basename\> is the value held by the flag which specifies the basename for the pid and log files). If logging is enabled, it also creates a log file named \<basename\>.log and writes its pid to it. 

![Screenshot 2025-02-19 030350](https://github.com/user-attachments/assets/0b2f9632-8627-457e-97ce-0b5062d45e32)
![Screenshot 2025-02-19 030413](https://github.com/user-attachments/assets/b99a9749-4170-4c19-8f50-c9d7e238f1c2)
![Screenshot 2025-02-19 030451](https://github.com/user-attachments/assets/d3edcc56-fc01-4d8a-bbab-fb313f033bca)
![Screenshot 2025-02-19 030709](https://github.com/user-attachments/assets/55e6a1ce-e195-46b2-9dde-e90a1eb56132)

The process priority is then adjusted based on the provided flag. 

![Screenshot 2025-02-19 030749](https://github.com/user-attachments/assets/f7e6b82d-daa0-4874-95a7-8518d4883bba)

If a root jail path is specified, the engine sets up the root jail and changes the working directory to it, ensuring an isolated execution environment before proceeding with its scanning operations.

![Screenshot 2025-02-19 030828](https://github.com/user-attachments/assets/e408025d-2e46-4b7e-a2f6-e0b5831fb4ea)
![Screenshot 2025-02-19 030839](https://github.com/user-attachments/assets/fadc8325-dc7d-49f2-a43b-86bc8e0d5572)

After parsing the whitelist and manifest data, the engine compiles and executes the OS exclusion rules using Go's expr package, and then gathers various system details such as the OS version, release, system name, username, UUID, DMI data, uptime, platform, mounted filesystem information, CPU details, and wireless network information. It also checks for a tainted kernel, which can indicate the presence of an unsigned or potentially malicious LKM.

![Screenshot 2025-02-19 183234](https://github.com/user-attachments/assets/0735b87e-f951-4122-8dc3-49ef23273ec2)
![Screenshot 2025-02-19 183246](https://github.com/user-attachments/assets/fd34eb56-53bf-4aa6-a302-4c01301e3700)

The engine’s core capabilities such as detecting hidden files, identifying hidden processes, and performing password audits, are implemented as Go subroutines, which the compiled rules execute. It then compiles and runs the detection rules. Each rule’s output is formatted with an explanation and logged if logging is enabled. Finally, the scan results are formatted and outputted to be captured by the scanning node

![Screenshot 2025-02-19 185936](https://github.com/user-attachments/assets/3875e811-b7fe-4857-a797-587b77afa7d1)
![Screenshot 2025-02-19 190059](https://github.com/user-attachments/assets/68524887-890b-4029-a9b8-fd4a5d70cfe4)
![Screenshot 2025-02-19 190524](https://github.com/user-attachments/assets/95be52b0-3681-4111-81b4-12ab56358cf3)
![Screenshot 2025-02-19 190357](https://github.com/user-attachments/assets/4abaa774-0d65-4eb4-bc08-21a41eea525a)

# Infrastructure

Sandfly’s infrastructure consists of a web server that hosts the UI and API endpoints, scanning nodes that run on either the same or different machines as the server, and protected hosts. The UI allows users to view scan results, assign tasks to scanning nodes, and add protected hosts by providing connection details. This information is sent to an API on the server, which Sandfly nodes continuously poll for available work. Both the web server and scanning nodes run in Docker containers, providing a secure environment and allowing them to operate on the same machine efficiently.

When a scan is initiated, the nodes receive tasks from the server’s API. Upon receiving a task, they decrypt the credentials retrieved from the server and use the decrypted credentials to establish SSH connections to the protected hosts. These credentials are stored on the server encrypted with a public key and can only be decrypted by the nodes, ensuring that no one on the server can see them. Each node then deploys its scanning engine through this SSH session and provides a set of rules defining the security checks to perform. The engine compiles and executes these rules, conducts the scan, and reports the results, including passes, alerts, and errors back to the node. The nodes then post their results and any errors to dedicated API endpoints on the server. The scanning node then disposes of the decrypted credentials once the scan has completed and the results along with any errors have been reported. 

![diagram_black](https://github.com/user-attachments/assets/15c5d981-684f-4570-aac6-66e90afc983a)

By acting as a proxy between the server and the host, the scanning node ensures minimal tampering by remotely verifying that the scanning engine executed as expected. For each request the node makes to the server, it must first authenticate, preventing unauthorized access. Any anomalies in the scanner's execution or the SSH connection between the node and the host indicate potential tampering. One key security advantage of Sandfly’s design is that the scanning node operates on a separate computer from the host it is monitoring, as it conducts it's monitoring remotely via SSH. This means that even if an intruder compromises the monitored host, they cannot directly access the scanning node’s memory or configuration files to steal authentication credentials used for communication with the Sandfly server. Because the node is isolated from the host, it can securely authenticate to the server and relay scan results without exposing its authentication tokens or session data to potential attackers residing on the monitored system. This architecture significantly enhances security by ensuring that even if the host is fully compromised, the attacker cannot interfere with or hijack the scanning node’s communication with the server. This allows the scanning node to reliably detect tampering and report it without risk of its own credentials being stolen. This gives the scanning node an advantage over intruders as it ensures that attempts at evasion or manipulation are logged and flagged while keeping the integrity of the Sandfly scanning infrastructure intact.

# Conclusion

Sandfly’s design minimizes its footprint on protected hosts while maintaining effective scanning capabilities. By leveraging SSH for remote scanning, it avoids direct agent installation, reducing attack surface. The scanning nodes act as a proxy between the server and the protected hosts, securely handling authentication, system enumeration, and scanner deployment while ensuring minimal exposure on the target system. This approach enhances security by preventing direct interaction between the Sandfly server and the scanned host, making it a unique method for Linux endpoint detection and response.
