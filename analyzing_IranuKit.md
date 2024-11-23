# Analyzing IranuKit: A modular linux kernel rootkit

While hanging out on the Rootkit Researchers Discord server (https://discord.gg/YBJGPkdK), Matheuz
(https://github.com/MatheuZSecurity) discovered an open directory containing some intriguing malware samples. 
Among these were a bootkit, two kernel modules (dropper.ko and rootkit_loader.ko), and a shared library named 
systemdInjector.so. 

![Screenshot 2024-11-23 120125](https://github.com/user-attachments/assets/54f912f0-e01c-4a7e-94c7-9d48af680d28)


The directory also featured an image containing the message "PWNED BY IranuKit".

![logofail_fake](https://github.com/user-attachments/assets/3009bc90-8e2b-4c87-9f58-3889dae60ed9)


This write-up focuses on the two kernel modules and the shared library to uncover how they operate together, 
emphasizing stealth, persistence, and modularity.

## systemdInjector.so

First things first we will get to analyzing systemdInjector.so. Upon opening it in binary ninja we can see that its job is to load dropper.ko which it assumes is located at /opt/dropper.ko, it does this by calling a function named load_module_from_path which loads a kernel module at a given filepath. load_module_from_path does this by first opening the file to get a file descriptor to it and then making a system call to finit_module with the file descriptor as an argument.

![Screenshot 2024-11-23 005010](https://github.com/user-attachments/assets/ee6b5446-976c-4855-9b5c-481bbbcf3f9c)

Whats interesting about systemdInjector.so that it contains placeholders for hooks on SElinux, and also contains a function called init_module which makes a system call to init_module to load a kernel module from memory, however it doesn't seem to utilize this function anywhere.

![Screenshot 2024-11-23 125303](https://github.com/user-attachments/assets/803b0028-89f1-43cc-ae97-ac5b8d4dfa07)



When I uploaded systemdInjector.so to virustotal it showed no detections.

![Screenshot 2024-11-23 123000](https://github.com/user-attachments/assets/d25e0575-b7f6-43db-be60-a217546d120c)

## dropper.ko

dropper.ko's job is to unpack a binary into /opt/observer and then executes it by calling call_usermodehelper, so I extracted the binary for later analysis.

![Screenshot 2024-11-23 005114](https://github.com/user-attachments/assets/60851059-1658-477e-ab25-48c36e2af726)

![Screenshot 2024-11-23 005146](https://github.com/user-attachments/assets/97c5e370-eef0-4ce0-8a8b-c4ff83fe06fa)

![Screenshot 2024-11-23 005325](https://github.com/user-attachments/assets/497d919c-9336-46fc-925a-88d186f21f3c)

![Screenshot 2024-11-23 005349](https://github.com/user-attachments/assets/8ec95915-8b49-42e7-94aa-f72c369352e4)

After executing /opt/observer it then hides its own module, which it does by manipulating the kernel module list.

![Screenshot 2024-11-23 005401](https://github.com/user-attachments/assets/aa49ca63-e080-4747-8b6c-84f0ed70bf36)

We can also see that it contains hooks on system calls such as getdents and getdents64 to hide /opt/observer. It also hooks API's such as tcp4_seq_show to hide network traffic.

![Screenshot 2024-11-23 012738](https://github.com/user-attachments/assets/3bbde4c5-1767-49f0-8454-2b4ea74733da)

![Screenshot 2024-11-23 012749](https://github.com/user-attachments/assets/8677bf43-8a93-4580-9d8e-ce49b188e3c1)

We can also see it targets x86_64 systems.

![Screenshot 2024-11-23 122345](https://github.com/user-attachments/assets/c9ed3719-bf4b-410b-9b50-a8a6c4e9b59c)



When I uploaded dropper.ko to virustotal it showed 1 detection.

![Screenshot 2024-11-23 123013](https://github.com/user-attachments/assets/c0e2078a-24c3-4fbf-b825-4e59833b7437)

## /opt/observer (extracted)

The binary unpacked into /opt/observer, when executed first popens and pcloses gdm3, honestly I have no clue why it does this, I assume to check if its in a graphical user environment?

After it pcloses gdm3 it then loads in a kernel module located at /opt/rootkit_loader.ko by calling the load_module_from_path function, which works the same as the one we found in systemdInjector.so.

![Screenshot 2024-11-23 005657](https://github.com/user-attachments/assets/1cca05e9-394c-4bbf-a1d7-3a9ada1067a8)

![Screenshot 2024-11-23 010307](https://github.com/user-attachments/assets/14a35f8c-8a68-43a8-8e90-045f233c5d7e)



When I uploaded the binary unpacked into /opt/observer to virustotal it showed one detection.

![Screenshot 2024-11-23 123031](https://github.com/user-attachments/assets/4187168e-0265-4162-b5ba-c848a31e0b01)

## rootkit_loader.ko

rootkit_loader.ko first registers a character device at /char/rootkit (very stealth XD). Kernel rootkits targetting linux very often utilize character devices to allow userland processes to directly communicate with the rootkit itself. 

![Screenshot 2024-11-23 011138](https://github.com/user-attachments/assets/e618e12e-38d4-4168-9673-9db94b44b0c4)

We can also see that just like dropper.ko from earlier it unpacks a binary, this time it unpacks a binary into /opt/rootkit which it then executes by calling call_usermodehelper. I then extracted the binary for later analysis.

![Screenshot 2024-11-23 011230](https://github.com/user-attachments/assets/ba1025ec-a503-4857-ab44-49726c6c6008)

![Screenshot 2024-11-23 011305](https://github.com/user-attachments/assets/24d04e1d-3548-493a-ab82-6eb122917ed0)

We can see that rootkit_loader.ko contains very similar hooks as dropper.ko.

![Screenshot 2024-11-23 012608](https://github.com/user-attachments/assets/dccf989e-7677-4fd6-bee1-1776681af603)

![Screenshot 2024-11-23 012628](https://github.com/user-attachments/assets/594f9c4e-35a2-40d5-8fb6-e7115ff2b4bd)



When I uploaded rootkit_loader.ko to virustotal it showed 6 detections.

![Screenshot 2024-11-23 123047](https://github.com/user-attachments/assets/452cf1f5-a6fe-4f4c-b686-ec756189d5ba)

## /opt/rootkit (extracted)

The binary unpacked into /opt/rootkit starts a new thread in which it will call mmap to allocate a region of memory, then it will write its shellcode into that memory and execute it. In the main thread of the process it will keep attempting to open /dev/rootkit, when successful it then kills its own process.

![Screenshot 2024-11-23 011429](https://github.com/user-attachments/assets/8131e29e-885e-43df-a6e7-a2fb1ddd3480)

![Screenshot 2024-11-23 011451](https://github.com/user-attachments/assets/d6fe63d6-7e31-4f07-a8d8-270e3c0be724)

![Screenshot 2024-11-23 011513](https://github.com/user-attachments/assets/6f4a292d-da91-4af3-99b0-c67bda82a4b3)

![Screenshot 2024-11-23 123530](https://github.com/user-attachments/assets/8cc76f35-31b0-405d-9c0b-11b6c6bbe1d1)



When I uploaded the binary unpacked into /opt/rootkit to virustotal it showed 6 detections.

![Screenshot 2024-11-23 123110](https://github.com/user-attachments/assets/855270d5-f46e-4f75-8e3f-8c1feefbb7d4)

## Overall analysis

1. systemdInjector.so loads dropper.ko located in /opt/dropper.ko by calling a function named load_module_from_path. load_module_from_path opens the filepath of the kernel module to get a file descriptor to it, then it makes a system call to finit_module with the file descriptor as an argument to load the kernel module.

2. dropper.ko unpacks a binary into /opt/observer, then executes it, then hides itself by manipulating the module list. From analysing dropper.ko we can see it contains hooks for system calls such as getdents/getdents64 to hide /opt/observer and API's such as tcp4_seq_show to hide network traffic.

3. the executed binary at /opt/observer popens and then pcloses gdm3 (not very sure why, maybe to check if its in a graphical user environment?), It then loads /opt/rootkit_loader.ko by calling the function named load_module_from_path, this function works the same as the one in systemdInjector.so.

4. rootkit_loader.ko registers a character device at /dev/rootkit. Then it writes a binary into /opt/rootkit
and executes it. From analysing rootkit_loader.ko we can see it contains very similar hooks to dropper.ko.

5. the executed binary at /opt/rootkit then starts a new thread where it allocates a region of memory by calling mmap, writes its shellcode to that region of memory and executes it. also we can see from our analysis that it will keep attempting to open /dev/rootkit, and when it has successfully opened and got a valid file descriptor for the character device it will kill its own process.

## Conclusion

In conclusion, IranuKit is a very modular kernel rootkit targetting x86_64 linux systems and has several different components which work together to achieve stealth and persistence. Given its modular nature and the fact that some components, like systemdInjector.so's hooks on SELinux, are placeholders, it suggests that IranuKit is still under development.

If you enjoyed this then make sure to join the rootkit researchers discord server https://discord.gg/YBJGPkdK where we discuss and share insights in developing aswell as detecting and analyzing malware.
