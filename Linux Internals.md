# Linux Internals

# Services and Process Management

Services also referred to as daemons are fundamental components that run in the background without user interaction, they provide functionalities to keep the os operational and functional.

**System Services**

Internal services essential for system startup. They handle hardware tasks and initialize components needed for the OS to run—like a car’s engine and transmission. Without them, the system won’t function.

**User-Installed Services**

Added by users, these services provide extra features, like servers or background apps—similar to a car’s AC or GPS. Not critical, but enhance functionality.

Daemons often end with **d**, e.g., `sshd` or `systemd`. Linux relies on both system and user services for a complete, efficient experience.

**Service/Process Management Goals:**

- Start/Restart
- Stop
- Monitor
- Enable/Disable at boot
- Locate

## Systemctl

Pretty self-explanatory, this command is used for starting linux services such as ssh, ftpd ..etc 

We can also make services start on startup with the following command:

`D3xt3rM0Rg4IV@htb[/htb]**$** systemctl enable ssh`

`Synchronizing state of ssh.service with SysV service script with /lib/systemd/systemd-sysv-install.
Executing: /lib/systemd/systemd-sysv-install enable ssh`

Once we reboot the system, the OpenSSH server will automatically run. We can check this with a tool called `ps`.

Service and Process Management

```bash
D3xt3rM0Rg4IV@htb[/htb]$ ps -aux | grep sshroot       846  0.0  0.1  72300  5660 ?        Ss   Mai14   0:00 /usr/sbin/sshd -D
```

We can also use `systemctl` to list all services.

Service and Process Management

```bash
D3xt3rM0Rg4IV@htb[/htb]$ systemctl list-units --type=serviceUNIT                                                       LOAD   ACTIVE SUB     DESCRIPTION
accounts-daemon.service                                    loaded active running Accounts Service
acpid.service                                              loaded active running ACPI event daemon
apache2.service                                            loaded active running The Apache HTTP Server
apparmor.service                                           loaded active exited  AppArmor initialization
apport.service                                             loaded active exited  LSB: automatic crash repor
avahi-daemon.service                                       loaded active running Avahi mDNS/DNS-SD Stack
bolt.service                                               loaded active running Thunderbolt system service
```

It is quite possible that the services do not start due to an error. To see the problem, we can use the tool `journalctl` to view the logs.

Service and Process Management

```bash
D3xt3rM0Rg4IV@htb[/htb]$ journalctl -u ssh.service --no-pager-- Logs begin at Wed 2020-05-13 17:30:52 CEST, end at Fri 2020-05-15 16:00:14 CEST. --
Mai 13 20:38:44 inlane systemd[1]: Starting OpenBSD Secure Shell server...
Mai 13 20:38:44 inlane sshd[2722]: Server listening on 0.0.0.0 port 22.
Mai 13 20:38:44 inlane sshd[2722]: Server listening on :: port 22.
Mai 13 20:38:44 inlane systemd[1]: Started OpenBSD Secure Shell server.
Mai 13 20:39:06 inlane sshd[3939]: Connection closed by 10.22.2.1 port 36444 [preauth]
Mai 13 20:39:27 inlane sshd[3942]: Accepted password for master from 10.22.2.1 port 36452 ssh2
Mai 13 20:39:27 inlane sshd[3942]: pam_unix(sshd:session): session opened for user master by (uid=0)
Mai 13 20:39:28 inlane sshd[3942]: pam_unix(sshd:session): session closed for user master
Mai 14 02:04:49 inlane sshd[2722]: Received signal 15; terminating.
Mai 14 02:04:49 inlane systemd[1]: Stopping OpenBSD Secure Shell server...
Mai 14 02:04:49 inlane systemd[1]: Stopped OpenBSD Secure Shell server.
-- Reboot --

```

## Background Processes

Sometimes it will be necessary to put the scan or process we just started in the background to continue using the current session to interact with the system or start other processes. As we have already seen, we can do this with the shortcut `[Ctrl + Z]`. As mentioned above, we send the `SIGTSTP` signal to the kernel, which suspends the process.

Service and Process Management

```bash
D3xt3rM0Rg4IV@htb[/htb]$ ping -c 10 www.hackthebox.euD3xt3rM0Rg4IV@htb[/htb]$ vim tmpfile[Ctrl + Z]
[2]+  Stopped                 vim tmpfile

```

Now all background processes can be displayed with the following command.

Service and Process Management

```bash
D3xt3rM0Rg4IV@htb[/htb]$ jobs[1]+  Stopped                 ping -c 10 www.hackthebox.eu
[2]+  Stopped                 vim tmpfile

```

The `[Ctrl] + Z` shortcut suspends the processes, and they will not be executed further. To keep it running in the background, we have to enter the command `bg` to put the process in the background.

Service and Process Management

```bash
D3xt3rM0Rg4IV@htb[/htb]$ bgD3xt3rM0Rg4IV@htb[/htb]$ --- www.hackthebox.eu ping statistics ---
10 packets transmitted, 0 received, 100% packet loss, time 113482ms

[ENTER]
[1]+  Exit 1                  ping -c 10 www.hackthebox.eu

```

Another option is to automatically set the process with an AND sign (`&`) at the end of the command.

Service and Process Management

```bash
D3xt3rM0Rg4IV@htb[/htb]$ ping -c 10 www.hackthebox.eu &[1] 10825
PING www.hackthebox.eu (172.67.1.1) 56(84) bytes of data.

```

Once the process finishes, we will see the results.

Service and Process Management

```bash
D3xt3rM0Rg4IV@htb[/htb]$ --- www.hackthebox.eu ping statistics ---
10 packets transmitted, 0 received, 100% packet loss, time 9210ms

[ENTER]
[1]+  Exit 1                  ping -c 10 www.hackthebox.eu

```

# Task Scheduling

**Task scheduling** in Linux automates tasks at specific times or intervals, removing the need for manual execution. Common uses include software updates, script execution, database maintenance, and backups, with options for alerts on certain events. Like a programmed coffee maker, it ensures tasks run reliably and consistently.

For **cybersecurity specialists and penetration testers**, understanding task scheduling is vital. It’s both a legitimate admin tool and a potential attack vector—malicious cron jobs can maintain persistence or run harmful scripts. Knowing how it works helps identify risks, audit systems, and even simulate attacks in penetration testing.

## Systemd

Systemd is a service used in Linux systems such as Ubuntu, Redhat Linux, and Solaris to start processes and scripts at a specific time. With it, we can set up processes and scripts to run at a specific time or time interval and can also specify specific events and triggers that will trigger a specific task. To do this, we need to take some steps and precautions before our scripts or processes are automatically executed by the system.

1. Create a timer (schedules when your `mytimer.service` should run)
2. Create a service (executes the commands or script)
3. Activate the timer

### **Create a Timer**

To create a timer for systemd, we need to create a directory where the timer script will be stored.

Task Scheduling

```bash
D3xt3rM0Rg4IV@htb[/htb]$ sudo mkdir /etc/systemd/system/mytimer.timer.dD3xt3rM0Rg4IV@htb[/htb]$ sudo vim /etc/systemd/system/mytimer.timer
```

Next, we need to create a script that configures the timer. The script must contain the following options: "Unit", "Timer" and "Install". The "Unit" option specifies a description for the timer. The "Timer" option specifies when to start the timer and when to activate it. Finally, the "Install" option specifies where to install the timer.

### **Mytimer.timer**

Code: txt

```
[Unit]
Description=My Timer

[Timer]
OnBootSec=3min
OnUnitActiveSec=1hour

[Install]
WantedBy=timers.target

```

Here it depends on how we want to use our script. For example, if we want to run our script only once after the system boot, we should use `OnBootSec` setting in `Timer`. However, if we want our script to run regularly, then we should use the `OnUnitActiveSec` to have the system run the script at regular intervals. Next, we need to create our `service`.

### **Create a Service**

Task Scheduling

```bash
D3xt3rM0Rg4IV@htb[/htb]$ sudo vim /etc/systemd/system/mytimer.service
```

## Cron

Another way to create automated processes is by using cron.

With **Cron**, we can also automate tasks, but its setup differs from **Systemd**. Tasks are stored in a **crontab** file, where we define when and how they should run. By configuring the Cron daemon with these entries, we can schedule and automate tasks. A Cron job is defined using the following components:

| **Time Frame** | **Description** |
| --- | --- |
| Minutes (0-59) | This specifies in which minute the task should be executed. |
| Hours (0-23) | This specifies in which hour the task should be executed. |
| Days of month (1-31) | This specifies on which day of the month the task should be executed. |
| Months (1-12) | This specifies in which month the task should be executed. |
| Days of the week (0-7) | This specifies on which day of the week the task should be executed. |

For example, such a crontab could look like this:

Code: txt

```
# System Update
0 */6 * * * /path/to/update_software.sh

# Execute Scripts
0 0 1 * * /path/to/scripts/run_scripts.sh

# Cleanup DB
0 0 * * 0 /path/to/scripts/clean_database.sh

# Backups
0 0 * * 7 /path/to/scripts/backup.sh
```

### **Systemd vs. Cron**

Systemd and Cron are both tools that can be used in Linux systems to schedule and automate processes. The key difference between these two tools is how they are configured. With Systemd, you need to create a timer and services script that tells the operating system when to run the tasks. On the other hand, with Cron, you need to create a `crontab` file that tells the cron daemon when to run the tasks.

# Network Services (NFS to be thorough)

NFS (Network File System) lets you access and manage files on remote machines as if they were local, making centralized storage and collaboration simple. Admins use it to share files across Linux and Windows systems, replicate file systems, and allow multiple users simultaneous access with access controls and near real-time transfers. Common NFS server implementations include `nfs-utils` (Linux/Ubuntu), `NFS-Ganesha` (Solaris), and `OpenNFS` (Red Hat). If an FTP client isn’t available on a target, NFS can be used as an alternative for file sharing.

We can configure NFS via the configuration file `/etc/exports`. This file specifies which directories should be shared and the access rights for users and systems. It is also possible to configure settings such as the transfer speed and the use of encryption. NFS access rights determine which users and systems can access the shared directories and what actions they can perform. Here are some important access rights that can be configured in NFS:

| **Permissions** | **Description** |
| --- | --- |
| `rw` | Gives users and systems read and write permissions to the shared directory. |
| `ro` | Gives users and systems read-only access to the shared directory. |
| `no_root_squash` | Prevents the root user on the client from being restricted to the rights of a normal user. |
| `root_squash` | Restricts the rights of the root user on the client to the rights of a normal user. |
| `sync` | Synchronizes the transfer of data to ensure that changes are only transferred after they have been saved on the file system. |
| `async` | Transfers data asynchronously, which makes the transfer faster, but may cause inconsistencies in the file system if changes have not been fully committed. |

# Web Servers and Linux

We have several options when it comes to web dev and all like apache, nginx and even python web servers. 

To get familiar with the concepts, I played around with the most popular of linux web servers which is apache servers, i installed one in my local machine and understood al little about how it works.

# Containers

Containerization is a method of packaging an application with all its necessary components, like libraries and dependencies, into an isolated environment called a **container**. This ensures the application runs consistently and reliably across different computing environments.

### Key Points:

- **Core Technology**: Technologies like **Docker** and **Linux Containers (LXC)** are central to containerization. They create lightweight, portable environments for applications.
- **Containers vs. Virtual Machines (VMs)**: Unlike VMs, which require a full guest operating system, containers share the host system's kernel. This makes them significantly more **lightweight, faster to start, and resource-efficient**.
- **Benefits**:
    - **Portability**: Applications run the same way everywhere, from a developer's laptop to production servers.
    - **Efficiency**: Allows for running many containers on a single host, which is ideal for microservice architectures.
    - **Scalability**: Easy to scale applications up or down by adding or removing containers.
- **Security**:
    - **Isolation**: Containers provide a security barrier by isolating applications from the host and each other.
    - **Risks**: Despite the isolation, they are not foolproof. Vulnerabilities like **privilege escalation** or **container escapes** can pose significant security risks if not managed properly. The level of isolation is generally less than that of a traditional VM.

### **Install Docker-Engine**

Installing Docker is relatively straightforward. We can use the following script to install it on a Ubuntu host:

Code: bash

```bash
#!/bin/bash# Preparation
sudo apt update -y
sudo apt install ca-certificates curl gnupg lsb-release -y
sudo mkdir -m 0755 -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker Engine
sudo apt update -y
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y

# Add user htb-student to the Docker group
sudo usermod -aG docker htb-student
echo '[!] You need to log out and log back in for the group changes to take effect.'

# Test Docker installation
docker run hello-world
```      
       
