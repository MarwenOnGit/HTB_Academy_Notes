# FUFF Cheat Sheet

# Directory Fuzzing

## `ffuf -w /usr/share/wordlists/Seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt:FUZZ -u http://SERVER:PORT/FUZZ`

we should also consider matching or filtering the sizes and statuses of responses, as ffuf sometimes returns a lot unwanted directories that would just cover up the important ones, we do this to make the output more readable that’s all. 

# Page Fuzzing

## Extension Fuzzing

## `ffuf -w /usr/share/wordlists/Seclists/Discovery/Web-   Content/web-extensions.txt:FUZZ -u http://SERVER:PORT/<fuzzedDirectory>/indexFUZZ`

## Page Fuzzing

## `ffuf -w /usr/share/wordlists/Seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt:FUZZ -u http://SERVER:PORT/FUZZ.<extension>`

# Recursive Fuzzing

## `ffuf -w /usr/share/wordlists/Seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth <depth> -e <.extension> -v`

Under the recursion depth option we need to put how deep the search is wanted to be. For example,if we specify `-recursion-depth 1`, it will only fuzz the main directories and their direct sub-directories. If any sub-sub-directories are identified (like `/login/user`, it will not fuzz them for pages)
The -e option stands for extension that will be automatically appended whenever a directory/subdirectory is discovered. The -v option gives us the full url to the fuzzed pages.

# Subdomain Fuzzing

## `ffuf -w /usr/share/worldlists/Seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.<DOMAIN-NAME>/`

If this doesn’t return results it doesn’t mean that there are no subdomains, it’s not necessarily true, but if there are subdomains, there aren’t public records of them. And that would take us to the V-host section.

# VHost Fuzzing

**Vhosts vs. Sub-domains**

The key difference between VHosts and sub-domains is that a VHost is basically a 'sub-domain' served on the same server and has the same IP, such that a single IP could be serving two or more different websites. VHosts may or may not have public DNS records.

VHost Fuzzing works with http headers specifically the Host header, because if we don’t do that we would have to add the entire wordlist to our host in the /etc/hosts file, that would be unpractical.

## `ffuf -w /usr/share/wordlists/Seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://<domain-name,server-ip>:PORT/ -H 'Host: FUZZ.<domain-name>'`

# Parameter Fuzzing - GET

You can review this in the file inclusion module notes, i will just add the command here.

## `CSmarwen@htb[/htb]**$** ffuf -w /usr/share/wordlists/Seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://<Domain OR Server IP>:PORT/<directory>/example.php?FUZZ=key -fs xxx`

this is a case where ffuf would return a lot of 200 statuses, we need to filter out the unwanted response size

# Parameter Fuzzing - POST

Unlike the GET request, POST request can be sent from the browser with a simple url and query ?.

Post requests are passed in the data section within the http request. To fuzz the data with ffuf this is the command that we use 

## `ffuf -w /usr/share/wordlists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://<Domain OR Server IP>:PORT/<directory>/example.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx`

We include the Content-Type header because that’s how PHP expects POST requests to be.

# Value Fuzzing

This is the last step before exploitation, after we find subdirectories/directories, pages and parameters, all we need to do now is brute force the value of the parameter. We can do that by creating a custom wordlist that has numbers for example ranging from 0 to 100000 or any other form of wordlist we want. And then we go ahead and FUZZ the value of the already fuzzed parameter.

NOTE: Keep the same method used for fuzzing the parameter in the first place.