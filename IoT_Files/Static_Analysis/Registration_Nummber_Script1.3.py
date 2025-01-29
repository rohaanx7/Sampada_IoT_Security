import os
import re
import subprocess

def extract_shadow_passwd(directory):
    shadow_file = os.path.join(directory, "etc", "shadow")
    passwd_file = os.path.join(directory, "etc", "passwd")
    
    shadow_content = None
    passwd_content = None

    if os.path.exists(shadow_file):
        with open(shadow_file, 'r') as f:
            shadow_content = f.read()
    
    if os.path.exists(passwd_file):
        with open(passwd_file, 'r') as f:
            passwd_content = f.read()

    return shadow_content, passwd_content


def list_ssl_files(directory):
    ssl_dir = os.path.join(directory, "etc", "ssl")
    ssl_files = []
    if os.path.exists(ssl_dir):
        for root, _, files in os.walk(ssl_dir):
            ssl_files.extend([os.path.join(root, file) for file in files])
    return ssl_files


def list_config_files(directory):
    config_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(('.conf', '.cfg', '.ini')):
                config_files.append(os.path.join(root, file))
    return config_files


def list_script_files(directory):
    script_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(('.sh', '.lua', '.py', '.pl')):
                script_files.append(os.path.join(root, file))
    return script_files


def list_bin_files(directory):
    bin_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.bin'):
                bin_files.append(os.path.join(root, file))
    return bin_files


def search_for_keywords(directory, keywords):
    found_keywords = []
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'r', errors='ignore') as f:
                    content = f.read()
                    for keyword in keywords:
                        if re.search(keyword, content, re.IGNORECASE):
                            found_keywords.append(keyword)
            except Exception:
                continue
    return list(set(found_keywords))  # Removing duplicates


def list_web_server_binaries(directory):
    web_servers = ["nginx", "httpd", "lighttpd", "apache2", "uc_httpd"]
    web_server_binaries = []
    for root, _, files in os.walk(directory):
        for file in files:
            if any(web_server in file for web_server in web_servers):
                web_server_binaries.append(os.path.join(root, file))
    return web_server_binaries


def list_common_binaries(directory):
    common_binaries = ["busybox", "wget", "curl", "telnet", "bash", "sh"]
    binaries = []
    for root, _, files in os.walk(directory):
        for file in files:
            if any(binary in file for binary in common_binaries):
                binaries.append(os.path.join(root, file))
    return binaries


def extract_urls_emails_ips(directory):
    urls = []
    emails = []
    ips = []
    url_pattern = r'https?://[^\s]+'
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'

    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'r', errors='ignore') as f:
                    content = f.read()
                    urls.extend(re.findall(url_pattern, content))
                    emails.extend(re.findall(email_pattern, content))
                    ips.extend(re.findall(ip_pattern, content))
            except Exception:
                continue
    return list(set(urls)), list(set(emails)), list(set(ips))


if __name__ == "__main__":
    directory = "squashfs-root"  # Change this to your extracted firmware directory

    # Step 1: Extract shadow and passwd content
    shadow, passwd = extract_shadow_passwd(directory)
    
    # Step 2: List SSL-related files
    ssl_files = list_ssl_files(directory)
    
    # Step 3: List config files
    config_files = list_config_files(directory)
    
    # Step 4: List script files
    script_files = list_script_files(directory)
    
    # Step 5: List binary files
    bin_files = list_bin_files(directory)
    
    # Step 6: Search for security-related keywords
    keywords = ['pass', 'pwd', 'key', 'auth', 'token']
    found_keywords = search_for_keywords(directory, keywords)
    
    # Step 7: List common web servers binaries
    web_server_binaries = list_web_server_binaries(directory)
    
    # Step 8: List common binaries
    common_binaries = list_common_binaries(directory)
    
    # Step 9: Extract URLs, emails, and IP addresses
    urls, emails, ips = extract_urls_emails_ips(directory)
    
    # Print the results
    print("etc/shadow content:", shadow if shadow else "Not found")
    print("etc/passwd content:", passwd if passwd else "Not found")
    print("List of SSL files:", ssl_files)
    print("List of configuration files:", config_files)
    print("List of script files:", script_files)
    print("List of .bin files:", bin_files)
    print("Keywords found:", found_keywords)
    print("Web server binaries found:", web_server_binaries)
    print("Common binaries found:", common_binaries)
    print("URLs found:", urls)
    print("Emails found:", emails)
    print("IP addresses found:", ips)
