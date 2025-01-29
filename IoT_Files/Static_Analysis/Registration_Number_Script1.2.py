import os
import hashlib
import re
import subprocess
from collections import Counter
import math

def calculate_entropy(file_path):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        if not data:
            return 0  # Return 0 entropy for empty files
        byte_count = Counter(data)
        total_bytes = len(data)
        entropy = -sum((count / total_bytes) * math.log2(count / total_bytes) for count in byte_count.values())
        return entropy
    except Exception as e:
        print(f"Error computing entropy for {file_path}: {e}")
        return None

def extract_firmware_details(directory):
    report = []
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                size = os.path.getsize(file_path)
                md5_hash = hashlib.md5()
                with open(file_path, 'rb') as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        md5_hash.update(chunk)
                md5 = md5_hash.hexdigest()

                file_format = subprocess.check_output(['file', file_path]).decode().strip()
                with open(file_path, 'rb') as f:
                    content = f.read().decode(errors='ignore')
                urls = re.findall(r'(https?://[^\s]+)', content)
                ip_addresses = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', content)
                entropy = calculate_entropy(file_path)

                # Packing Info
                packing_info = subprocess.check_output(['binwalk', '-B', file_path]).decode(errors='ignore')

                # Architecture Info
                architecture = file_format.split(':')[-1].strip() if 'ARM' in file_format else "Unknown"

                # Metadata
                version = re.search(r'Version:\s*(\S+)', content)
                build_date = re.search(r'Build[_\s]date[:=]\s*([\w\s-]+)', content, re.IGNORECASE)
                developer = re.search(r'Developer[:=]\s*([\w\s]+)', content, re.IGNORECASE)

                # UI Resources
                ui_resources = [file for file in files if file.lower().endswith(('.png', '.jpg', '.ttf', '.ico'))]

                # Cryptographic Algorithms
                crypto_algos = re.findall(r'(AES|RSA|SHA256|MD5|DES)', content)

                # Cryptographic Analysis
                private_keys = re.findall(r'-----BEGIN (RSA|EC) PRIVATE KEY-----', content)
                certificates = re.findall(r'-----BEGIN CERTIFICATE-----', content)

                # Potential Passwords
                strings_output = subprocess.check_output(['strings', file_path]).decode(errors='ignore')
                potential_passwords = re.findall(r'[A-Za-z0-9@#$%^&+=]{8,}', strings_output)
                top_passwords = Counter(potential_passwords).most_common(10)

                report.append({
                    "File Path": file_path,
                    "File Size": f"{size} bytes",
                    "MD5 Hash": md5,
                    "File Format": file_format,
                    "Detected URLs": urls,
                    "Detected IP Addresses": ip_addresses,
                    "Entropy": entropy,
                    "Packing Info": packing_info.strip() or "None",
                    "Architecture": architecture,
                    "Version": version.group(1) if version else "Unknown",
                    "Build Date": build_date.group(1) if build_date else "Unknown",
                    "Developer": developer.group(1) if developer else "Unknown",
                    "UI Resources": ui_resources or "None",
                    "Cryptographic Algorithms": crypto_algos or "None",
                    "Private Keys": private_keys or "None",
                    "Certificates": certificates or "None",
                    "Top Passwords": [pw for pw, _ in top_passwords] or "None",
                })
            except Exception as e:
                print(f"Error analyzing {file_path}: {e}")
    return report

def write_report_to_file(report, output_file):
    with open(output_file, 'w') as f:
        f.write("# Firmware Details Analysis Report\n\n")
        for item in report:
            f.write(f"## {item['File Path']}\n")
            f.write(f"- **File Size:** {item['File Size']}\n")
            f.write(f"- **MD5 Hash:** {item['MD5 Hash']}\n")
            f.write(f"- **File Format:** {item['File Format']}\n")
            f.write(f"- **Detected URLs:** {', '.join(item['Detected URLs']) or 'None'}\n")
            f.write(f"- **Detected IP Addresses:** {', '.join(item['Detected IP Addresses']) or 'None'}\n")
            f.write(f"- **Entropy:** {item['Entropy']}\n")
            f.write(f"- **Packing Info:** {item['Packing Info']}\n")
            f.write(f"- **Architecture:** {item['Architecture']}\n")
            f.write(f"- **Version:** {item['Version']}\n")
            f.write(f"- **Build Date:** {item['Build Date']}\n")
            f.write(f"- **Developer:** {item['Developer']}\n")
            f.write(f"- **UI Resources:** {', '.join(item['UI Resources'])}\n")
            f.write(f"- **Cryptographic Algorithms:** {', '.join(item['Cryptographic Algorithms'])}\n")
            f.write(f"- **Private Keys:** {', '.join(item['Private Keys'])}\n")
            f.write(f"- **Certificates:** {', '.join(item['Certificates'])}\n")
            f.write(f"- **Top Passwords:** {', '.join(item['Top Passwords'])}\n")
            f.write("\n")

if __name__ == "__main__":
    extracted_dir = "squashfs-root"
    output_file = "Firmware_Details_Report.md"
    print("Analyzing firmware files...")
    report = extract_firmware_details(extracted_dir)
    write_report_to_file(report, output_file)
    print(f"Firmware analysis report saved to {output_file}")
