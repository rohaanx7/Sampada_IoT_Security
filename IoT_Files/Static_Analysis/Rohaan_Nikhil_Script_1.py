import os
import subprocess

def extract_firmware(binary_file):
    
    extract_dir = f"{binary_file}.extracted"
    if os.path.exists(extract_dir):
        os.system(f"rm -rf {extract_dir}")
    
    # Run binwalk to extract firmware 
    try:
        subprocess.run(["sudo", "binwalk", "-e", "--run-as=root", binary_file], check=True)
        print(f"Firmware extracted to: {extract_dir}")
    except subprocess.CalledProcessError as e:
        print(f"Error during firmware extraction: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    binary_file = "chakravyuh.bin"
    extract_firmware(binary_file)
