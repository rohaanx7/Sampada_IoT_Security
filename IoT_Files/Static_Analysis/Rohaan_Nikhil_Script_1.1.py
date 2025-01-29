import os

# Function to determine the file type based on its extension
def get_file_type(file_path):
    if os.path.isdir(file_path):
        return "directory"
    elif file_path.endswith('.bin'):
        return "binary"
    elif file_path.endswith('.txt'):
        return "text"
    elif file_path.endswith('.sh'):
        return "script"
    elif file_path.endswith('.jpg') or file_path.endswith('.png'):
        return "image"
    else:
        return "unknown"

# Function to generate the file tree recursively up to a given depth
def file_tree(path, depth=0, max_depth=8):
    if depth > max_depth:
        return ""
    
    tree_structure = ""
    try:
        # List all files and directories in the current directory
        for item in os.listdir(path):
            item_path = os.path.join(path, item)
            item_type = get_file_type(item_path)
            tree_structure += "  " * depth + f"--- {item} [{item_type}]\n"
            
            # If it's a directory, recursively explore its contents
            if os.path.isdir(item_path):
                tree_structure += file_tree(item_path, depth + 1, max_depth)
    except PermissionError:
        tree_structure += "  " * depth + f"--- {item} [Permission Denied]\n"
    
    return tree_structure

# Function to generate the markdown file structure report
def generate_file_structure_report(extracted_dir, output_file="file_structure_report.md"):
    report_content = "# Directory Tree Structure\n"
    report_content += file_tree(extracted_dir)
    
    # Write the tree structure to a markdown file
    with open(output_file, "w") as f:
        f.write(report_content)
    print(f"File Structure Report generated at: {output_file}")

# Path to the extracted firmware directory (adjust as per your extraction path)
extracted_dir = "_chakravyuh.bin.extracted/squashfs-root"  # Update with your actual extracted path
generate_file_structure_report(extracted_dir)
