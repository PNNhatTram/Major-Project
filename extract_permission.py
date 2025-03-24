import os
import subprocess

""" Find and process APK files with Apktool """

def handleAPK(file, apktool_path):
    print(f"Decompiling {file} using {apktool_path}...")
    try:
        # apktool d <apk_path> -o <decompile_folder_path> -f
        decompile_folder = file.rsplit(".apk", 1)[0]        
        subprocess.run([apktool_path, "d", file, "-o", decompile_folder, "-f"], check=True)        
        manifest_path = os.path.join(decompile_folder, "AndroidManifest.xml")
        if os.path.exists(manifest_path):
            with open(manifest_path, "r", encoding="utf-8") as manifest_file:
                printPermission(manifest_file)
        else:
            print(f"AndroidManifest.xml not found in {decompile_folder}")
    except subprocess.CalledProcessError as e:
        print(f"Error decompile APK {file}: {e}")
    except Exception as e:
        print(f"Error: {e}")


""" Extract Permission """


def printPermission(file):
    try:  
        # List permission  
        permissions = []
        permission_prefix = "android.permission."
        for line in file:
            if permission_prefix in line:
                start_id = line.find(permission_prefix) + len(permission_prefix)
                end_id = line.find('"', start_id)
                permission = line[start_id:end_id].strip()
                if permission and permission not in permissions:
                    permissions.append(permission)
        # Write list 
        with open('result.txt', 'w', encoding='utf-8') as wf:
            permissions_str = ", ".join(permissions)            
            wf.write(f"permission = [{permissions_str}]")
        print("The results have been saved to the file reconn.txt")
    except Exception as e:
        print(f"Error: {e}")


def main():
    # Get Apktool path from user
    apktool_path = input("Enter the path of Apktool or press Enter for default (ex: C:/Windows/apktool.bat): ").strip()
    if not apktool_path:
        apktool_path = r"C:\Windows\apktool.bat"
    while not os.path.exists(apktool_path):
        print(f"Apktool not found at: {apktool_path}")
        apktool_path = input("Please enter the correct path to apktool.bat: ").strip()
        if not apktool_path:
            apktool_path = r"C:\Windows\apktool.bat"
    # Get file path from user
    file_path = input(
        "Enter the file path for reconnaissance (ex: C:/Users/YourName/Documents/example.apk): ").strip()
    while not os.path.exists(file_path):
        print(f"File not found at: {file_path}")
        file_path = input("Please enter the correct path: ").strip()
    handleAPK(file_path, apktool_path)

def check_java():
    try:
        subprocess.run(["java", "-version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError:
        print("Error: Java is not installed or not configured properly. Please install JDK.")
        exit(1)

if __name__ == "__main__":
    check_java()
    main()
