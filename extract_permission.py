import os

""" Open folder for reconnaissance """
def openFolder():
    # Get folder path from user
    folder = input("Enter the folder path for reconnaissance: ").strip()
    # Check if the path is valid
    if os.path.exists(folder):
        searchAndMa(folder)
    else:
        print("The folder does not exist!")
        return openFolder()

""" Find AndroidManifest.xml """
def searchAndMa(folder):
    # Loop through all files and directories in the folder
    for f in os.listdir(folder):
        if f == "AndroidManifest.xml":
            try:
                # Open file (use absolute path) in read mode with UTF-8 encoding
                with open(os.path.join(folder, f), "r", encoding="utf-8") as file:
                    print(file.read())
            except Exception as e:
                print(f"Error: {e}")
    print("File does not exist!")

def main():
    openFolder()

if __name__ == "__main__":
    main()

