import os

""" Open folder for reconnaissance """
def openFolder():
    # Get folder path from user
    folder = input("Enter the folder path for reconnaissance: ").strip()
    # Check if the path is valid
    if os.path.exists(folder):
        print(folder)
    else:
        print("The folder does not exist!")
        return openFolder()
    
def main():
    openFolder()

if __name__ == "__main__":
    main()

