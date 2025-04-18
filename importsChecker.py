import pefile
import os

def imports_analyze(file_path):
    if not os.path.exists(file_path):
        print("File path is incorrect.\n")
        return

    try:
        pe = pefile.PE(file_path)
    except Exception as exc:
        print(f"Cannot open the file - {exc}.\n")
        return
    
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        print("No imports find.")
        return

    nt = pe.OPTIONAL_HEADER.AddressOfEntryPoint

    print("Imports:")
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print(f"{entry.dll.decode('UTF-8')}")
    print(f"Address Of Entry Point: {hex(nt)}")
    print("Imports analysis completed.\n")

def main():
    path = input("Enter path to file: ")
    imports_analyze(path)

if __name__ == "__main__":
    main()
    input("Press Enter to exit...")
