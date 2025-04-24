import pefile
import os

def winapi_analyze(file_path, winapi_list):

    used_api = []

    try:
        pe = pefile.PE(file_path)
    except Exception as exc:
        print(f"[-] Cannot open the file - {exc}.\n")
        return

    if not os.path.exists(file_path):
        print("[-] File path is incorrect.\n")
        return
    
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name and imp.name.decode() in winapi_list:
                    used_api.append(imp.name.decode())
    else:
        print("[-] No imports find.")
        return

    return used_api

def imports_analyze(file_path):
    if not os.path.exists(file_path):
        print("[-] File path is incorrect.\n")
        return

    try:
        pe = pefile.PE(file_path)
    except Exception as exc:
        print(f"[-] Cannot open the file - {exc}.\n")
        return
    
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        print("[-] No imports find.")
        return

    nt = pe.OPTIONAL_HEADER.AddressOfEntryPoint

    print("[+] Imports:")
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print(f"    [#] {entry.dll.decode('UTF-8')}")
    print(f"[+] Address Of Entry Point: {hex(nt)}")
    print("[+] Imports analysis completed.\n")

def main():
    path = input("[~] Enter path to file: ")

    imports_analyze(path)

    winapi_list = ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugStringA"
                   "OutputDebugStringW", "CreateToolhelp32Snapshot", "Process32First",
                   "NTQuerySystemInformation", "NtQueryInformationProcess",
                   "ProcessDebugPort", "NtGetContextThread", "NtSetContextThread",]
    
    result = winapi_analyze(path, winapi_list)

    if result:
        print("[+] Suspicious API calls found:")
        for api in result:
            print(f"    [#] {api}\n",end="")
        print("[+] Count of founded API calls:", len(result))
        print("[+] Suspicious API calls analysis completed.\n")
    else:
        print("[-] No suspicious API calls found.\n")
    input()
        
if __name__ == "__main__":
    main()
