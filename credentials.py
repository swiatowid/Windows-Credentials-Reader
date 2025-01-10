import ctypes
from ctypes import wintypes

# Definitions of structures for managing credentials in Windows
class CREDENTIAL_ATTRIBUTE(ctypes.Structure):
    _fields_ = [
        ('Keyword', wintypes.LPWSTR),
        ('Flags', wintypes.DWORD),
        ('ValueSize', wintypes.DWORD),
        ('Value', ctypes.POINTER(wintypes.BYTE))
    ]

class CREDENTIAL(ctypes.Structure):
    _fields_ = [
        ('Flags', wintypes.DWORD),
        ('Type', wintypes.DWORD),
        ('TargetName', wintypes.LPWSTR),
        ('Comment', wintypes.LPWSTR),
        ('LastWritten', wintypes.FILETIME),
        ('CredentialBlobSize', wintypes.DWORD),
        ('CredentialBlob', ctypes.POINTER(wintypes.BYTE)),
        ('Persist', wintypes.DWORD),
        ('AttributeCount', wintypes.DWORD),
        ('Attributes', ctypes.POINTER(CREDENTIAL_ATTRIBUTE)),
        ('TargetAlias', wintypes.LPWSTR),
        ('UserName', wintypes.LPWSTR)
    ]

# Define a pointer type to a pointer of the CREDENTIAL structure
PCREDENTIAL = ctypes.POINTER(CREDENTIAL)
PCREDENTIAL_ARRAY = ctypes.POINTER(PCREDENTIAL)

# Function to read credentials
def get_credentials():
    CredEnumerate = ctypes.windll.advapi32.CredEnumerateW
    CredEnumerate.restype = wintypes.BOOL
    CredEnumerate.argtypes = [wintypes.LPWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(PCREDENTIAL_ARRAY)]

    count = wintypes.DWORD()
    p_credentials = PCREDENTIAL_ARRAY()

    if CredEnumerate(None, 0, ctypes.byref(count), ctypes.byref(p_credentials)):
        for i in range(count.value):
            credential = p_credentials[i].contents
            target_name = credential.TargetName
            user_name = credential.UserName
            blob_size = credential.CredentialBlobSize
            blob = credential.CredentialBlob
            if blob_size > 0:
                password = ctypes.wstring_at(blob, blob_size // 2)
                
                # Filter only records matching your credential name
                if target_name == "ENTER CREDENTIAL NAME HERE":
                    print(f"Target: {target_name}")
                    print(f"Username: {user_name}")
                    print(f"Password: {password}\n")
        # Free allocated memory for credentials
        ctypes.windll.kernel32.LocalFree(p_credentials)
    else:
        print("Failed to read credentials.")

# Run the function
get_credentials()
