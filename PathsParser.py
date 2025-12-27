import webview
import os
import sys
import time
import ctypes
from ctypes import wintypes, POINTER, byref, create_unicode_buffer
import json
import threading
from pathlib import Path
import re
import math
from concurrent.futures import ThreadPoolExecutor, as_completed

class GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD),
                ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD),
                ("Data4", wintypes.BYTE * 8)]

class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD),
                ("pcwszFilePath", wintypes.LPCWSTR),
                ("hFile", wintypes.HANDLE),
                ("pgKnownSubject", ctypes.POINTER(GUID))]

class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD),
                ("pPolicyCallbackData", ctypes.c_void_p),
                ("pSIPClientData", ctypes.c_void_p),
                ("dwUIChoice", wintypes.DWORD),
                ("fdwRevocationChecks", wintypes.DWORD),
                ("dwUnionChoice", wintypes.DWORD),
                ("pFile", ctypes.c_void_p),
                ("dwStateAction", wintypes.DWORD),
                ("hWVTStateData", wintypes.HANDLE),
                ("pwszURLReference", wintypes.LPCWSTR),
                ("dwProvFlags", wintypes.DWORD),
                ("dwUIContext", wintypes.DWORD)]

WTD_UI_NONE = 2
WTD_CHOICE_FILE = 1
WTD_REVOKE_NONE = 0
WTD_STATEACTION_IGNORE = 0
WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID(0xaac56b, 0xcd44, 0x11d0, (0x8c, 0xc2, 0x0, 0xc0, 0x4f, 0xc2, 0x95, 0xee))

wintrust = ctypes.windll.wintrust

class FileScanner:
    def __init__(self):
        self.results = []
        self.is_scanning = False
        self.drive_map = {}
        self.scanned_paths = set()
        self.thread_pool = ThreadPoolExecutor(max_workers=4)
        self._build_drive_mapping()
    
    def _build_drive_mapping(self):
        try:
            self.drive_map = {}
            MAX_PATH = 260
            print("Building drive mapping...")
            for drive in range(ord('A'), ord('Z')+1):
                drive_letter = f"{chr(drive)}:"
                device_path = create_unicode_buffer(MAX_PATH)
                if ctypes.windll.kernel32.QueryDosDeviceW(drive_letter, device_path, MAX_PATH):
                    device_str = device_path.value
                    if device_str:
                        self.drive_map[device_str] = drive_letter
                        print(f"Mapped {device_str} -> {drive_letter}")
            print(f"Drive mapping completed: {len(self.drive_map)} mappings")
        except Exception as e:
            print(f"Error building drive mapping: {e}")
    
    def convert_harddiskvolume_to_drive(self, path):
        if not path:
            return path
        if re.match(r'^[A-Za-z]:\\', path):
            return path
        patterns = [
            r'(\\\\\?\\|\\\\)?Device\\HarddiskVolume(\d+)(\\.*)',
            r'Device\\HarddiskVolume(\d+)(\\.*)',
            r'HarddiskVolume(\d+)(\\.*)'
        ]
        for pattern in patterns:
            match = re.search(pattern, path, re.IGNORECASE)
            if match:
                volume_number = match.group(2) if len(match.groups()) >= 3 else match.group(1)
                remaining_path = match.group(3) if len(match.groups()) >= 3 else match.group(2)
                if not remaining_path:
                    remaining_path = ""
                possible_paths = [
                    f"\\Device\\HarddiskVolume{volume_number}",
                    f"\\\\?\\Device\\HarddiskVolume{volume_number}",
                    f"Device\\HarddiskVolume{volume_number}",
                ]
                for device_path in possible_paths:
                    if device_path in self.drive_map:
                        drive_letter = self.drive_map[device_path]
                        converted_path = f"{drive_letter}\\{remaining_path.lstrip('\\')}"
                        return converted_path
        return path

    def check_file_signature(self, file_path):
        if not file_path or file_path == "N/A" or not os.path.exists(file_path):
            return "deleted"
        if os.path.isdir(file_path):
            return "unsigned"
        try:
            file_info = WINTRUST_FILE_INFO()
            file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
            file_info.pcwszFilePath = file_path
            file_info.hFile = None
            file_info.pgKnownSubject = None
            data = WINTRUST_DATA()
            data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
            data.pPolicyCallbackData = None
            data.pSIPClientData = None
            data.dwUIChoice = WTD_UI_NONE
            data.fdwRevocationChecks = WTD_REVOKE_NONE
            data.dwUnionChoice = WTD_CHOICE_FILE
            data.pFile = ctypes.addressof(file_info)
            data.dwStateAction = WTD_STATEACTION_IGNORE
            data.hWVTStateData = None
            data.pwszURLReference = None
            data.dwProvFlags = 0
            data.dwUIContext = 0
            result_code = wintrust.WinVerifyTrust(
                wintypes.HWND(0),
                ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2),
                ctypes.byref(data)
            )
            if result_code == 0:
                return "valid"
            else:
                return self._check_catalog_signature(file_path)
        except Exception as e:
            return self._check_catalog_signature(file_path)

    def _check_catalog_signature(self, file_path):
        try:
            cryptcatadmin = ctypes.windll.wintrust
            CryptCATAdminAcquireContext2 = cryptcatadmin.CryptCATAdminAcquireContext2
            CryptCATAdminAcquireContext2.argtypes = [wintypes.HANDLE, ctypes.POINTER(GUID), wintypes.LPCWSTR, wintypes.HANDLE, wintypes.DWORD]
            CryptCATAdminAcquireContext2.restype = wintypes.BOOL
            CryptCATAdminReleaseContext = cryptcatadmin.CryptCATAdminReleaseContext
            CryptCATAdminReleaseContext.argtypes = [wintypes.HANDLE, wintypes.DWORD]
            CryptCATAdminReleaseContext.restype = wintypes.BOOL
            CryptCATAdminCalcHashFromFileHandle2 = cryptcatadmin.CryptCATAdminCalcHashFromFileHandle2
            CryptCATAdminCalcHashFromFileHandle2.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p, wintypes.DWORD]
            CryptCATAdminCalcHashFromFileHandle2.restype = wintypes.BOOL
            CryptCATAdminEnumCatalogFromHash = cryptcatadmin.CryptCATAdminEnumCatalogFromHash
            CryptCATAdminEnumCatalogFromHash.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
            CryptCATAdminEnumCatalogFromHash.restype = wintypes.HANDLE
            CryptCATCatalogInfoFromContext = cryptcatadmin.CryptCATCatalogInfoFromContext
            CryptCATCatalogInfoFromContext.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
            CryptCATCatalogInfoFromContext.restype = wintypes.BOOL
            CryptCATAdminReleaseCatalogContext = cryptcatadmin.CryptCATAdminReleaseCatalogContext
            CryptCATAdminReleaseCatalogContext.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.DWORD]
            CryptCATAdminReleaseCatalogContext.restype = wintypes.BOOL
            
            file_handle = ctypes.windll.kernel32.CreateFileW(
                file_path, 
                0x80000000,
                1,
                None, 
                3,
                0, 
                None
            )
            if file_handle == wintypes.HANDLE(-1).value:
                return "unsigned"
            try:
                hCatAdmin = wintypes.HANDLE()
                if not CryptCATAdminAcquireContext2(ctypes.byref(hCatAdmin), None, None, None, 0):
                    return "unsigned"
                try:
                    hash_size = wintypes.DWORD(100)
                    hash_buffer = (ctypes.c_byte * hash_size.value)()
                    if not CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, file_handle, ctypes.byref(hash_size), hash_buffer, 0):
                        return "unsigned"
                    hPrevCat = wintypes.HANDLE()
                    hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash_buffer, hash_size.value, 0, ctypes.byref(hPrevCat))
                    if hCatInfo:
                        catalog_info = ctypes.create_string_buffer(1024)
                        if CryptCATCatalogInfoFromContext(hCatInfo, catalog_info, 1024):
                            CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0)
                            return "valid"
                        else:
                            CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0)
                            return "unsigned"
                    else:
                        return "unsigned"
                finally:
                    CryptCATAdminReleaseContext(hCatAdmin, 0)
            finally:
                ctypes.windll.kernel32.CloseHandle(file_handle)
        except Exception as e:
            return "unsigned"
    
    def get_exe_directory(self):
        if getattr(sys, 'frozen', False):
            return os.path.dirname(sys.executable)
        else:
            return os.path.dirname(os.path.abspath(__file__))
    
    def scan_txt_csv_files(self):
        exe_dir = self.get_exe_directory()
        print(f"Scanning executable directory: {exe_dir}")
        file_paths = []
        found_files = []
        
        # Use os.listdir() instead of Path.glob() for better Windows 10 compatibility
        try:
            # List all files in the directory
            for filename in os.listdir(exe_dir):
                file_lower = filename.lower()
                if file_lower.endswith('.txt') or file_lower.endswith('.csv'):
                    full_path = os.path.join(exe_dir, filename)
                    found_files.append(full_path)
                    print(f"Found file: {filename}")
                    
                    try:
                        # Try multiple encodings to handle different Windows versions
                        encodings = ['utf-8-sig', 'utf-8', 'latin-1', 'cp1252']
                        content = None
                        last_error = None
                        
                        for encoding in encodings:
                            try:
                                with open(full_path, 'r', encoding=encoding, errors='ignore') as f:
                                    content = f.read()
                                    print(f"Successfully read {filename} with encoding: {encoding}")
                                    break
                            except UnicodeDecodeError as e:
                                last_error = e
                                continue
                            except Exception as e:
                                last_error = e
                                continue
                        
                        if content is None:
                            print(f"Could not read {filename}: {last_error}")
                            continue
                            
                        # Extract paths from the content
                        paths = self._extract_paths_from_text(content)
                        file_paths.extend(paths)
                        print(f"Found {len(paths)} paths in {filename}")
                        
                    except Exception as e:
                        print(f"Error reading {filename}: {e}")
                        
        except Exception as e:
            print(f"Error scanning directory {exe_dir}: {e}")
        
        print(f"Total files found: {len(found_files)}")
        print(f"Files scanned: {[os.path.basename(f) for f in found_files]}")
        unique_paths = list(set(file_paths))
        print(f"Total unique paths found: {len(unique_paths)}")
        return unique_paths
    
    def _extract_paths_from_text(self, text):
        paths = []
        pattern = r'(?:\\\\\?\\|\\\\)?(?:\\Device\\HarddiskVolume\d+\\[^[\]<>:"|?*,\n]+\.\w+|[A-Za-z]:\\[^[\]<>:"|?*,\n]+\.\w+|\\\\[^[\]<>:"|?*,\n]+\.\w+)'
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            clean_path = match.strip()
            clean_path = re.sub(r'[.,;:]*$', '', clean_path)
            if len(clean_path) > 10:
                paths.append(clean_path)
        return paths

    def _process_single_file_async(self, converted_path, signature_status, file_index, total_files):
        result = {
            'name': os.path.basename(converted_path) if converted_path != "deleted" else "N/A",
            'path': converted_path,
            'signature': signature_status
        }
        return result, file_index, total_files
    
    def scan_files(self, window):
        self.is_scanning = True
        self.results = []
        self.scanned_paths.clear()
        try:
            window.evaluate_js("clearAllResults();")
            file_paths = self.scan_txt_csv_files()
            print(f"Found {len(file_paths)} unique paths to scan")
            if not file_paths:
                window.evaluate_js("showError('No file paths found in TXT/CSV files in the current directory.');")
                self.is_scanning = False
                return
            total_files = len(file_paths)
            futures = []
            for i, file_path in enumerate(file_paths):
                if not self.is_scanning:
                    break
                print(f"Scanning: {file_path}")
                converted_path = self.convert_harddiskvolume_to_drive(file_path)
                normalized_converted = converted_path.lower()
                if normalized_converted in self.scanned_paths:
                    continue
                self.scanned_paths.add(normalized_converted)
                signature_status = self.check_file_signature(converted_path)
                if signature_status == "directory":
                    continue
                future = self.thread_pool.submit(self._process_single_file_async, converted_path, signature_status, i, total_files)
                futures.append(future)
            completed_count = 0
            for future in as_completed(futures):
                if not self.is_scanning:
                    break
                try:
                    result, file_index, total = future.result(timeout=5)
                    self.results.append(result)
                    completed_count += 1
                    progress = (file_index + 1) / total * 100
                    window.evaluate_js(f"""
                        updateProgress({progress:.1f}, {completed_count}, {total});
                        addResult({json.dumps(result)});
                    """)
                except Exception as e:
                    print(f"Error processing file: {e}")
                    completed_count += 1
        except Exception as e:
            print(f"Scanning error: {e}")
            window.evaluate_js(f"showError('Scanning failed: {str(e)}');")
        finally:
            self.is_scanning = False
            window.evaluate_js("scanComplete();")
    
    def get_results(self):
        return self.results
    
    def stop_scan(self):
        self.is_scanning = False

class Api:
    def __init__(self):
        self.scanner = FileScanner()
    
    def start_scan(self):
        print("API: start_scan called")
        if self.scanner.is_scanning:
            print("API: Scan already in progress")
            return False
        if not webview.windows:
            print("API: No window found")
            return False
        window = webview.windows[0]
        print("API: Starting scan thread")
        thread = threading.Thread(target=self.scanner.scan_files, args=(window,))
        thread.daemon = True
        thread.start()
        return True
    
    def stop_scan(self):
        print("API: stop_scan called")
        self.scanner.stop_scan()
        return True
    
    def get_results(self):
        print("API: get_results called")
        return self.scanner.get_results()
    
    def clear_results(self):
        print("API: clear_results called")
        self.scanner.results = []
        self.scanner.scanned_paths.clear()
        return True
    
    def window_minimize(self):
        print("API: window_minimize called")
        if webview.windows:
            webview.windows[0].minimize()
        return True
    
    def window_maximize(self):
        print("API: window_maximize called")
        if webview.windows:
            window = webview.windows[0]
            window.toggle_fullscreen()
        return True
    
    def window_close(self):
        print("API: window_close called")
        if webview.windows:
            webview.windows[0].destroy()
        return True
    
    def window_move(self, x, y):
        print(f"API: window_move called with {x}, {y}")
        if webview.windows:
            webview.windows[0].move(x, y)
        return True

def get_web_files_path():
    if getattr(sys, 'frozen', False):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
    web_path = os.path.join(base_path, 'web')
    return web_path

def create_fallback_html():
    return """
<!DOCTYPE html>
<html>
<head>
    <title>PathsParser - Error</title>
    <style>
        body { background: #0f172a; color: white; font-family: Arial; margin: 0; padding: 20px; }
        .error { color: #ef4444; background: rgba(239, 68, 68, 0.1); padding: 20px; border-radius: 8px; margin: 20px 0; }
    </style>
</head>
<body>
    <h1>PathsParser - File Analysis</h1>
    <div class="error">
        Error: Web files not found. Please ensure the 'web' folder with UI.html and style.css exists.
    </div>
</body>
</html>
"""

if __name__ == '__main__':
    if getattr(sys, 'frozen', False) and sys.platform == 'win32':
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    api = Api()
    web_path = get_web_files_path()
    ui_html_path = os.path.join(web_path, 'UI.html')
    print(f"Looking for web files in: {web_path}")
    print(f"UI.html exists: {os.path.exists(ui_html_path)}")
    if os.path.exists(ui_html_path):
        try:
            if getattr(sys, 'frozen', False):
                url = f'file:///{ui_html_path}'.replace('\\', '/')
            else:
                url = ui_html_path
            print(f"Loading URL: {url}")
            window = webview.create_window(
                'PathsParser - File Analysis',
                url=url,
                width=1200,
                height=800,
                resizable=True,
                frameless=True,
                easy_drag=False,
                min_size=(800, 600),
                js_api=api
            )
        except Exception as e:
            print(f"Error loading external UI: {e}")
            window = webview.create_window(
                'PathsParser - File Analysis',
                html=create_fallback_html(),
                width=1200,
                height=800,
                resizable=True,
                frameless=True,
                easy_drag=False,
                min_size=(800, 600),
                js_api=api
            )
    else:
        print("Web files not found, using fallback HTML")
        window = webview.create_window(
            'PathsParser - File Analysis',
            html=create_fallback_html(),
            width=1200,
            height=800,
            resizable=True,
            frameless=True,
            easy_drag=False,
            min_size=(800, 600),
            js_api=api
        )
    print("Starting webview...")
    webview.start(debug=False)