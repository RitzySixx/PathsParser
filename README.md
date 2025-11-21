# PathsParser

![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Security](https://img.shields.io/badge/Security-Tool-red?style=for-the-badge)

A modern file path analyzer that scans TXT and CSV files for executable paths and verifies their digital signatures with a beautiful glass-morphism interface.

## 🚀 Features

- **Automated Scanning** - Scans all TXT and CSV files in the current directory for executable paths
- **Signature Verification** - Checks digital signatures of discovered executable files
- **Path Conversion** - Converts Device paths (HarddiskVolume) to drive letters automatically
- **Modern UI** - Glass-morphism interface with real-time progress tracking
- **Smart Filtering** - Search and filter results by file status (unsigned, deleted, valid)
- **Multi-threaded** - Parallel processing for fast scanning performance

## 🛡️ Detection Capabilities

| Status Type | Description |
|-------------|-------------|
| **Valid** | File exists and has a valid digital signature |
| **Unsigned** | File exists but lacks a valid digital signature |
| **Deleted** | File path points to a non-existent file |
| **Invalid** | File path cannot be accessed or verified |

## 📦 Installation

### Option 1: Using Pre-built Executable
1. Download the latest `PathsParser.exe` from releases
2. Place your TXT/CSV files in the same directory
3. Run `PathsParser.exe`

### Option 2: Build from Source
1. **Clone or download the source files**
   - `PathsParser.py`
   - `style.css` 
   - `UI.html`
   - `paths.ico`

2. **Install Python dependencies**
   ```bash
   pip install pyinstaller pywebview
   ```

3. **Build the executable**
   ```bash
   python -m PyInstaller --onefile --windowed --icon paths.ico --add-data "web;web" --hidden-import="webview" --hidden-import="webview.platforms.win32" PathsParser.py
   ```

## 🎯 Usage

### Preparing Files
1. Place TXT or CSV files containing file paths in the same directory as PathsParser
2. Run the application

### Interface Controls
- **Scan TXT/CSV Files** - Start analyzing all text files for executable paths
- **Stop Scan** - Cancel ongoing scan
- **Clear Results** - Reset the results grid
- **Search** - Filter files by name, path, or signature status
- **Toggle Filters** - Show only unsigned or deleted files

### Quick Actions
- **Click** any cell to select
- **Right-click** or **Shift+Click** to copy cell content to clipboard
- **Drag** the title bar to move the window

## 🖥️ Interface Preview

The application features a modern glass-morphism design with:
- Real-time progress tracking and status updates
- Interactive results grid with file details
- Advanced filtering options for signature status
- Copy-to-clipboard functionality for easy analysis

## 🔧 Technical Details

- **Path Extraction**: Uses regex patterns to identify file paths in text content
- **Signature Verification**: Implements Windows WinVerifyTrust API and catalog signing checks
- **Path Conversion**: Automatically converts Device\HarddiskVolume paths to drive letters
- **Multi-threaded Scanning**: Uses ThreadPoolExecutor for parallel file verification
- **Modern GUI**: Built with pywebview and custom CSS glass-morphism effects

## 📋 Requirements

- **OS**: Windows 7 or newer
- **Python**: 3.7+ (if running from source)
- **Required Packages**: `pywebview`

## 🐛 Reporting Issues

Found a bug or have a feature request? Please [open an issue](https://github.com/ritzysixx/PathsParser/issues).

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is for educational and security research purposes only. Use responsibly and only on systems you own or have permission to test.
