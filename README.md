# PathsParser

![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Security](https://img.shields.io/badge/Security-Tool-red?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-2.0.0-blue?style=for-the-badge)

A modern file path analyzer that scans TXT and CSV files for executable paths and verifies their digital signatures with an enhanced glass-morphism interface.

## 🚀 Features

- **Automated Scanning** - Scans all TXT and CSV files in the current directory for executable paths
- **Signature Verification** - Checks digital signatures of discovered executable files using Windows API
- **Path Conversion** - Converts Device paths (HarddiskVolume) to drive letters automatically
- **Premium UI** - Enhanced glass-morphism interface with smooth animations and real-time progress tracking
- **Smart Filtering** - Advanced search and filter results by file status (unsigned, deleted, valid)
- **Multi-threaded Performance** - Parallel processing with ThreadPoolExecutor for optimal speed
- **Quick Actions** - Right-click or Shift+Click to copy any cell content to clipboard

## 🛡️ Detection Capabilities

| Status Type | Icon | Description |
|-------------|------|-------------|
| **Valid** | 🟢 | File exists and has a valid digital signature |
| **Unsigned** | 🟡 | File exists but lacks a valid digital signature |
| **Deleted** | 🔴 | File path points to a non-existent file |
| **Invalid** | ⚫ | File path cannot be accessed or verified |

## 📦 Installation

### Option 1: Using Pre-built Executable (Recommended)
1. Download the latest `PathsParser.exe` from [Releases](https://github.com/ritzysixx/PathsParser/releases)
2. Place your TXT/CSV files in the same directory
3. Run `PathsParser.exe` - no installation required!

### Option 2: Build from Source
1. **Clone the repository**
   ```bash
   git clone https://github.com/ritzysixx/PathsParser.git
   cd PathsParser
   ```

2. **Install Python dependencies**
   ```bash
   pip install pywebview
   ```

3. **Run directly**
   ```bash
   python PathsParser.py
   ```

### Option 3: Build Executable
```bash
pip install pyinstaller
python -m PyInstaller --onefile --windowed --add-data "web;web" --hidden-import="webview" --hidden-import="webview.platforms.win32" PathsParser.py
```

## 🎯 Usage

### Quick Start
1. **Prepare Files**: Place TXT or CSV files containing file paths in the same directory as PathsParser
2. **Launch**: Run PathsParser.exe
3. **Scan**: Click "Scan TXT/CSV Files" to begin analysis
4. **Review**: View results with color-coded signature status
5. **Filter**: Use search bar and toggle switches to focus on specific results

### Interface Controls
- **Scan TXT/CSV Files** - Start analyzing all text files for executable paths
- **Stop Scan** - Cancel ongoing scan operation
- **Clear Results** - Reset the results grid and start fresh
- **Search Bar** - Filter files by name, path, or signature status in real-time
- **Toggle Filters** - Show only unsigned or deleted files

### Advanced Features
- **Quick Copy**: Right-click or Shift+Click on any cell to copy its content
- **Drag Window**: Click and drag the title bar to move the frameless window
- **Real-time Updates**: Watch progress bars and status updates during scanning

## 🖥️ Interface Preview

The v2.0.0 interface features:
- **Premium Glass Effect** - Advanced backdrop filters and transparency effects
- **Smooth Animations** - Enhanced hover effects and transitions throughout
- **Professional Layout** - Optimized grid system with better spacing and typography
- **Visual Feedback** - Glowing effects and real-time status indicators
- **Custom Controls** - Themed scrollbars and interactive elements

## 🔧 Technical Details

### Backend Architecture
- **Python Core** - Robust backend with Windows API integration
- **pywebview** - Modern web-based UI framework for seamless experience
- **Multi-threading** - Concurrent file processing using ThreadPoolExecutor
- **Windows API** - Direct integration with WinVerifyTrust and catalog signing

### Path Processing
- **Smart Extraction** - Advanced regex patterns to identify file paths in text content
- **Path Conversion** - Automatic conversion from device paths to drive letters
- **Duplicate Removal** - Intelligent filtering of duplicate paths
- **Validation** - Comprehensive path validation and error handling

### Signature Verification
- **Dual Verification** - Primary WinVerifyTrust + fallback catalog checking
- **Error Resilience** - Robust error handling for inaccessible files
- **Performance Optimized** - Efficient checking with minimal system impact

## 📋 System Requirements

- **OS**: Windows 7 or newer
- **Architecture**: x64 or x86
- **RAM**: 2GB minimum (4GB recommended)
- **Storage**: 50MB free space

## 📁 Supported File Formats

- `.txt` files (any text-based format)
- `.csv` files (comma-separated values)
- Log files from various applications
- Output from system utilities and tools
- Custom file lists and reports

### Supported Path Formats
- Standard Windows paths: `C:\Windows\System32\file.exe`
- Device paths: `\Device\HarddiskVolume1\Windows\file.exe`
- UNC paths: `\\Server\Share\file.exe`
- Complex paths with special characters

## 🐛 Reporting Issues

Found a bug or have a feature request? Please [open an issue](https://github.com/ritzysixx/PathsParser/issues) with:
- Detailed description of the problem
- Steps to reproduce
- Screenshots (if applicable)
- Your system specifications

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is designed for legitimate security analysis, digital forensics, and system administration purposes. Users are responsible for complying with local laws and regulations regarding system analysis and file scanning. Use only on systems you own or have explicit permission to test.
