# Chrome OS Setup Script - WIP

This repository contains a PowerShell script designed to automate the installation and setup of Chrome OS on Windows environments. The script bundles necessary components like Cygwin, `bash`, and `tar` to ensure a smooth and hassle-free installation process for Chrome OS development or testing on Windows.

## Features:
- Automates the installation of Chrome OS components.
- Bundled Cygwin environment with required binaries.
- Configures the environment for Chrome OS development.
- Simple, easy-to-use PowerShell script for Windows users.

## Prerequisites:
- Windows 10 or later.
- PowerShell (pre-installed on Windows).
- A stable internet connection to download necessary files.
- Sufficient storage space for the installation files.

## Installation Instructions:
1. Download the latest release from the [GitHub Releases Page](https://github.com/bobanilic/chromeos-installer/releases).
2. Extract the contents of the release to a folder on your machine.
3. Open PowerShell as Administrator and navigate to the extracted folder.
4. Run the following command to execute the setup script:
   ```powershell
   .\install-chromeos.ps1

### Directory Structure

The following is the directory structure required for the script to work:

```plaintext
C:\
├── cygwin64\               # Default Cygwin installation directory
│   ├── bin\                # Contains required tools
│   │   ├── bash.exe
│   │   ├── dd.exe
│   │   ├── pv.exe
│   │   ├── tar.exe
│   │   └── unzip.exe
├── ChromeOS_Installer\     # Create this directory
│   ├── install.ps1         # The main script
│   └── config\             # Created automatically by script
