Python to Windows EXE Builder

A Windows GUI for turning Python scripts and full Python projects into Windows executable files using PyInstaller or Nuitka.

Version 1.5.11 adds release-grade Authenticode signing that works for ordinary PyInstaller builds as well as protected builds. It supports PFX/P12 files and Windows Certificate Store identities, requires/verifies RFC3161 timestamping by default, and fails the release if signing verification fails. It also retains the v1.5.10 Windows long-command fix.

Features

Build a Single EXE (--onefile) or Application Folder (--onedir)

Select one Python script or an entire Python project folder

Automatic main-script detection for files such as main.py, app.py, *_gui.py, and scripts using if __name__ == "__main__"

Whole-project bundling for multi-file Python applications

AST-based dependency scanning

Automatic requirements.txt installation

Scan and install missing Python imports

Isolated per-project virtual environments

Automatic collection of local Python modules

Automatic detection and bundling of runtime resources such as:

HTML, CSS and JavaScript

JSON, XML, YAML and configuration files

SQLite databases

Images, icons and fonts

DLL, EXE, BAT, PowerShell and other helper files

Manual hidden imports and collect-all package support

Custom application icon support

Automatic Tkinter/Toplevel/dialog icon propagation

Optional UPX support

PyInstaller debug, optimization and advanced argument controls

Automatic cleanup of previous build output

Live build log and diagnostics

Optional production security hardening

Nuitka Native security/build backend

Optional PyArmor + PyInstaller backend

Optional release Authenticode signing (PFX/P12 or Windows Certificate Store)

SHA-256 integrity output and build verification

Sensitive-secret/private-key preflight for protected builds

Optional expiry/device-binding controls when supported by the selected security backend

What's New in v1.5.11

Release Authenticode Signing Fix

Previously, Authenticode signing was coupled to anti-decompile security hardening, so a normal PyInstaller build could remain unsigned even when signing was selected. v1.5.11 makes signing independent and runs it after every successful final EXE build when enabled.

Signing sources:

PFX / P12 certificate file

Windows Certificate Store automatic selection

Windows Certificate Store selection by certificate thumbprint

The builder uses SHA-256 file digests, RFC3161 timestamps, and SignTool verification. The default timestamp URL is DigiCert's public RFC3161 endpoint and can be changed to the service supplied by your certificate authority.

A publicly trusted code-signing certificate is still required for public distribution; the builder cannot create publisher reputation with a self-signed certificate.

Retained from v1.5.10 — Windows Long Command Fix

Large whole-project PyInstaller builds could fail before PyInstaller started with:

WinError 206: The filename or extension is too long

v1.5.10 fixes this by passing the cleaned runtime staging directory to PyInstaller as one recursive --add-data directory instead of generating hundreds of separate command-line arguments.

This is especially useful for projects containing many assets, web files, helper scripts, modules, or other runtime resources.

Requirements

Windows 10 or Windows 11

Python 3 installed and available in PATH

Internet access may be required when installing missing Python packages or build dependencies

For best compatibility, install Python from the official Python website and enable Add Python to PATH during installation.

How to Run the Builder

Method 1 — Recommended

Download or clone this repository.

Extract it if you downloaded the ZIP file.

Open the project folder.

Double-click:

START_PY_TO_EXE_BUILDER.bat

The launcher first tries py -3 and then falls back to python.

Method 2 — Run from Command Prompt

Open Command Prompt inside the project folder and run:

python py_to_exe_gui.py

or:

py -3 py_to_exe_gui.py

Tutorial — Build a Python Project into an EXE

1. Open the Build tab

Start the application and stay on the Build tab.

2. Choose your Python project

For a normal multi-file project, click Choose folder... beside Project folder.

The builder can automatically detect the most likely entry-point script. You can also manually select it using Choose .py....

3. Confirm the main Python script

Check the Main Python script field.

Typical entry points include:

main.py
app.py
gui.py
launcher.py
run.py
start.py

The builder can also detect files containing:

if __name__ == "__main__":

4. Choose the output folder

Select where the finished build will be created.

The default is normally a dist folder inside your project.

5. Enter the application name

Set the name you want for the generated EXE.

Example:

MyApplication

6. Add an application icon — optional

You may select an .ico, .png, .jpg, or .bmp image.

For Tkinter applications, the builder can also propagate the selected icon to the main window, Toplevel windows, taskbar identity, and Tk-owned dialogs.

7. Choose the build type

Choose one of the following:

Single EXE (--onefile)
Creates one executable file. It is easier to distribute, but startup may be slower because files are unpacked at runtime.

Application folder (--onedir)
Creates an executable together with its required files. This is recommended for the first test because it is easier to diagnose missing dependencies or runtime resources.

8. Keep Whole-project mode enabled for multi-file projects

Enable:

Bundle entire project folder (multi-file project)

Auto-detect main script when a folder is selected

Collect all local Python modules when your project uses local modules or dynamic imports

Whole-project mode preserves project-relative folders and can include modules, helper scripts, assets, templates, databases, web files and other runtime resources.

9. Use the recommended dependency options

For most projects, these options are useful:

Clean PyInstaller cache

Use isolated virtual environment

Install requirements.txt automatically

Scan & install missing imports

Auto-bundle referenced support/resource files

Open output folder after success

Enable Show console window when debugging a console application or when you need to see runtime errors.

10. Analyze dependencies

Click:

Analyze Dependencies

Review the detected third-party packages and warnings.

11. Prepare dependencies

Click:

Prepare / Install Dependencies

The builder can create an isolated build environment and install the dependencies required by your project.

12. Add special dependencies if needed

Open the dependency options if your application uses packages that PyInstaller cannot automatically discover.

You can manually add:

Extra pip packages

Hidden imports

collect-all packages

Data files

Data folders

13. Configure Security — optional

Security hardening is optional and should be tested before release.

Available approaches include:

Nuitka Native — free native compilation option

PyArmor + PyInstaller — optional licensed protection workflow

Authenticode release signing (independent of source-protection mode)

SHA-256 verification

Secret/private-key preflight

Expiry/device binding when supported

Start with a compatible or balanced configuration and test the finished application before using stronger settings.

No client-side executable can be made completely impossible to reverse engineer. Security features should be treated as layers of protection, not absolute guarantees.


How to Enable Authenticode Release Signing

Open the Signing tab.

Enable: Sign the final EXE after every successful build.

Choose one certificate source:

PFX / P12 file — select your certificate file and enter its password for the current session.

Windows Certificate Store (auto) — lets SignTool automatically choose a usable code-signing certificate from the selected Windows certificate store.

Windows Certificate Store (thumbprint) — enter the 40-hex-character certificate SHA-1 thumbprint when you want to select one exact certificate. This SHA-1 value is only the certificate identifier; the executable signature itself uses SHA-256.

Leave Require timestamp enabled for public releases. The default RFC3161 service is http://timestamp.digicert.com, or replace it with the timestamp endpoint supplied by your certificate authority.

Build normally. After PyInstaller or Nuitka succeeds, the builder signs the final EXE and runs SignTool verification. If signing or verification fails, the build is treated as failed instead of silently distributing an unsigned release.

The PFX password is not saved to the builder settings file.

14. Build the EXE

Click:

BUILD WINDOWS EXE

Watch the Build Log tab for progress, warnings, dependency installation, compiler output and verification results.

15. Test the finished application

After a successful build:

Open the output folder.

Run the generated EXE.

Test all major features.

Confirm that images, databases, templates, web files and helper executables are present and usable.

Test the application on another Windows PC if you plan to distribute it.

Recommended First Build

For a new project, start with:

Build type: Application folder (--onedir)
Whole-project mode: ON
Use isolated virtual environment: ON
Install requirements.txt automatically: ON
Scan & install missing imports: ON
Auto-bundle resources: ON
Security: OFF for the first compatibility test

Once the application works correctly, try Single EXE and then enable any security features you need.

Troubleshooting

Python was not found

Make sure Python 3 is installed and added to your Windows PATH.

Test with:

python --version

or:

py -3 --version

Missing module after build

Use Analyze Dependencies, add the module under Hidden imports, or use Collect-all packages for packages with dynamic imports or bundled data.

Missing image, HTML, database or resource file

Enable Auto-bundle referenced support/resource files or manually add the required file/folder in the bundled data section.

EXE works on your PC but not another PC

Check the Build Log and confirm that all required runtime files, DLLs, packages and external dependencies were bundled. Test an --onedir build first because it is easier to inspect.

WinError 206 on a large project

Upgrade to v1.5.10 or newer. This version changes whole-project staging so large builds use a much shorter PyInstaller command line.

Important Notes

The builder is designed to run on Windows and create Windows executables.

Always test the generated application before distributing it.

Never embed production API keys, private keys, tokens or sensitive credentials directly in a client-side executable when they can be stored securely on a server instead.

Authenticode signing requires your own valid code-signing certificate and Microsoft SignTool. For public distribution, use a certificate/identity that chains to a Windows-trusted root; self-signed certificates are for development or managed internal environments. Timestamp every public release and keep the same publisher identity across releases when possible.

Some Nuitka or PyArmor features may require additional compilers, tools, packages or licenses.

Project Files

py_to_exe_gui.py                  Main GUI application
START_PY_TO_EXE_BUILDER.bat       Windows launcher
README.txt                         Original project notes
CHANGELOG_v*.txt                   Version history
SECURITY_GUIDE_v*.txt              Security documentation
PATCH_VALIDATION_v*.txt            Patch validation notes

Contributing

Bug reports, compatibility reports and pull requests are welcome.

When reporting a build issue, include:

Windows version

Python version

Builder version

Selected build backend

Build type (onefile or onedir)

Relevant Build Log output

Minimal reproduction steps when possible

Do not include passwords, private keys, API secrets, access tokens or other sensitive information in public issues.

Python to Windows EXE Builder v1.5.11
Build Python applications for Windows with project detection, dependency handling, resource bundling, build diagnostics and optional security hardening.