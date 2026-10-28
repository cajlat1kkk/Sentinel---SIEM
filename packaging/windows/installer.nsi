Unicode true
!include "MUI2.nsh"
!ifndef APPDIR
  !error "Define APPDIR as the absolute portable bundle path"
!endif
!ifndef OUTPUT
  !error "Define OUTPUT as the installer output filename"
!endif
!ifndef UNINSTALL_LIST
  !error "Define UNINSTALL_LIST as the generated list of owned installation files"
!endif
Name "Sentinel SIEM"
OutFile "${OUTPUT}"
InstallDir "$LOCALAPPDATA\Programs\Sentinel SIEM"
InstallDirRegKey HKCU "Software\Sentinel\Installer" "InstallDir"
RequestExecutionLevel user
SetCompressor /SOLID lzma
ShowInstDetails show
ShowUninstDetails show
!define MUI_ABORTWARNING
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_RUN "$INSTDIR\sentinel-siem.exe"
!define MUI_FINISHPAGE_RUN_NOTCHECKED
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "Russian"
!insertmacro MUI_LANGUAGE "English"
Section "Sentinel SIEM" SecMain
  SetRegView 64
  SetOutPath "$INSTDIR"
  File /r "${APPDIR}\*"
  WriteUninstaller "$INSTDIR\uninstall.exe"
  CreateDirectory "$SMPROGRAMS\Sentinel SIEM"
  CreateShortcut "$SMPROGRAMS\Sentinel SIEM\Sentinel SIEM.lnk" "$INSTDIR\sentinel-siem.exe"
  CreateShortcut "$SMPROGRAMS\Sentinel SIEM\Demo.lnk" "$INSTDIR\sentinel-siem.exe" "--demo"
  CreateShortcut "$SMPROGRAMS\Sentinel SIEM\Uninstall.lnk" "$INSTDIR\uninstall.exe"
  WriteRegStr HKCU "Software\Sentinel\Installer" "InstallDir" "$INSTDIR"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelSIEM" "DisplayName" "Sentinel SIEM"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelSIEM" "DisplayVersion" "0.2.0"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelSIEM" "Publisher" "Sentinel SIEM"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelSIEM" "DisplayIcon" "$INSTDIR\sentinel-siem.exe"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelSIEM" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelSIEM" "NoModify" 1
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelSIEM" "NoRepair" 1
SectionEnd
Section "Uninstall"
  SetRegView 64
  Delete "$SMPROGRAMS\Sentinel SIEM\Sentinel SIEM.lnk"
  Delete "$SMPROGRAMS\Sentinel SIEM\Demo.lnk"
  Delete "$SMPROGRAMS\Sentinel SIEM\Uninstall.lnk"
  RMDir "$SMPROGRAMS\Sentinel SIEM"
  !include "${UNINSTALL_LIST}"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelSIEM"
  DeleteRegKey HKCU "Software\Sentinel\Installer"
SectionEnd
