; HorusShield 2.0 — NSIS Installer Script
; Team NullByte · WE School · Alexandria 🇪🇬
; Creates a real Windows installer with:
;   - Desktop shortcut
;   - Start Menu shortcut
;   - Add/Remove Programs entry
;   - Uninstaller

!include "MUI2.nsh"

;─── General ─────────────────────────────────────────────
Name "HorusShield 2.0"
OutFile "HorusShield_Setup.exe"
InstallDir "$PROGRAMFILES64\HorusShield"
InstallDirRegKey HKCU "Software\HorusShield" ""
RequestExecutionLevel admin

;─── UI Settings ─────────────────────────────────────────
!define MUI_ABORTWARNING
!define MUI_ICON "..\icon.ico"
!define MUI_UNICON "..\icon.ico"
!define MUI_WELCOMEPAGE_TITLE "HorusShield 2.0"
!define MUI_WELCOMEPAGE_TEXT "Egyptian AI Cybersecurity Platform$\r$\nTeam NullByte · WE School · Alexandria"
!define MUI_FINISHPAGE_RUN "$INSTDIR\HorusShield.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Launch HorusShield 2.0"
!define MUI_FINISHPAGE_SHOWREADME "$INSTDIR\README.md"
!define MUI_FINISHPAGE_SHOWREADME_TEXT "View README"

;─── Pages ───────────────────────────────────────────────
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\README.md"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

;─── Installer Sections ──────────────────────────────────
Section "HorusShield 2.0" SecMain
    SetOutPath "$INSTDIR"

    ; Copy all files
    File "..\dist\HorusShield.exe"
    File "..\icon.ico"
    File "..\README.md"
    File /r "..\dist\ai"
    File /r "..\dist\database"
    File /r "..\dist\logs"

    ; Write registry for Add/Remove Programs
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\HorusShield" \
        "DisplayName" "HorusShield 2.0"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\HorusShield" \
        "UninstallString" "$INSTDIR\uninstall.exe"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\HorusShield" \
        "DisplayIcon" "$INSTDIR\icon.ico"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\HorusShield" \
        "Publisher" "Team NullByte — WE School"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\HorusShield" \
        "DisplayVersion" "2.0"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\HorusShield" \
        "URLInfoAbout" "https://github.com/NullByte-WESchool/HorusShield"

    ; Desktop Shortcut
    CreateShortcut "$DESKTOP\HorusShield 2.0.lnk" \
        "$INSTDIR\HorusShield.exe" "" "$INSTDIR\icon.ico" 0 \
        SW_SHOWNORMAL "" "Egyptian AI Cybersecurity Platform"

    ; Start Menu
    CreateDirectory "$SMPROGRAMS\HorusShield"
    CreateShortcut "$SMPROGRAMS\HorusShield\HorusShield 2.0.lnk" \
        "$INSTDIR\HorusShield.exe" "" "$INSTDIR\icon.ico"
    CreateShortcut "$SMPROGRAMS\HorusShield\Uninstall.lnk" \
        "$INSTDIR\uninstall.exe"

    ; Write Uninstaller
    WriteUninstaller "$INSTDIR\uninstall.exe"
SectionEnd

;─── Uninstaller ─────────────────────────────────────────
Section "Uninstall"
    Delete "$INSTDIR\HorusShield.exe"
    Delete "$INSTDIR\icon.ico"
    Delete "$INSTDIR\README.md"
    Delete "$INSTDIR\uninstall.exe"
    RMDir /r "$INSTDIR\ai"
    RMDir /r "$INSTDIR\database"
    RMDir /r "$INSTDIR\logs"
    RMDir "$INSTDIR"

    ; Remove Shortcuts
    Delete "$DESKTOP\HorusShield 2.0.lnk"
    Delete "$SMPROGRAMS\HorusShield\HorusShield 2.0.lnk"
    Delete "$SMPROGRAMS\HorusShield\Uninstall.lnk"
    RMDir  "$SMPROGRAMS\HorusShield"

    ; Remove Registry
    DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\HorusShield"
    DeleteRegKey HKCU "Software\HorusShield"
SectionEnd
