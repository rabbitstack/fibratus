!define APPNAME "Fibratus"
!define COMPANYNAME "Fibratus"
!define DESCRIPTION "Fibratus is a modern tool for exploration and tracing of the Windows kernel"


# These will be displayed by the "Click here for support information" link in "Add/Remove Programs"
!define HELPURL "https://www.fibratus.io" # "Support Information" link
!define UPDATEURL "https://www.fibratus.io" # "Product Updates" link
!define ABOUTURL "https://www.fibratus.io" # "Publisher" link

RequestExecutionLevel admin ;Require admin rights on NT6+ (When UAC is turned on)

InstallDir "$PROGRAMFILES64\${COMPANYNAME}"
!define UNINSTALLDIR "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME}"
BrandingText " "

# This will be in the installer/uninstaller's title bar
Name "${APPNAME}"
OutFile "fibratus-${VERSION}-amd64.exe"

!include "LogicLib.nsh"
!include "MUI2.nsh"       ; Modern UI

!define MUI_FINISHPAGE_NOAUTOCLOSE
!define MUI_UNFINISHPAGE_NOAUTOCLOSE

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "LICENSE.txt"
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

; Set languages (first is default language)
;!insertmacro MUI_LANGUAGE "English"
!define MUI_LANGDLL_ALLLANGUAGES
;Languages

  !insertmacro MUI_LANGUAGE "English"
  !insertmacro MUI_LANGUAGE "French"
  !insertmacro MUI_LANGUAGE "TradChinese"
  !insertmacro MUI_LANGUAGE "Spanish"
  !insertmacro MUI_LANGUAGE "Hungarian"
  !insertmacro MUI_LANGUAGE "Russian"
  !insertmacro MUI_LANGUAGE "German"
  !insertmacro MUI_LANGUAGE "Dutch"
  !insertmacro MUI_LANGUAGE "SimpChinese"
  !insertmacro MUI_LANGUAGE "Italian"
  !insertmacro MUI_LANGUAGE "Danish"
  !insertmacro MUI_LANGUAGE "Polish"
  !insertmacro MUI_LANGUAGE "Czech"
  !insertmacro MUI_LANGUAGE "Slovenian"
  !insertmacro MUI_LANGUAGE "Slovak"
  !insertmacro MUI_LANGUAGE "Swedish"
  !insertmacro MUI_LANGUAGE "Norwegian"
  !insertmacro MUI_LANGUAGE "PortugueseBR"
  !insertmacro MUI_LANGUAGE "Ukrainian"
  !insertmacro MUI_LANGUAGE "Turkish"
  !insertmacro MUI_LANGUAGE "Catalan"
  !insertmacro MUI_LANGUAGE "Arabic"
  !insertmacro MUI_LANGUAGE "Lithuanian"
  !insertmacro MUI_LANGUAGE "Finnish"
  !insertmacro MUI_LANGUAGE "Greek"
  !insertmacro MUI_LANGUAGE "Korean"
  !insertmacro MUI_LANGUAGE "Hebrew"
  !insertmacro MUI_LANGUAGE "Portuguese"
  !insertmacro MUI_LANGUAGE "Farsi"
  !insertmacro MUI_LANGUAGE "Bulgarian"
  !insertmacro MUI_LANGUAGE "Indonesian"
  !insertmacro MUI_LANGUAGE "Japanese"
  !insertmacro MUI_LANGUAGE "Croatian"
  !insertmacro MUI_LANGUAGE "Serbian"
  !insertmacro MUI_LANGUAGE "Thai"
  !insertmacro MUI_LANGUAGE "NorwegianNynorsk"
  !insertmacro MUI_LANGUAGE "Belarusian"
  !insertmacro MUI_LANGUAGE "Albanian"
  !insertmacro MUI_LANGUAGE "Malay"
  !insertmacro MUI_LANGUAGE "Galician"
  !insertmacro MUI_LANGUAGE "Basque"
  !insertmacro MUI_LANGUAGE "Luxembourgish"
  !insertmacro MUI_LANGUAGE "Afrikaans"
  !insertmacro MUI_LANGUAGE "Uzbek"
  !insertmacro MUI_LANGUAGE "Macedonian"
  !insertmacro MUI_LANGUAGE "Latvian"
  !insertmacro MUI_LANGUAGE "Bosnian"
  !insertmacro MUI_LANGUAGE "Mongolian"
  !insertmacro MUI_LANGUAGE "Estonian"

!insertmacro MUI_RESERVEFILE_LANGDLL

Function .onInit

  !insertmacro MUI_LANGDLL_DISPLAY

FunctionEnd

Section "Install"
	# Files for the install directory
	SetOutPath $INSTDIR

    # Create directories
    CreateDirectory $INSTDIR\Logs

	# Files added here should be removed by the uninstaller
	File /r "release\Bin"
	File /r "release\Config"
	File /r /x .idea /x __pycache__ "release\Filaments"
	File /r "release\Python"

	# Uninstaller - See function un.onInit and section "uninstall" for configuration
	WriteUninstaller "$INSTDIR\uninstall.exe"

	# Registry information for add/remove programs
	WriteRegStr HKLM "${UNINSTALLDIR}" "DisplayName" "${APPNAME} - ${DESCRIPTION}"
	WriteRegStr HKLM "${UNINSTALLDIR}" "UninstallString" "$\"$INSTDIR\uninstall.exe$\""
	WriteRegStr HKLM "${UNINSTALLDIR}" "QuietUninstallString" "$\"$INSTDIR\uninstall.exe$\" /S"
	WriteRegStr HKLM "${UNINSTALLDIR}" "InstallLocation" "$\"$INSTDIR$\""
	WriteRegStr HKLM "${UNINSTALLDIR}" "Publisher" "${COMPANYNAME}"
	WriteRegStr HKLM "${UNINSTALLDIR}" "HelpLink" "$\"${HELPURL}$\""
	WriteRegStr HKLM "${UNINSTALLDIR}" "URLUpdateInfo" "$\"${UPDATEURL}$\""
	WriteRegStr HKLM "${UNINSTALLDIR}" "URLInfoAbout" "$\"${ABOUTURL}$\""
	WriteRegStr HKLM "${UNINSTALLDIR}" "DisplayVersion" "${VERSION}"

    # There is no option for modifying or repairing the install
	WriteRegDWORD HKLM "${UNINSTALLDIR}" "NoModify" 1
	WriteRegDWORD HKLM "${UNINSTALLDIR}" "NoRepair" 1

    # Set the INSTALLSIZE constant (!defined at the top of this script) so Add/Remove Programs can accurately report the size
	WriteRegDWORD HKLM "${UNINSTALLDIR}" "EstimatedSize" ${INSTALLSIZE}

	# Add executable to PATH
	EnVar::SetHKCU
	EnVar::AddValue "Path" "$INSTDIR\Bin\"


SectionEnd

Section "Uninstall"

	# Remove uninstalled executable from PATH
	EnVar::SetHKCU
    EnVar::DeleteValue  "Path" "$INSTDIR\Bin\"

	# Remove files/directories
	RMDir /r /REBOOTOK $INSTDIR\Bin
	RMDir /r /REBOOTOK $INSTDIR\Logs
	RMDir /r /REBOOTOK $INSTDIR\Config
    RMDir /r /REBOOTOK $INSTDIR\Filaments
    RMDir /r /REBOOTOK $INSTDIR\Python

	# Always delete uninstaller as the last action
	Delete /REBOOTOK $INSTDIR\uninstall.exe

	# Try to remove the install directory - this will only happen if it is empty
	RmDir /REBOOTOK $INSTDIR

	# Remove uninstaller information from the registry
	DeleteRegKey HKLM "${UNINSTALLDIR}"

SectionEnd
