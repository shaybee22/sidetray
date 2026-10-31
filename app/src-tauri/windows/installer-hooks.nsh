; Side Tray: extra steps for the Tauri NSIS installer (per-user install, no admin).
;
; Tauri's installer already registers sidetray:// links against the installed
; exe and gives the Start menu and desktop shortcuts our AppUserModelID
; (org.sidetray.app). Here: the name and icon Windows shows on toasts for that
; id, so notifications look right even before the Start menu has indexed the
; shortcut. Uninstalling removes them again; the user's data
; (%APPDATA%\org.sidetray.app) stays unless they tick "Delete the application data".

!macro NSIS_HOOK_POSTINSTALL
  WriteRegStr HKCU "Software\Classes\AppUserModelId\${BUNDLEID}" "DisplayName" "${PRODUCTNAME}"
  WriteRegStr HKCU "Software\Classes\AppUserModelId\${BUNDLEID}" "IconUri" "$INSTDIR\notification-icon.png"
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  ${If} $UpdateMode <> 1
    DeleteRegKey HKCU "Software\Classes\AppUserModelId\${BUNDLEID}"
  ${EndIf}
!macroend
