set BASE_PATH=C:\users\WDAGUtilityAccount
goto :start

:download 
echo Downloading %~2...
curl -L "%~1" --output "%TEMP%\%~2"
exit /b 0

:start
call :download "https://update.code.visualstudio.com/latest/win32-x64-user/stable", "vscode.exe"
"%TEMP%\vscode.exe" /verysilent /suppressmsgboxes /MERGETASKS="!runcode,desktopicon,quicklaunchicon,addcontextmenufiles,addcontextmenufolders,addtopath"

call :download "https://www.7-zip.org/a/7z2406-x64.exe", "7zip.msi"
msiexec /i "%TEMP%\7zip.msi" /qn /norestart

call :download "https://corretto.aws/downloads/latest/amazon-corretto-21-x64-windows-jdk.msi", "corretto.msi"
msiexec /i "%TEMP%\corretto.msi" /qn /norestart

call :download "https://sourceforge.net/projects/dosbox/files/latest/download", "dosbox.exe"
"%TEMP%\dosbox.exe" /S

call :download "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.6.8/npp.8.6.8.Installer.x64.exe", "notepad++.exe"
"%TEMP%\notepad++.exe" /S

call :download "https://download.sublimetext.com/sublime_text_build_4169_x64_setup.exe", "sublime.exe"
"%TEMP%\sublime.exe" /VERYSILENT /NORESTART /TASKS="contextentry"

call :download "https://aka.ms/vs/17/release/vc_redist.x64.exe", "vcredist_x64.exe"
"%TEMP%\vcredist_x64.exe"
"%TEMP%\vcredist_x64.exe" /passive /norestart

call :download "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.1_build/ghidra_11.1_PUBLIC_20240607.zip", "ghidra.zip"
"%PROGRAMFILES%\7-Zip\7z.exe" x -aoa "%TEMP%\ghidra.zip" -o"%USERPROFILE%\Desktop\ghidra" 

call :download "https://download.sysinternals.com/files/SysinternalsSuite.zip", "sysinternals.zip"
"%PROGRAMFILES%\7-Zip\7z.exe" x -aoa "%TEMP%\sysinternals.zip" -o"%USERPROFILE%\Desktop\sysinternals"

call :download "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml", "sysmonconfig-export.xml"
"%USERPROFILE%\Desktop\sysinternals\Sysmon64.exe" -accepteula -i "%TEMP%\sysmonconfig-export.xml"

call :download "https://sourceforge.net/projects/x64dbg/files/latest/download", "x64dbg.zip"
"%PROGRAMFILES%\7-Zip\7z.exe" x -aoa "%TEMP%\x64dbg.zip" -o"%USERPROFILE%\Desktop\x64dbg"

call :download "https://github.com/dnSpyEx/dnSpy/releases/latest/download/dnSpy-net-win64.zip", "dnSpy.zip"
"%PROGRAMFILES%\7-Zip\7z.exe" x -aoa "%TEMP%\dnSpy.zip" -o"%USERPROFILE%\Desktop\dnSpy"

call :download "https://github.com/horsicq/DIE-engine/releases/download/3.09/die_win64_portable_3.09_x64.zip", "detectiteasy.zip"
"%PROGRAMFILES%\7-Zip\7z.exe" x -aoa "%TEMP%\detectiteasy.zip" -o"%USERPROFILE%\Desktop\detectiteasy"

call :download "https://github.com/upx/upx/releases/download/v4.2.4/upx-4.2.4-win64.zip", "upx.zip"
"%PROGRAMFILES%\7-Zip\7z.exe" x -aoa "%TEMP%\upx.zip" -o"%USERPROFILE%\Desktop\upx"

call :download "https://github.com/hasherezade/pe-bear/releases/download/v0.6.7.3/PE-bear_0.6.7.3_x64_win_vs19.zip", "pebear.zip"
"%PROGRAMFILES%\7-Zip\7z.exe" x -aoa "%TEMP%\pebear.zip" -o"%USERPROFILE%\Desktop\pebear"

call :download "https://www.winitor.com/tools/pestudio/current/pestudio.zip", "pestudio.zip"
"%PROGRAMFILES%\7-Zip\7z.exe" x -aoa "%TEMP%\pestudio.zip" -o"%USERPROFILE%\Desktop\pestudio"

call :download "https://www.python.org/ftp/python/2.7.18/python-2.7.18.amd64.msi", "python2.msi"
msiexec /i "%TEMP%\python2.msi" /qn /norestart

call :download "https://www.python.org/ftp/python/3.12.4/python-3.12.4-amd64.exe", "python3.exe"
"%TEMP%\python3.exe" /quiet InstallAllUsers=1 PrependPath=1 Include_test=0

call :download "https://mh-nexus.de/downloads/HxDSetup.zip", "hxd.zip"
"%PROGRAMFILES%\7-Zip\7z.exe" x -aoa "%TEMP%\hxd.zip" -o"%TEMP%"
"%TEMP%\HxDSetup.exe" /VERYSILENT /NORESTART 

call :download "https://2.na.dl.wireshark.org/win64/Wireshark-4.2.5-x64.exe", "wireshark.exe"
"%TEMP%\wireshark.exe" /S /desktopicon=yes

call :download "https://npcap.com/dist/npcap-1.79.exe", "npcap.exe"
"%TEMP%\npcap.exe" /loopback_support=yes

rem powershell script block logging
powershell.exe -Command "New-Item -Path HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Force"
powershell.exe -Command "Set-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Name EnableScriptBlockLogging -Value 1 -Force"

exit /B 0
