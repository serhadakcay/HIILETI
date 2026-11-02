@echo off
chcp 65001 >nul
title MSJ - Windows Başlangıcına Ekle
echo ==========================================================
echo MSJ Otomatik Başlatma Yapılandırması
echo ==========================================================
echo.
echo Bilgisayarınız her açıldığında MSJ sunucusunun arka planda
echo otomatik olarak başlaması için başlangıç kısayolu oluşturuluyor...
echo.

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$appDir = 'C:\Users\Aile\AppData\Local\Programs\MSJ'; if (!(Test-Path $appDir)) { $appDir = 'c:\Users\Aile\Desktop\MSJ' }; ^
   $exePath = Join-Path $appDir 'MSJ.exe'; ^
   $icoPath = Join-Path $appDir 'app.ico'; ^
   $startup = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Startup); ^
   $shortcutPath = Join-Path $startup 'MSJ.lnk'; ^
   $shell = New-Object -ComObject WScript.Shell; ^
   $shortcut = $shell.CreateShortcut($shortcutPath); ^
   $shortcut.TargetPath = $exePath; ^
   $shortcut.WorkingDirectory = $appDir; ^
   $shortcut.IconLocation = $icoPath + ',0'; ^
   $shortcut.Description = 'MSJ - Bilgisayar Açılışında Otomatik Başlat'; ^
   $shortcut.Save(); ^
   Write-Host 'BAŞARILI: MSJ başlangıç klasörüne eklendi!' -ForegroundColor Green"

echo.
echo ==========================================================
echo Tamamlandı! Artık bilgisayar her açıldığında MSJ otomatik çalışacak.
echo Telefon ve tabletleriniz doğrudan bağlanabilecektir.
echo ==========================================================
pause
