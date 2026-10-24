@echo off
chcp 65001 >nul
:: Yönetici yetkisi kontrolü ve otomatik yükseltme
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Yönetici yetkisi isteniyor...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

title MSJ - Windows Güvenlik Duvarı İzni
echo ==========================================================
echo MSJ Güvenlik Duvarı Port İzinleri (Yönetici Modu)
echo ==========================================================
echo.
echo Telefon ve tabletlerin sorunsuz bağlanabilmesi için 
echo 3000 (HTTP) ve 3443 (HTTPS) portlarına tam izin veriliyor...
echo.

netsh advfirewall firewall delete rule name="MSJ_HTTP_3000" >nul 2>&1
netsh advfirewall firewall add rule name="MSJ_HTTP_3000" dir=in action=allow protocol=TCP localport=3000 profile=any >nul 2>&1

netsh advfirewall firewall delete rule name="MSJ_HTTPS_3443" >nul 2>&1
netsh advfirewall firewall add rule name="MSJ_HTTPS_3443" dir=in action=allow protocol=TCP localport=3443 profile=any >nul 2>&1

echo [BAŞARILI] Port 3000 ve 3443 Güvenlik Duvarında başarıyla açıldı!
echo Artık telefon ve tabletleriniz doğrudan bağlanabilir.
echo ==========================================================
echo.
pause
