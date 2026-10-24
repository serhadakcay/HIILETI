using System;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Media;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;

namespace MSJ
{
    static class Program
    {
        private static Process serverProcess = null;
        private static NotifyIcon trayIcon = null;
        private static string appDir = "";
        private static string browserPath = "";
        private static string profileDir = "";
        private static MenuItem miAutoStart = null;
        private static Control uiSyncControl = null;
        private static IncomingCallPopupForm activeCallPopup = null;
        private static SoundPlayer ringtonePlayer = null;

        [DllImport("user32.dll")]
        private static extern bool SetForegroundWindow(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        [DllImport("user32.dll")]
        private static extern bool IsWindowVisible(IntPtr hWnd);

        private const int SW_RESTORE = 9;
        private static Process lastAppBrowserProcess = null;

        public static bool IsAppWindowVisible()
        {
            try
            {
                if (lastAppBrowserProcess != null && !lastAppBrowserProcess.HasExited)
                {
                    lastAppBrowserProcess.Refresh();
                    if (lastAppBrowserProcess.MainWindowHandle != IntPtr.Zero && IsWindowVisible(lastAppBrowserProcess.MainWindowHandle))
                    {
                        return true;
                    }
                }

                string[] browserNames = new string[] { "msedge", "chrome" };
                foreach (string bName in browserNames)
                {
                    Process[] procs = Process.GetProcessesByName(bName);
                    foreach (Process p in procs)
                    {
                        try
                        {
                            if (p.MainWindowHandle != IntPtr.Zero && IsWindowVisible(p.MainWindowHandle))
                            {
                                string title = p.MainWindowTitle ?? "";
                                if (title.IndexOf("HIHaberle", StringComparison.OrdinalIgnoreCase) >= 0)
                                {
                                    return true;
                                }
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
            return false;
        }

        [STAThread]
        static void Main(string[] args)
        {
            try
            {
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);

                appDir = AppDomain.CurrentDomain.BaseDirectory;
                profileDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "MSJ", "AppData");
                browserPath = FindBrowser();

                bool createdNew;
                using (Mutex mutex = new Mutex(true, "MSJ_Single_Instance_Mutex", out createdNew))
                {
                    if (!createdNew)
                    {
                        EnsureServerRunning();
                        OpenAppWindow();
                        return;
                    }

                    bool isBackground = false;
                    if (args != null)
                    {
                        foreach (string arg in args)
                        {
                            if (arg.Equals("--background", StringComparison.OrdinalIgnoreCase) ||
                                arg.Equals("-b", StringComparison.OrdinalIgnoreCase) ||
                                arg.Equals("--autostart", StringComparison.OrdinalIgnoreCase))
                            {
                                isBackground = true;
                            }
                        }
                    }

                    // UI Thread senkronizasyon kontrolü (arka plan bildirim pencerelerini ekrana düşürmek için)
                    uiSyncControl = new Control();
                    uiSyncControl.CreateControl();

                    // 1. Arka Plan Sunucusunu Başlat
                    EnsureServerRunning();

                    // 2. Program kapalıyken de mesaj/arama gelmesi için Windows Başlangıç kaydını garantiye al
                    EnsureAutoStartShortcut();

                    // 3. Sistem Tepsisi (Tray) İkonunu ve Bildirim Dinleyicisini Başlat
                    SetupTrayIcon();

                    // 4. Normal başlatılmışsa arayüz penceresini aç
                    if (!isBackground)
                    {
                        OpenAppWindow();
                    }

                    // 5. Tepsi uygulamasını arka planda kalıcı çalıştır
                    Application.Run(new ApplicationContext());
                }
            }
            catch (Exception ex)
            {
                try
                {
                    File.WriteAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "launcher_error.log"), ex.ToString());
                }
                catch { }
            }
        }

        static void EnsureServerRunning()
        {
            if (IsServerRunning()) return;

            string nodeExe = Path.Combine(appDir, "node.exe");
            string serverJs = Path.Combine(appDir, "server.js");

            if (!File.Exists(nodeExe))
            {
                nodeExe = "node.exe";
            }

            if (!File.Exists(serverJs))
            {
                return;
            }

            try
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = nodeExe;
                psi.Arguments = "\"" + serverJs + "\"";
                psi.WorkingDirectory = appDir;
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.WindowStyle = ProcessWindowStyle.Hidden;

                serverProcess = Process.Start(psi);
            }
            catch
            {
                return;
            }

            int attempts = 0;
            while (!IsServerRunning() && attempts < 60)
            {
                Thread.Sleep(250);
                attempts++;
            }
        }

        static bool IsServerRunning()
        {
            try
            {
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create("http://127.0.0.1:3000/api/info");
                req.Timeout = 1000;
                req.Method = "GET";
                using (HttpWebResponse res = (HttpWebResponse)req.GetResponse())
                {
                    return res.StatusCode == HttpStatusCode.OK;
                }
            }
            catch
            {
                return false;
            }
        }

        static void CleanStaleBrowserCache()
        {
            try
            {
                string defaultDir = Path.Combine(profileDir, "Default");
                if (!Directory.Exists(defaultDir)) return;

                string[] cacheDirs = new string[]
                {
                    Path.Combine(defaultDir, "Cache"),
                    Path.Combine(defaultDir, "Code Cache"),
                    Path.Combine(defaultDir, "GPUCache"),
                    Path.Combine(defaultDir, "Service Worker", "CacheStorage"),
                    Path.Combine(defaultDir, "Service Worker", "ScriptCache"),
                    Path.Combine(defaultDir, "Service Worker")
                };

                foreach (string d in cacheDirs)
                {
                    try
                    {
                        if (Directory.Exists(d))
                        {
                            Directory.Delete(d, true);
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        public static void OpenAppWindow(string query = "")
        {
            try
            {
                EnsureServerRunning();

                if (!Directory.Exists(profileDir))
                {
                    Directory.CreateDirectory(profileDir);
                }

                CleanStaleBrowserCache();

                string targetUrl = "http://localhost:3000";
                if (!string.IsNullOrEmpty(query))
                {
                    if (!query.StartsWith("?") && !query.StartsWith("/"))
                        targetUrl += "/?" + query;
                    else if (query.StartsWith("?"))
                        targetUrl += "/" + query;
                    else
                        targetUrl += query;
                }

                ProcessStartInfo bPsi = new ProcessStartInfo();
                bPsi.FileName = browserPath;
                // --ignore-certificate-errors kaldırıldı (uyarı çubuğu çıkmaması için)
                bPsi.Arguments = "--app=\"" + targetUrl + "\" --window-size=1280,820 --autoplay-policy=no-user-gesture-required --disable-http-cache --disk-cache-size=1 --user-data-dir=\"" + profileDir + "\"";
                bPsi.UseShellExecute = false;

                Process p = Process.Start(bPsi);
                if (p != null)
                {
                    lastAppBrowserProcess = p;
                    ThreadPool.QueueUserWorkItem(_ =>
                    {
                        try
                        {
                            Thread.Sleep(450);
                            p.Refresh();
                            if (p.MainWindowHandle != IntPtr.Zero)
                            {
                                ShowWindow(p.MainWindowHandle, SW_RESTORE);
                                SetForegroundWindow(p.MainWindowHandle);
                            }
                        }
                        catch { }
                    });
                }
            }
            catch
            {
                try { Process.Start("http://localhost:3000"); } catch { }
            }
        }

        static void SetupTrayIcon()
        {
            trayIcon = new NotifyIcon();
            trayIcon.Text = "HIHaberleşme - Arka Planda Aktif (Mesaj ve Aramalar Açık)";

            string iconPath = Path.Combine(appDir, "app.ico");
            if (File.Exists(iconPath))
            {
                try { trayIcon.Icon = new Icon(iconPath); } catch { trayIcon.Icon = SystemIcons.Application; }
            }
            else
            {
                trayIcon.Icon = SystemIcons.Application;
            }

            ContextMenu contextMenu = new ContextMenu();

            MenuItem miOpen = new MenuItem("💬 HIHaberleşme Uygulamasını Aç", (s, e) => OpenAppWindow());
            miOpen.DefaultItem = true;
            contextMenu.MenuItems.Add(miOpen);

            contextMenu.MenuItems.Add(new MenuItem("🌐 Tarayıcıda Aç", (s, e) => Process.Start("http://localhost:3000")));

            contextMenu.MenuItems.Add("-");

            bool autoStartEnabled = IsAutoStartEnabled();
            miAutoStart = new MenuItem("🚀 Windows ile Birlikte Başlat", (s, e) => ToggleAutoStart());
            miAutoStart.Checked = autoStartEnabled;
            contextMenu.MenuItems.Add(miAutoStart);

            contextMenu.MenuItems.Add("-");

            contextMenu.MenuItems.Add(new MenuItem("❌ Çıkış Yap ve Kapat", (s, e) =>
            {
                if (MessageBox.Show("HIHaberleşme uygulamasından çıkmak istediğinize emin misiniz?\nÇıkış yaparsanız program kapalıyken gelen arama ve mesaj bildirimleri duracaktır.", "HIHaberleşme Çıkış", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
                {
                    ExitApp();
                }
            }));

            trayIcon.ContextMenu = contextMenu;
            trayIcon.Visible = true;

            trayIcon.DoubleClick += (s, e) => OpenAppWindow();
            trayIcon.BalloonTipClicked += (s, e) => OpenAppWindow();

            StartBackgroundNotificationListener();
        }

        private static int lastNotificationId = 0;
        private static Thread notificationThread = null;

        static void StartBackgroundNotificationListener()
        {
            if (notificationThread != null && notificationThread.IsAlive) return;

            notificationThread = new Thread(() =>
            {
                try
                {
                    using (WebClient wc = new WebClient())
                    {
                        wc.Encoding = Encoding.UTF8;
                        string initJson = wc.DownloadString("http://127.0.0.1:3000/api/system/notifications/poll?since=0");
                        var match = Regex.Match(initJson, "\"lastId\"\\s*:\\s*(\\d+)");
                        if (match.Success)
                        {
                            int.TryParse(match.Groups[1].Value, out lastNotificationId);
                        }
                    }
                }
                catch { }

                while (true)
                {
                    try
                    {
                        Thread.Sleep(1000);

                        // Eğer sunucu kapanmışsa otomatik yeniden başlat
                        if (!IsServerRunning())
                        {
                            EnsureServerRunning();
                        }

                        using (WebClient wc = new WebClient())
                        {
                            wc.Encoding = Encoding.UTF8;
                            string url = "http://127.0.0.1:3000/api/system/notifications/poll?since=" + lastNotificationId;
                            string res = wc.DownloadString(url);

                            var lastIdMatch = Regex.Match(res, "\"lastId\"\\s*:\\s*(\\d+)");
                            if (lastIdMatch.Success)
                            {
                                int newLastId = 0;
                                if (int.TryParse(lastIdMatch.Groups[1].Value, out newLastId))
                                {
                                    if (newLastId < lastNotificationId)
                                    {
                                        // Sunucu yeniden başlatılmışsa bildirim sayacını sıfırla
                                        lastNotificationId = 0;
                                    }
                                    else if (newLastId > lastNotificationId)
                                    {
                                        var itemMatches = Regex.Matches(res, "\\{[^\\{\\}]*\"type\"\\s*:\\s*\"([^\"]+)\"[^\\{\\}]*\\}");
                                        foreach (Match im in itemMatches)
                                        {
                                            string block = im.Value;
                                            string type = UnescapeJson(Regex.Match(block, "\"type\"\\s*:\\s*\"([^\"]+)\"").Groups[1].Value);
                                            string sender = UnescapeJson(Regex.Match(block, "\"sender\"\\s*:\\s*\"([^\"]*)\"").Groups[1].Value);
                                            string recipient = UnescapeJson(Regex.Match(block, "\"recipient\"\\s*:\\s*\"([^\"]*)\"").Groups[1].Value);
                                            string text = UnescapeJson(Regex.Match(block, "\"text\"\\s*:\\s*\"([^\"]*)\"").Groups[1].Value);
                                            string callType = UnescapeJson(Regex.Match(block, "\"callType\"\\s*:\\s*\"([^\"]*)\"").Groups[1].Value);
                                            bool isTargetOnline = Regex.Match(block, "\"isTargetOnline\"\\s*:\\s*true").Success;

                                            if (type == "call")
                                            {
                                                HandleIncomingCallEvent(sender, recipient, callType, isTargetOnline);
                                            }
                                            else if (type == "call_ended")
                                            {
                                                HandleCallEndedEvent();
                                            }
                                            else if (type == "message")
                                            {
                                                HandleIncomingMessageEvent(sender, recipient, text, isTargetOnline);
                                            }
                                        }
                                        lastNotificationId = newLastId;
                                    }
                                }
                            }
                        }
                    }
                    catch { }
                }
            });
            notificationThread.IsBackground = true;
            notificationThread.Start();
        }

        static string UnescapeJson(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return s.Replace("\\\"", "\"").Replace("\\\\", "\\").Replace("\\n", " ").Replace("\\r", "");
        }

        static void HandleIncomingMessageEvent(string sender, string recipient, string text, bool isTargetOnline)
        {
            PlayWaveSound("message.wav", false);

            string msgPreview = string.IsNullOrEmpty(text) ? "Yeni bir mesajınız var." : text;

            if (trayIcon != null)
            {
                trayIcon.ShowBalloonTip(6000, "💬 Yeni Mesaj: " + sender, msgPreview, ToolTipIcon.Info);
            }

            // Program penceresi kapalı olsa bile Masaüstü Bildirim Kartını (Hızlı Yanıtlı) ekrana düşür ve pencere kapalıysa otomatik aç
            if (uiSyncControl != null && uiSyncControl.IsHandleCreated)
            {
                uiSyncControl.BeginInvoke(new Action(() =>
                {
                    try
                    {
                        bool appWindowVisible = IsAppWindowVisible();

                        MessagePopupForm popup = new MessagePopupForm(sender, recipient, msgPreview);
                        popup.Show();
                        try
                        {
                            ShowWindow(popup.Handle, SW_RESTORE);
                            SetForegroundWindow(popup.Handle);
                        }
                        catch { }

                        // Yalnızca program penceresi kapalıysa (!appWindowVisible) pencereyi otomatik aç;
                        // pencere zaten açıksa mevcut kullanıcı oturumuna yeni sekme açarak müdahale etme!
                        if (!appWindowVisible)
                        {
                            string q = "?openChat=" + Uri.EscapeDataString(sender);
                            if (!string.IsNullOrEmpty(recipient))
                            {
                                q += "&autoUser=" + Uri.EscapeDataString(recipient);
                            }
                            OpenAppWindow(q);
                        }
                    }
                    catch { }
                }));
            }
        }

        static void HandleIncomingCallEvent(string caller, string recipient, string callType, bool isTargetOnline)
        {
            PlayWaveSound("ringtone.wav", true);

            if (trayIcon != null)
            {
                trayIcon.ShowBalloonTip(10000, "📞 GELEN ARAMA: " + caller, "Aramayı cevaplamak için tıklayın!", ToolTipIcon.Warning);
            }

            // Program kapalı veya kullanıcı Offline olsa bile:
            // 1) Uygulama penceresini otomatik ekrana açıp kullanıcıyı Online yap (bekleyen arama anında ekrana düşer)
            // 2) Ekranın sağ alt/orta kısmında her şeyin üstünde (TopMost) Cevapla / Reddet penceresi göster
            if (uiSyncControl != null && uiSyncControl.IsHandleCreated)
            {
                uiSyncControl.BeginInvoke(new Action(() =>
                {
                    try
                    {
                        bool appWindowVisible = IsAppWindowVisible();
                        if (!appWindowVisible)
                        {
                            string q = "?openChat=" + Uri.EscapeDataString(caller) + "&incomingCall=1";
                            if (!string.IsNullOrEmpty(recipient))
                            {
                                q += "&autoUser=" + Uri.EscapeDataString(recipient);
                            }
                            OpenAppWindow(q);
                        }

                        if (activeCallPopup != null && !activeCallPopup.IsDisposed)
                        {
                            activeCallPopup.Close();
                        }
                        activeCallPopup = new IncomingCallPopupForm(caller, recipient, callType);
                        activeCallPopup.Show();
                        try
                        {
                            ShowWindow(activeCallPopup.Handle, SW_RESTORE);
                            SetForegroundWindow(activeCallPopup.Handle);
                        }
                        catch { }
                    }
                    catch { }
                }));
            }
        }

        public static void HandleCallEndedEvent()
        {
            StopRingtoneSound();
            if (uiSyncControl != null && uiSyncControl.IsHandleCreated)
            {
                uiSyncControl.BeginInvoke(new Action(() =>
                {
                    try
                    {
                        if (activeCallPopup != null && !activeCallPopup.IsDisposed)
                        {
                            activeCallPopup.Close();
                            activeCallPopup = null;
                        }
                    }
                    catch { }
                }));
            }
        }

        public static void PlayWaveSound(string fileName, bool loop)
        {
            try
            {
                string soundPath = Path.Combine(appDir, "public", "sounds", fileName);
                if (File.Exists(soundPath))
                {
                    if (loop)
                    {
                        StopRingtoneSound();
                        ringtonePlayer = new SoundPlayer(soundPath);
                        ringtonePlayer.PlayLooping();
                    }
                    else
                    {
                        using (SoundPlayer sp = new SoundPlayer(soundPath))
                        {
                            sp.Play();
                        }
                    }
                    return;
                }
            }
            catch { }

            try
            {
                if (loop) SystemSounds.Exclamation.Play();
                else SystemSounds.Asterisk.Play();
            }
            catch { }
        }

        public static void StopRingtoneSound()
        {
            try
            {
                if (ringtonePlayer != null)
                {
                    ringtonePlayer.Stop();
                    ringtonePlayer.Dispose();
                    ringtonePlayer = null;
                }
            }
            catch { }
        }

        public static void SendQuickReplyToServer(string sender, string recipient, string replyText)
        {
            if (string.IsNullOrEmpty(replyText)) return;
            ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    using (WebClient wc = new WebClient())
                    {
                        wc.Encoding = Encoding.UTF8;
                        wc.Headers[HttpRequestHeader.ContentType] = "application/json";
                        string safeSender = (sender ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"");
                        string safeRecipient = (recipient ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"");
                        string safeText = replyText.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", "").Replace("\n", " ");
                        string body = "{\"sender\":\"" + safeSender + "\",\"recipient\":\"" + safeRecipient + "\",\"text\":\"" + safeText + "\"}";
                        wc.UploadString("http://127.0.0.1:3000/api/system/quick_reply", "POST", body);
                    }
                }
                catch { }
            });
        }

        public static void RejectPendingCallOnServer(string caller, string recipient)
        {
            ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    using (WebClient wc = new WebClient())
                    {
                        wc.Encoding = Encoding.UTF8;
                        wc.Headers[HttpRequestHeader.ContentType] = "application/json";
                        string body = "{\"caller\":\"" + caller.Replace("\"", "\\\"") + "\",\"recipient\":\"" + recipient.Replace("\"", "\\\"") + "\"}";
                        wc.UploadString("http://127.0.0.1:3000/api/system/call/reject", "POST", body);
                    }
                }
                catch { }
            });
        }

        static void EnsureAutoStartShortcut()
        {
            try
            {
                string startup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
                string lnk = Path.Combine(startup, "HIHaberlesme.lnk");
                if (!File.Exists(lnk))
                {
                    CreateStartupShortcut(lnk);
                }
            }
            catch { }
        }

        static void CreateStartupShortcut(string lnkPath)
        {
            string exePath = Path.Combine(appDir, "MSJ.exe");
            string icoPath = Path.Combine(appDir, "app.ico");
            Type shellType = Type.GetTypeFromProgID("WScript.Shell");
            if (shellType != null)
            {
                dynamic shell = Activator.CreateInstance(shellType);
                dynamic sc = shell.CreateShortcut(lnkPath);
                sc.TargetPath = exePath;
                sc.Arguments = "--background";
                sc.WorkingDirectory = appDir;
                if (File.Exists(icoPath)) sc.IconLocation = icoPath + ",0";
                sc.Description = "HIHaberleşme - Bilgisayar Açılışında Otomatik Başlat";
                sc.Save();
            }
        }

        static bool IsAutoStartEnabled()
        {
            try
            {
                string startup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
                string lnk = Path.Combine(startup, "HIHaberlesme.lnk");
                return File.Exists(lnk);
            }
            catch { return false; }
        }

        static void ToggleAutoStart()
        {
            try
            {
                string startup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
                string lnk = Path.Combine(startup, "HIHaberlesme.lnk");

                if (File.Exists(lnk))
                {
                    File.Delete(lnk);
                    if (miAutoStart != null) miAutoStart.Checked = false;
                    MessageBox.Show("HIHaberleşme başlangıçtan kaldırıldı.", "HIHaberleşme", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                else
                {
                    CreateStartupShortcut(lnk);
                    if (miAutoStart != null) miAutoStart.Checked = true;
                    MessageBox.Show("HIHaberleşme başarıyla Windows başlangıcına eklendi.\nBilgisayarınız her açıldığında arka planda otomatik çalışacaktır.", "HIHaberleşme", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Hata: " + ex.Message, "MSJ", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        static void ExitApp()
        {
            StopRingtoneSound();
            if (trayIcon != null)
            {
                trayIcon.Visible = false;
                trayIcon.Dispose();
            }

            if (serverProcess != null && !serverProcess.HasExited)
            {
                try { serverProcess.Kill(); } catch { }
            }

            try
            {
                Process[] procs = Process.GetProcessesByName("node");
                foreach (Process p in procs)
                {
                    try { p.Kill(); } catch { }
                }
            }
            catch { }

            Application.Exit();
            Environment.Exit(0);
        }

        static string FindBrowser()
        {
            string[] paths = new string[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), @"Microsoft\Edge\Application\msedge.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Microsoft\Edge\Application\msedge.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Google\Chrome\Application\chrome.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), @"Google\Chrome\Application\chrome.exe")
            };

            foreach (string p in paths)
            {
                if (File.Exists(p)) return p;
            }

            return "explorer.exe";
        }
    }

    // =========================================================================
    // PROGRAM KAPALIYKEN EKRANA DÜŞEN MASAÜSTÜ MESAJ BİLDİRİM PENCERESİ (HIZLI YANITLI)
    // =========================================================================
    public class MessagePopupForm : Form
    {
        private System.Windows.Forms.Timer closeTimer;
        private TextBox txtQuickReply;

        public MessagePopupForm(string sender, string recipient, string messageText)
        {
            this.FormBorderStyle = FormBorderStyle.None;
            this.StartPosition = FormStartPosition.Manual;
            this.TopMost = true;
            this.ShowInTaskbar = true;
            this.Text = "💬 " + sender + " - Yeni Mesaj";
            this.BackColor = Color.FromArgb(17, 27, 33);
            this.Size = new Size(410, 185);

            Rectangle workingArea = Screen.PrimaryScreen.WorkingArea;
            this.Location = new Point(workingArea.Right - this.Width - 18, workingArea.Bottom - this.Height - 18);

            Panel accentBar = new Panel();
            accentBar.BackColor = Color.FromArgb(0, 168, 132);
            accentBar.Dock = DockStyle.Left;
            accentBar.Width = 6;
            this.Controls.Add(accentBar);

            Label lblHeader = new Label();
            lblHeader.Text = "💬 YENİ MESAJ • HIHaberleşme";
            lblHeader.ForeColor = Color.FromArgb(0, 217, 165);
            lblHeader.Font = new Font("Segoe UI", 9.5f, FontStyle.Bold);
            lblHeader.Location = new Point(18, 10);
            lblHeader.AutoSize = true;
            this.Controls.Add(lblHeader);

            Button btnClose = new Button();
            btnClose.Text = "✕";
            btnClose.ForeColor = Color.FromArgb(134, 150, 160);
            btnClose.BackColor = Color.Transparent;
            btnClose.FlatStyle = FlatStyle.Flat;
            btnClose.FlatAppearance.BorderSize = 0;
            btnClose.Font = new Font("Segoe UI", 9f, FontStyle.Bold);
            btnClose.Size = new Size(28, 26);
            btnClose.Location = new Point(this.Width - 34, 6);
            btnClose.Cursor = Cursors.Hand;
            btnClose.Click += (s, e) => this.Close();
            this.Controls.Add(btnClose);

            Label lblSender = new Label();
            lblSender.Text = sender;
            lblSender.ForeColor = Color.White;
            lblSender.Font = new Font("Segoe UI", 12.5f, FontStyle.Bold);
            lblSender.Location = new Point(18, 32);
            lblSender.AutoSize = true;
            this.Controls.Add(lblSender);

            Label lblMsg = new Label();
            lblMsg.Text = messageText.Length > 110 ? messageText.Substring(0, 110) + "..." : messageText;
            lblMsg.ForeColor = Color.FromArgb(209, 215, 219);
            lblMsg.Font = new Font("Segoe UI", 10f, FontStyle.Regular);
            lblMsg.Location = new Point(18, 58);
            lblMsg.Size = new Size(375, 42);
            this.Controls.Add(lblMsg);

            string targetQuery = "?openChat=" + Uri.EscapeDataString(sender) + (!string.IsNullOrEmpty(recipient) ? "&autoUser=" + Uri.EscapeDataString(recipient) : "");

            txtQuickReply = new TextBox();
            txtQuickReply.BackColor = Color.FromArgb(32, 44, 51);
            txtQuickReply.ForeColor = Color.White;
            txtQuickReply.BorderStyle = BorderStyle.FixedSingle;
            txtQuickReply.Font = new Font("Segoe UI", 10f, FontStyle.Regular);
            txtQuickReply.Location = new Point(18, 108);
            txtQuickReply.Size = new Size(265, 27);
            txtQuickReply.Enter += (s, e) => { if (closeTimer != null) closeTimer.Stop(); };
            txtQuickReply.TextChanged += (s, e) => { if (closeTimer != null) closeTimer.Stop(); };
            this.Controls.Add(txtQuickReply);

            Button btnSendQuick = new Button();
            btnSendQuick.Text = "Gönder ➤";
            btnSendQuick.BackColor = Color.FromArgb(0, 168, 132);
            btnSendQuick.ForeColor = Color.White;
            btnSendQuick.FlatStyle = FlatStyle.Flat;
            btnSendQuick.FlatAppearance.BorderSize = 0;
            btnSendQuick.Font = new Font("Segoe UI", 9.5f, FontStyle.Bold);
            btnSendQuick.Size = new Size(105, 27);
            btnSendQuick.Location = new Point(290, 108);
            btnSendQuick.Cursor = Cursors.Hand;
            EventHandler sendAction = (s, e) =>
            {
                string reply = txtQuickReply.Text.Trim();
                if (!string.IsNullOrEmpty(reply))
                {
                    // Hızlı yanıtta gönderen=recipient (yerel kullanıcı), alıcı=sender (mesajı atan kişi)
                    Program.SendQuickReplyToServer(recipient, sender, reply);
                    this.Close();
                }
                else
                {
                    Program.OpenAppWindow(targetQuery);
                    this.Close();
                }
            };
            btnSendQuick.Click += sendAction;
            txtQuickReply.KeyDown += (s, e) =>
            {
                if (e.KeyCode == Keys.Enter)
                {
                    e.SuppressKeyPress = true;
                    sendAction(s, e);
                }
            };
            this.Controls.Add(btnSendQuick);

            Button btnOpenChat = new Button();
            btnOpenChat.Text = "💬 Sohbet Ekranını Aç";
            btnOpenChat.BackColor = Color.FromArgb(32, 44, 51);
            btnOpenChat.ForeColor = Color.FromArgb(37, 211, 102);
            btnOpenChat.FlatStyle = FlatStyle.Flat;
            btnOpenChat.FlatAppearance.BorderSize = 1;
            btnOpenChat.FlatAppearance.BorderColor = Color.FromArgb(0, 168, 132);
            btnOpenChat.Font = new Font("Segoe UI", 9f, FontStyle.Bold);
            btnOpenChat.Size = new Size(377, 30);
            btnOpenChat.Location = new Point(18, 143);
            btnOpenChat.Cursor = Cursors.Hand;
            btnOpenChat.Click += (s, e) =>
            {
                Program.OpenAppWindow(targetQuery);
                this.Close();
            };
            this.Controls.Add(btnOpenChat);

            EventHandler openClick = (s, e) =>
            {
                Program.OpenAppWindow(targetQuery);
                this.Close();
            };
            lblSender.Click += openClick;
            lblMsg.Click += openClick;

            closeTimer = new System.Windows.Forms.Timer();
            closeTimer.Interval = 15000;
            closeTimer.Tick += (s, e) =>
            {
                closeTimer.Stop();
                this.Close();
            };
            closeTimer.Start();
        }
    }

    // =========================================================================
    // PROGRAM KAPALI OLSA DA EKRANA GELEN ARAMA PENCERESİ (CEVAPLA / REDDET)
    // =========================================================================
    public class IncomingCallPopupForm : Form
    {
        private System.Windows.Forms.Timer autoCloseTimer;

        public IncomingCallPopupForm(string caller, string recipient, string callType)
        {
            this.FormBorderStyle = FormBorderStyle.None;
            this.StartPosition = FormStartPosition.Manual;
            this.TopMost = true;
            this.ShowInTaskbar = true;
            this.BackColor = Color.FromArgb(14, 24, 30);
            this.Size = new Size(400, 215);

            Rectangle workingArea = Screen.PrimaryScreen.WorkingArea;
            this.Location = new Point(workingArea.Right - this.Width - 20, workingArea.Bottom - this.Height - 20);

            Panel topBar = new Panel();
            topBar.BackColor = Color.FromArgb(37, 211, 102);
            topBar.Dock = DockStyle.Top;
            topBar.Height = 6;
            this.Controls.Add(topBar);

            Label lblBadge = new Label();
            lblBadge.Text = callType == "video" ? "📹 GELEN GÖRÜNTÜLÜ ARAMA" : "📞 GELEN SESLİ ARAMA";
            lblBadge.ForeColor = Color.FromArgb(37, 211, 102);
            lblBadge.Font = new Font("Segoe UI", 10.5f, FontStyle.Bold);
            lblBadge.Location = new Point(22, 18);
            lblBadge.AutoSize = true;
            this.Controls.Add(lblBadge);

            Label lblCaller = new Label();
            lblCaller.Text = caller;
            lblCaller.ForeColor = Color.White;
            lblCaller.Font = new Font("Segoe UI", 18f, FontStyle.Bold);
            lblCaller.Location = new Point(20, 46);
            lblCaller.AutoSize = true;
            this.Controls.Add(lblCaller);

            Label lblSub = new Label();
            lblSub.Text = "Sizi arıyor... Cevaplamak için aşağıdan seçin:";
            lblSub.ForeColor = Color.FromArgb(160, 178, 188);
            lblSub.Font = new Font("Segoe UI", 9.5f, FontStyle.Regular);
            lblSub.Location = new Point(22, 88);
            lblSub.AutoSize = true;
            this.Controls.Add(lblSub);

            Button btnAccept = new Button();
            btnAccept.Text = "📞 CEVAPLA (EVET)";
            btnAccept.BackColor = Color.FromArgb(37, 211, 102);
            btnAccept.ForeColor = Color.White;
            btnAccept.FlatStyle = FlatStyle.Flat;
            btnAccept.FlatAppearance.BorderSize = 0;
            btnAccept.Font = new Font("Segoe UI", 10.5f, FontStyle.Bold);
            btnAccept.Size = new Size(170, 48);
            btnAccept.Location = new Point(22, 138);
            btnAccept.Cursor = Cursors.Hand;
            btnAccept.Click += (s, e) =>
            {
                Program.StopRingtoneSound();
                string acceptQuery = "?openChat=" + Uri.EscapeDataString(caller) + "&autoAcceptCall=1" + (!string.IsNullOrEmpty(recipient) ? "&autoUser=" + Uri.EscapeDataString(recipient) : "");
                Program.OpenAppWindow(acceptQuery);
                this.Close();
            };
            this.Controls.Add(btnAccept);

            Button btnReject = new Button();
            btnReject.Text = "❌ REDDET (HAYIR)";
            btnReject.BackColor = Color.FromArgb(234, 0, 56);
            btnReject.ForeColor = Color.White;
            btnReject.FlatStyle = FlatStyle.Flat;
            btnReject.FlatAppearance.BorderSize = 0;
            btnReject.Font = new Font("Segoe UI", 10.5f, FontStyle.Bold);
            btnReject.Size = new Size(170, 48);
            btnReject.Location = new Point(206, 138);
            btnReject.Cursor = Cursors.Hand;
            btnReject.Click += (s, e) =>
            {
                Program.StopRingtoneSound();
                Program.RejectPendingCallOnServer(caller, recipient);
                this.Close();
            };
            this.Controls.Add(btnReject);

            autoCloseTimer = new System.Windows.Forms.Timer();
            autoCloseTimer.Interval = 42000;
            autoCloseTimer.Tick += (s, e) =>
            {
                autoCloseTimer.Stop();
                Program.StopRingtoneSound();
                this.Close();
            };
            autoCloseTimer.Start();
        }

        protected override void OnFormClosed(FormClosedEventArgs e)
        {
            if (autoCloseTimer != null) autoCloseTimer.Stop();
            base.OnFormClosed(e);
        }
    }
}
