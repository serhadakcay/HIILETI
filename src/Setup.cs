using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Threading;
using System.Windows.Forms;
using System.Diagnostics;

namespace MSJInstaller
{
    static class Program
    {
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new InstallerForm());
        }
    }

    public class InstallerForm : Form
    {
        private Panel bannerPanel;
        private Label lblBannerTitle;
        private Label lblBannerSub;
        private Panel contentPanel;
        private Panel bottomPanel;
        private Button btnCancel;
        private Button btnInstall;
        private Button btnBrowse;
        private TextBox txtInstallPath;
        private CheckBox chkDesktopShortcut;
        private CheckBox chkStartMenuShortcut;
        private CheckBox chkStartupShortcut;
        private ProgressBar progressBar;
        private Label lblProgressStatus;
        private CheckBox chkLaunchNow;
        private Label lblDoneTitle;
        private Label lblDoneDesc;

        private int currentStep = 1; // 1: Seçim, 2: Kuruluyor, 3: Bitti
        private string finalInstallPath = "";

        public InstallerForm()
        {
            this.Text = "MSJ Kurulum Sihirbazı";
            this.Size = new Size(580, 440);
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = true;
            this.StartPosition = FormStartPosition.CenterScreen;

            try
            {
                this.Icon = Icon.ExtractAssociatedIcon(Assembly.GetExecutingAssembly().Location);
            }
            catch { }

            InitUI();
        }

        private void InitUI()
        {
            // Banner
            bannerPanel = new Panel();
            bannerPanel.Dock = DockStyle.Top;
            bannerPanel.Height = 75;
            bannerPanel.Paint += (s, e) =>
            {
                using (LinearGradientBrush brush = new LinearGradientBrush(bannerPanel.ClientRectangle,
                    Color.FromArgb(0, 168, 132), Color.FromArgb(18, 140, 126), 45f))
                {
                    e.Graphics.FillRectangle(brush, bannerPanel.ClientRectangle);
                }
            };

            lblBannerTitle = new Label();
            lblBannerTitle.Text = "MSJ Kurulum Sihirbazı";
            lblBannerTitle.Font = new Font("Segoe UI", 13.5f, FontStyle.Bold);
            lblBannerTitle.ForeColor = Color.White;
            lblBannerTitle.Location = new Point(20, 14);
            lblBannerTitle.AutoSize = true;
            lblBannerTitle.BackColor = Color.Transparent;

            lblBannerSub = new Label();
            lblBannerSub.Text = "Windows, Android ve iOS ile uyumlu anlık iletişim ve arama programı";
            lblBannerSub.Font = new Font("Segoe UI", 9f);
            lblBannerSub.ForeColor = Color.FromArgb(235, 255, 250);
            lblBannerSub.Location = new Point(22, 42);
            lblBannerSub.AutoSize = true;
            lblBannerSub.BackColor = Color.Transparent;

            bannerPanel.Controls.Add(lblBannerTitle);
            bannerPanel.Controls.Add(lblBannerSub);
            this.Controls.Add(bannerPanel);

            // Alt Bar
            bottomPanel = new Panel();
            bottomPanel.Dock = DockStyle.Bottom;
            bottomPanel.Height = 55;
            bottomPanel.BackColor = Color.FromArgb(240, 240, 240);
            bottomPanel.Paint += (s, e) =>
            {
                e.Graphics.DrawLine(new Pen(Color.FromArgb(215, 215, 215)), 0, 0, bottomPanel.Width, 0);
            };

            btnCancel = new Button();
            btnCancel.Text = "İptal";
            btnCancel.Size = new Size(85, 30);
            btnCancel.Location = new Point(370, 12);
            btnCancel.Font = new Font("Segoe UI", 9f);
            btnCancel.Click += (s, e) => this.Close();

            btnInstall = new Button();
            btnInstall.Text = "Kur";
            btnInstall.Size = new Size(95, 30);
            btnInstall.Location = new Point(465, 12);
            btnInstall.Font = new Font("Segoe UI", 9f, FontStyle.Bold);
            btnInstall.BackColor = Color.FromArgb(0, 168, 132);
            btnInstall.ForeColor = Color.White;
            btnInstall.FlatStyle = FlatStyle.Flat;
            btnInstall.FlatAppearance.BorderSize = 0;
            btnInstall.Click += BtnAction_Click;

            bottomPanel.Controls.Add(btnCancel);
            bottomPanel.Controls.Add(btnInstall);
            this.Controls.Add(bottomPanel);

            // İçerik Paneli
            contentPanel = new Panel();
            contentPanel.Dock = DockStyle.Fill;
            contentPanel.Padding = new Padding(25, 20, 25, 15);
            contentPanel.BackColor = Color.White;
            this.Controls.Add(contentPanel);

            ShowStep1();
        }

        private void ShowStep1()
        {
            contentPanel.Controls.Clear();
            currentStep = 1;
            btnInstall.Text = "Kur";
            btnCancel.Visible = true;

            Label lblIntro = new Label();
            lblIntro.Text = "MSJ uygulamasını kurmak istediğiniz hedef klasörü seçin:\nKurulum için gerekli tüm bileşenler otomatik olarak yapılandırılacaktır.";
            lblIntro.Font = new Font("Segoe UI", 9.5f);
            lblIntro.Location = new Point(25, 15);
            lblIntro.Size = new Size(520, 40);
            contentPanel.Controls.Add(lblIntro);

            Label lblFolder = new Label();
            lblFolder.Text = "Kurulum Hedef Klasörü:";
            lblFolder.Font = new Font("Segoe UI", 9f, FontStyle.Bold);
            lblFolder.Location = new Point(25, 70);
            lblFolder.AutoSize = true;
            contentPanel.Controls.Add(lblFolder);

            string defaultPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "MSJ");
            txtInstallPath = new TextBox();
            txtInstallPath.Text = defaultPath;
            txtInstallPath.Font = new Font("Segoe UI", 9.5f);
            txtInstallPath.Location = new Point(25, 92);
            txtInstallPath.Size = new Size(410, 28);
            contentPanel.Controls.Add(txtInstallPath);

            btnBrowse = new Button();
            btnBrowse.Text = "Gözat...";
            btnBrowse.Font = new Font("Segoe UI", 9f);
            btnBrowse.Size = new Size(95, 28);
            btnBrowse.Location = new Point(445, 91);
            btnBrowse.Click += (s, e) =>
            {
                using (FolderBrowserDialog fbd = new FolderBrowserDialog())
                {
                    fbd.Description = "MSJ uygulamasının kurulacağı klasörü seçin:";
                    fbd.SelectedPath = txtInstallPath.Text;
                    if (fbd.ShowDialog() == DialogResult.OK)
                    {
                        txtInstallPath.Text = fbd.SelectedPath;
                    }
                }
            };
            contentPanel.Controls.Add(btnBrowse);

            chkDesktopShortcut = new CheckBox();
            chkDesktopShortcut.Text = "Masaüstü kısayolu oluştur (Önerilen)";
            chkDesktopShortcut.Font = new Font("Segoe UI", 9.5f);
            chkDesktopShortcut.Checked = true;
            chkDesktopShortcut.Location = new Point(28, 140);
            chkDesktopShortcut.Size = new Size(400, 25);
            contentPanel.Controls.Add(chkDesktopShortcut);

            chkStartMenuShortcut = new CheckBox();
            chkStartMenuShortcut.Text = "Başlat Menüsüne kısayol oluştur";
            chkStartMenuShortcut.Font = new Font("Segoe UI", 9.5f);
            chkStartMenuShortcut.Checked = true;
            chkStartMenuShortcut.Location = new Point(28, 170);
            chkStartMenuShortcut.Size = new Size(400, 25);
            contentPanel.Controls.Add(chkStartMenuShortcut);

            chkStartupShortcut = new CheckBox();
            chkStartupShortcut.Text = "Bilgisayar açıldığında arka planda otomatik başlat (Önerilen)";
            chkStartupShortcut.Font = new Font("Segoe UI", 9.5f);
            chkStartupShortcut.Checked = true;
            chkStartupShortcut.Location = new Point(28, 200);
            chkStartupShortcut.Size = new Size(450, 25);
            contentPanel.Controls.Add(chkStartupShortcut);
        }

        private void ShowStep2()
        {
            contentPanel.Controls.Clear();
            currentStep = 2;
            btnInstall.Enabled = false;
            btnCancel.Enabled = false;

            Label lblWorking = new Label();
            lblWorking.Text = "MSJ Kuruluyor...";
            lblWorking.Font = new Font("Segoe UI", 12f, FontStyle.Bold);
            lblWorking.ForeColor = Color.FromArgb(18, 140, 126);
            lblWorking.Location = new Point(25, 30);
            lblWorking.AutoSize = true;
            contentPanel.Controls.Add(lblWorking);

            lblProgressStatus = new Label();
            lblProgressStatus.Text = "Bileşenler ve dosyalar çıkartılıyor, lütfen bekleyin...";
            lblProgressStatus.Font = new Font("Segoe UI", 9.5f);
            lblProgressStatus.Location = new Point(27, 70);
            lblProgressStatus.Size = new Size(500, 30);
            contentPanel.Controls.Add(lblProgressStatus);

            progressBar = new ProgressBar();
            progressBar.Style = ProgressBarStyle.Marquee;
            progressBar.MarqueeAnimationSpeed = 30;
            progressBar.Location = new Point(27, 110);
            progressBar.Size = new Size(510, 25);
            contentPanel.Controls.Add(progressBar);
        }

        private void ShowStep3()
        {
            contentPanel.Controls.Clear();
            currentStep = 3;
            btnInstall.Enabled = true;
            btnInstall.Text = "Bitir";
            btnCancel.Visible = false;

            lblDoneTitle = new Label();
            lblDoneTitle.Text = "Tebrikler! Kurulum Başarıyla Tamamlandı.";
            lblDoneTitle.Font = new Font("Segoe UI", 12.5f, FontStyle.Bold);
            lblDoneTitle.ForeColor = Color.FromArgb(0, 168, 132);
            lblDoneTitle.Location = new Point(25, 30);
            lblDoneTitle.AutoSize = true;
            contentPanel.Controls.Add(lblDoneTitle);

            lblDoneDesc = new Label();
            lblDoneDesc.Text = "MSJ masaüstü uygulaması ve gerekli tüm arka plan servisleri hazırlandı.\nArtık uygulamanızı masaüstü simgesinden doğrudan çalıştırabilirsiniz.";
            lblDoneDesc.Font = new Font("Segoe UI", 9.5f);
            lblDoneDesc.Location = new Point(27, 75);
            lblDoneDesc.Size = new Size(510, 50);
            contentPanel.Controls.Add(lblDoneDesc);

            chkLaunchNow = new CheckBox();
            chkLaunchNow.Text = "MSJ uygulamasını şimdi başlat";
            chkLaunchNow.Font = new Font("Segoe UI", 10f, FontStyle.Bold);
            chkLaunchNow.Checked = true;
            chkLaunchNow.Location = new Point(30, 140);
            chkLaunchNow.Size = new Size(400, 30);
            contentPanel.Controls.Add(chkLaunchNow);
        }

        private void BtnAction_Click(object sender, EventArgs e)
        {
            if (currentStep == 1)
            {
                finalInstallPath = txtInstallPath.Text.Trim();
                if (string.IsNullOrEmpty(finalInstallPath))
                {
                    MessageBox.Show("Lütfen geçerli bir kurulum klasörü belirtin.", "MSJ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                ShowStep2();

                // Kurulumu arka planda çalıştır
                Thread installThread = new Thread(DoInstallation);
                installThread.IsBackground = true;
                installThread.Start();
            }
            else if (currentStep == 3)
            {
                if (chkLaunchNow != null && chkLaunchNow.Checked)
                {
                    string targetExe = Path.Combine(finalInstallPath, "MSJ.exe");
                    if (File.Exists(targetExe))
                    {
                        ProcessStartInfo psi = new ProcessStartInfo(targetExe);
                        psi.WorkingDirectory = finalInstallPath;
                        Process.Start(psi);
                    }
                }
                this.Close();
            }
        }

        private void DoInstallation()
        {
            try
            {
                if (!Directory.Exists(finalInstallPath))
                {
                    Directory.CreateDirectory(finalInstallPath);
                }

                // Gömülü zip arşivini oku ve çıkart
                Assembly asm = Assembly.GetExecutingAssembly();
                using (Stream zipStream = asm.GetManifestResourceStream("MSJPackage"))
                {
                    if (zipStream == null)
                    {
                        throw new Exception("Paket kaynağı (MSJPackage) bulunamadı!");
                    }

                    using (ZipArchive archive = new ZipArchive(zipStream))
                    {
                        foreach (ZipArchiveEntry entry in archive.Entries)
                        {
                            string destPath = Path.Combine(finalInstallPath, entry.FullName);
                            if (string.IsNullOrEmpty(entry.Name))
                            {
                                // Klasör
                                Directory.CreateDirectory(destPath);
                            }
                            else
                            {
                                Directory.CreateDirectory(Path.GetDirectoryName(destPath));
                                entry.ExtractToFile(destPath, true);
                            }
                        }
                    }
                }

                string exePath = Path.Combine(finalInstallPath, "MSJ.exe");
                string iconPath = Path.Combine(finalInstallPath, "app.ico");

                // Kısayollar
                if (chkDesktopShortcut.Checked)
                {
                    string desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
                    string lnkPath = Path.Combine(desktop, "MSJ.lnk");
                    CreateShortcut(lnkPath, exePath, finalInstallPath, iconPath);
                }

                if (chkStartMenuShortcut.Checked)
                {
                    string startMenu = Environment.GetFolderPath(Environment.SpecialFolder.StartMenu);
                    string lnkPath = Path.Combine(startMenu, "Programs", "MSJ.lnk");
                    CreateShortcut(lnkPath, exePath, finalInstallPath, iconPath, "");
                }

                if (chkStartupShortcut != null && chkStartupShortcut.Checked)
                {
                    string startup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
                    string lnkPath = Path.Combine(startup, "MSJ.lnk");
                    CreateShortcut(lnkPath, exePath, finalInstallPath, iconPath, "--background");
                }

                // Başarılı bitti
                this.Invoke(new Action(() => ShowStep3()));
            }
            catch (Exception ex)
            {
                this.Invoke(new Action(() =>
                {
                    MessageBox.Show("Kurulum sırasında bir hata oluştu:\n" + ex.Message, "MSJ Hata", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    ShowStep1();
                }));
            }
        }

        private void CreateShortcut(string shortcutPath, string targetPath, string workingDir, string iconPath, string arguments = "")
        {
            try
            {
                Type shellType = Type.GetTypeFromProgID("WScript.Shell");
                if (shellType == null) return;
                dynamic shell = Activator.CreateInstance(shellType);
                dynamic shortcut = shell.CreateShortcut(shortcutPath);
                shortcut.TargetPath = targetPath;
                if (!string.IsNullOrEmpty(arguments))
                {
                    shortcut.Arguments = arguments;
                }
                shortcut.WorkingDirectory = workingDir;
                if (File.Exists(iconPath))
                {
                    shortcut.IconLocation = iconPath + ",0";
                }
                shortcut.Description = "MSJ Güvenli Mesajlaşma ve WebRTC Arama";
                shortcut.Save();
            }
            catch { }
        }
    }
}
