using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace WinDump
{
    internal class Files
    {
        internal static string DumpFile(string file,out bool ok)
        {
            try
            {
                var data = File.ReadAllText(Environment.ExpandEnvironmentVariables(file));
                ok = true;
                return data;
            }
            catch (Exception e)
            {
                ok = false;
                return e.Message;
            }
        }
        internal static string Hosts()
        {
            return DumpFile(@"%windir%\system32\drivers\etc\hosts", out var _);
        }
        internal static string IIS()
        {
            // >=IIS7
            var iis7 = DumpFile(@"%windir%\system32\inetsrv\config\ApplicationHost.config", out var ok);
            if (ok) return iis7;
            // IIS6
            var iis6 = DumpFile(@"%windir%\system32\inetsrv\MetaBase.xml", out ok);
            if (ok)
            {
                return iis6;
            }
            else
            {
                return iis7 + "\n" + iis6;
            }
        }
        internal static string Powershell() {
            return DumpFile(@"%appdata%\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt", out var _);
        }
    }
}
