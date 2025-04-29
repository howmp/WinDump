using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Text;

namespace WinDump
{
    internal class OpenVPN
    {
        internal static DataTable GetOpenVPN()
        {
            var basePath = Environment.ExpandEnvironmentVariables(@"%USERPROFILE%\OpenVPN");
            if (!Directory.Exists(basePath)) { 
                return null;
            }
            return Directories.DirDump(Path.Combine(basePath,"config"),true,"*.ovpn",SearchOption.AllDirectories);
        }
    }
}
