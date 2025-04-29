using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Data;
using System.Text;

namespace WinDump
{
    internal class Putty
    {
        internal static DataTable GetPutty()
        {
            var dt = new DataTable();
            dt.Columns.Add("Name");
            dt.Columns.Add("Protocol");
            dt.Columns.Add("HostName");
            dt.Columns.Add("PortNumber");
            dt.Columns.Add("SerialLine");
            var basePath = @"Software\SimonTatham";
            using (var key = Registry.CurrentUser.OpenSubKey(basePath, false))
            {
                if (key == null)
                {
                    return dt;
                }
            }
            using (var key = Registry.CurrentUser.OpenSubKey(basePath+@"\PuTTY\Sessions", false))
            {
                if (key == null) {
                    return dt;
                }
                foreach (var name in key.GetSubKeyNames())
                {
                    using (var subkey = key.OpenSubKey(name)) { 
                    
                        var proto = subkey.GetValue("Protocol","");
                        var host = subkey.GetValue("HostName","");
                        var port = subkey.GetValue("PortNumber","");
                        var seri = subkey.GetValue("SerialLine","");
                        dt.Rows.Add(name,proto,host,port,seri);
                    }
                }
            }
            return dt;
            
        }
    }
}
