using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Data;
using System.Text;

namespace WinDump
{
    internal class RDP
    {
        internal static DataTable GetRDP()
        {
            var dt = new DataTable();
            dt.Columns.Add("Name");
            dt.Columns.Add("Username");
            var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Terminal Server Client\Servers", false);
            if (key == null)
            {
                return dt;
            }
            foreach (var subkeyname in key.GetSubKeyNames())
            {
                using (var subkey = key.OpenSubKey(subkeyname, false))
                {

                    var username = subkey.GetValue("UsernameHint", "");
                    dt.Rows.Add(subkeyname, username);

                }
            }

            return dt;

        }
    }
}
