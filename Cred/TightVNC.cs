using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace WinDump
{
    internal class TightVNC
    {
        internal static DataTable GetTightVNC()
        {
            var dt = new DataTable();
            dt.Columns.Add("Name");
            dt.Columns.Add("Port");
            dt.Columns.Add("Password");
            dt.Columns.Add("ControlPassword");
            dt.Columns.Add("PasswordViewOnly");
            foreach (var root in new RegistryKey[] { Registry.CurrentUser,Registry.LocalMachine })
            {
                try
                {
                    using (var key = root.OpenSubKey(@"SOFTWARE\TightVNC\Server"))
                    {
                        if (key == null)
                        {
                            continue;
                        }
                        var name = root.Name;
                        var port = key.GetValue("RfbPort", 5900).ToString();
                        var pwd = key.GetValue("Password", null);
                        var cpwd = key.GetValue("ControlPassword", null);
                        var vpwd = key.GetValue("PasswordViewOnly", null);
                        dt.Rows.Add(name, port, Decrypt(pwd as byte[]), Decrypt(cpwd as byte[]), Decrypt(vpwd as byte[]));
                    }
                }
                catch  { }

            }
            return dt;
        }
        internal static string Decrypt(byte[] data)
        {
            if(data == null)
            {
                return "";
            }
            var des = new DESCryptoServiceProvider
            {
                Mode = CipherMode.ECB,
                Padding = PaddingMode.Zeros,
                Key = new byte[] { 0xE8, 0x4A, 0xD6, 0x60, 0xC4, 0x72, 0x1A, 0xE0 }
            };
            using (var ms = new MemoryStream(data))
            using (CryptoStream cryptoStream = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Read))
            using (StreamReader streamReader = new StreamReader(cryptoStream, Encoding.UTF8))
            {
                return streamReader.ReadToEnd();
            }
        }
    }
}
