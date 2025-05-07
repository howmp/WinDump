using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Management;
using System.Text;
using System.Text.RegularExpressions;

namespace WinDump
{
    internal class Utils
    {
        public const string CIMV2 = "root\\CIMV2";
        public const string StandardCimv2 = "root/StandardCimv2";
        internal delegate  DataTable DtCall();
        internal static string TryToHTML(DtCall call)
        {
            try
            {
                return ToHTML(call());
            }
            catch
            {
                return "";
            }
        }
        internal static string ToHTML(DataTable dt)
        {
            if (dt == null)
            {
                return "";
            }
            StringBuilder html = new StringBuilder(1024*128);

            // 开始表格
            html.Append("<table>\n");

            // 添加表头
            html.Append("<thead>\n <tr>\n");
            foreach (DataColumn column in dt.Columns)
            {
                html.AppendFormat("  <th>{0}</th>\n", column.ColumnName);
            }
            html.Append(" </tr></thead>\n");

            // 添加表体
            html.Append("<tbody>");
            foreach (DataRow row in dt.Rows)
            {
                html.Append(" <tr>\n");
                foreach (DataColumn column in dt.Columns)
                {
                    html.AppendFormat("  <td>{0}</td>\n", row[column].ToString());
                }
                html.Append(" </tr>\n");
            }
            html.Append("</tbody>\n");

            // 结束表格
            html.Append("</table>");
            return html.ToString();
        }
        internal static byte[] FromHex(string hex)
        {
            if (hex == null)
            {
                return null;
            }
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < hex.Length; i += 2)
            {
                string hexByte = hex.Substring(i, 2);
                bytes[i / 2] = Convert.ToByte(hexByte, 16);
            }
            return bytes;
        }

        internal static string ToHex(byte[] bytes)
        {
            StringBuilder hex = new StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes)
            {
                hex.AppendFormat("{0:X2}", b);
            }
            return hex.ToString();
        }
        internal static DataTable Query(string sql, string scope=CIMV2)
        {
            var dataTable = new DataTable();
            var match = Regex.Match(sql, @"SELECT\s+(.*?)\s+FROM", RegexOptions.IgnoreCase);
            if (match.Success)
            {
                var fields = match.Groups[1].Value.Split(',');
                foreach (var field in fields)
                {
                    dataTable.Columns.Add(field.Trim());
                }
            }
            foreach (ManagementObject item in new ManagementObjectSearcher(scope, sql).Get())
            {

                var row = dataTable.NewRow();
                foreach (var f in item.Properties)
                {
                    
                    if (f.Value == null)
                    {
                        row[f.Name] = "";
                    }
                    else if (f.IsArray )
                    {
                        var values = (Array)f.Value;
                        var sb = new StringBuilder();
                        foreach (var v in values) {
                            sb.Append(v.ToString());
                            sb.Append(" ");
                        }
                        row[f.Name] = sb.ToString();
                    }
                    else
                    {
                        row[f.Name] = f.Value;
                    }                    
                }
                dataTable.Rows.Add(row);
            }
            return dataTable;
        }
        public static string GetInstalledAppPath(string appName)
        {
            // 检查的注册表路径列表（包括32位和64位系统）
            string[] registryPaths = new string[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            };

            foreach (var path in registryPaths)
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(path))
                {
                    if (key == null) continue;

                    foreach (string subkeyName in key.GetSubKeyNames())
                    {
                        using (RegistryKey subkey = key.OpenSubKey(subkeyName))
                        {
                            string displayName = subkey?.GetValue("DisplayName") as string;
                            if (displayName?.Contains(appName) == true)
                            {
                                return subkey.GetValue("InstallLocation") as string
                                    ?? subkey.GetValue("UninstallString") as string;
                            }
                        }
                    }
                }
            }
            return null; // 未找到返回null
        }
        internal static string[] GetAppLocation(string name)
        {
            var dt = SystemInfo.GetInstalledApp();
            var locs = new List<string>();
            foreach (DataRow row in dt.Rows)
            {
                if (row["Name"].ToString().Contains(name))
                {
                    var loc = row["Location"] as string;
                    if (!string.IsNullOrEmpty(loc))
                    {
                        locs.Add(loc);
                    }
                    
                    
                }
            }
            return locs.ToArray();
        }

    }

    internal class IniParser
    {
        private Dictionary<string, Dictionary<string, string>> sections =
            new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);

        public IniParser(string filePath)
        {
            Parse(filePath);
        }

        private void Parse(string filePath)
        {
            string currentSection = null;

            foreach (string line in File.ReadAllLines(filePath))
            {
                string trimmedLine = line.Trim();

                // 跳过空行
                if (string.IsNullOrEmpty(trimmedLine))
                    continue;

                // 处理节
                if (trimmedLine.StartsWith("[") && trimmedLine.EndsWith("]"))
                {
                    currentSection = trimmedLine.Substring(1, trimmedLine.Length - 2);
                    if (!sections.ContainsKey(currentSection))
                    {
                        sections[currentSection] = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    }
                    continue;
                }

                // 处理键值对
                int equalsPos = trimmedLine.IndexOf('=');
                if (equalsPos > 0 && currentSection != null)
                {
                    string key = trimmedLine.Substring(0, equalsPos).Trim();
                    string value = trimmedLine.Substring(equalsPos + 1).Trim();
                    sections[currentSection][key] = value;
                }
            }
        }

        public string GetValue(string section, string key)
        {
            if (sections.ContainsKey(section) && sections[section].ContainsKey(key))
            {
                return sections[section][key];
            }
            return null;
        }
    }

}
