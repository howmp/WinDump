using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Data;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;

namespace WinDump
{
    class SystemInfo
    {
        internal static DataTable GetDrive()
        {
            var dt =  Utils.Query("SELECT DeviceID,VolumeName,FileSystem,Size,FreeSpace FROM Win32_LogicalDisk");
            foreach (DataRow row in dt.Rows)
            {
                if (!double.TryParse(row["Size"].ToString(), out var size))
                {
                    size = 0;
                }
                if (!double.TryParse(row["FreeSpace"].ToString(), out var free))
                {
                    free = 0;
                }
                row["Size"] = string.Format("{0:0.00}G", (size / (1024.0 * 1024.0 * 1024.0)));
                row["FreeSpace"] = string.Format("{0:0.00}G", (free / (1024.0 * 1024.0 * 1024.0)));
            }
            return dt;
        }
        private static DataTable _cacheApps = null;
        internal static DataTable GetInstalledApp()
        {
            if (_cacheApps != null)
            {
                return _cacheApps;
            }
            // 检查的注册表路径列表（包括32位和64位系统）
            string[] registryPaths = new string[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            };
            var dt = new DataTable();
            dt.Columns.Add("Name");
            dt.Columns.Add("Location");
            dt.Columns.Add("Date");
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
                            string installLocation = subkey?.GetValue("InstallLocation") as string;
                            string date = subkey?.GetValue("InstallDate") as string;
                            if (displayName != null)
                            {
                                dt.Rows.Add(displayName,installLocation,date);
                            }
                        }
                    }
                }
            }
            _cacheApps = dt;
            return _cacheApps;
        }
        internal static DataTable GetInfo()
        {

            
            var dt = new DataTable();
            dt.Columns.Add("Name");
            dt.Columns.Add("Value");
            dt.Rows.Add("OSVersion", GetWindowsOSName());
            dt.Rows.Add("SystemDirectory", Environment.SystemDirectory);
            dt.Rows.Add("MachineName", Environment.MachineName);
            dt.Rows.Add("UserName", Environment.UserName);
            dt.Rows.Add("UserDomainName", Environment.UserDomainName);


            var mem = Memory();
            if ( mem != null)
            {
                dt.Rows.Add("Memory", mem);
            }

            using (RegistryKey processorKey = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\CentralProcessor\0"))
            {
                if (processorKey != null)
                {
                    dt.Rows.Add("CPU", $"{processorKey.GetValue("ProcessorNameString").ToString().Trim()} ({Environment.ProcessorCount} cores)");
                }
            }
            dt.Rows.Add("Proxy", GetSystemProxy());

            dt.Rows.Add("KB", GetKBFix());
            return dt;


        }
        static string GetKBFix()
        {
            ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT HotFixID FROM Win32_QuickFixEngineering");
            var sb = new StringBuilder();
            foreach (ManagementObject obj in searcher.Get())
            {
                sb.AppendLine(obj["HotFixID"].ToString());
            }
            return sb.ToString();
        }
        static string GetWindowsOSName()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT Caption FROM Win32_OperatingSystem"))
                {
                    foreach (ManagementObject os in searcher.Get())
                    {
                        return os["Caption"].ToString();
                    }
                }

            }
            catch 
            {
               
            }
            return "Unknow";

        }
        static string GetSystemProxy()
        {
            using(var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings",false))
            {
                return key.GetValue("ProxyServer", "").ToString();
            }
        }
        static string Memory() {
            MEMORYSTATUSEX memStatus = new MEMORYSTATUSEX();
            if (!GlobalMemoryStatusEx(memStatus))
            {
                return null;
                
            }
            double totalMemoryGB = memStatus.ullTotalPhys / (1024.0 * 1024.0 * 1024.0);
            double availMemoryGB = memStatus.ullAvailPhys / (1024.0 * 1024.0 * 1024.0);
            return string.Format("{0:0.00}G/{1:0.00}G",availMemoryGB,totalMemoryGB);
        }
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool GlobalMemoryStatusEx([In, Out] MEMORYSTATUSEX lpBuffer);
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private class MEMORYSTATUSEX
        {
            public uint dwLength;
            public uint dwMemoryLoad;
            public ulong ullTotalPhys;
            public ulong ullAvailPhys;
            public ulong ullTotalPageFile;
            public ulong ullAvailPageFile;
            public ulong ullTotalVirtual;
            public ulong ullAvailVirtual;
            public ulong ullAvailExtendedVirtual;
            public MEMORYSTATUSEX()
            {
                dwLength = (uint)Marshal.SizeOf(typeof(MEMORYSTATUSEX));
            }
        }
    }
}
