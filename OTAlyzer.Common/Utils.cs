using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace OTAlyzer.Common
{
    public static class Utils
    {
        private static readonly uint[] LookupTable = CreateLookupTable();

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string BuildProjectDataPath(string dataDir, string projectNumber, string platformName)
        {
            return Path.Combine(dataDir, projectNumber, platformName.ToUpper());
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string BuildTrafficCaptureName(string platformName, int subjectNumber, int testcaseNumber, string extension)
        {
            return $"{platformName.ToUpper()[0]}{subjectNumber:D2}_{testcaseNumber:D2}{extension}";
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static unsafe string ByteArrayToString(byte[] bytes)
        {
            string str = new string('\0', bytes.Length * 2);

            fixed (byte* pBytes = bytes)
            {
                fixed (char* pStr = str)
                {
                    for (int i = 0; i < bytes.Length; ++i)
                    {
                        ((uint*)pStr)[i] = LookupTable[pBytes[i]];
                    }
                }
            }

            return str;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string Capitalize(string str)
        {
            if (str == null)
            {
                return null;
            }

            if (str.Length > 1)
            {
                return char.ToUpper(str[0]) + str.Substring(1);
            }

            return str.ToUpper();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int CharToHexValue(char hex)
        {
            return hex - (hex < 58 ? 48 : (hex < 97 ? 55 : 87));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static long ExecutionTimeMs(Action action)
        {
            Stopwatch sw = Stopwatch.StartNew();
            action?.Invoke();
            sw.Stop();
            return sw.ElapsedMilliseconds;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string GenerateRandomString(int lenght)
        {
            using RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();

            int bit_count = lenght * 6;
            int byte_count = (bit_count + 7) / 8;
            byte[] bytes = new byte[byte_count];

            rng.GetBytes(bytes);

            return Convert.ToBase64String(bytes);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe static string HexStringToASCII(string hexString)
        {
            if (string.IsNullOrWhiteSpace(hexString))
            {
                return string.Empty;
            }

            int size = hexString.Length / 2;
            byte* bytes = stackalloc byte[size];

            for (int i = 0; i < size; i++)
            {
                // blazing_fast.mp3
                int high = (hexString[i * 2] & 0xf) + ((hexString[i * 2] & 0x40) >> 6) * 9;
                int low = (hexString[i * 2 + 1] & 0xf) + ((hexString[i * 2 + 1] & 0x40) >> 6) * 9;
                bytes[i] = (byte)((high << 4) | low);
            }

            return Encoding.ASCII.GetString(bytes, size);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe static byte[] HexStringToBytes(string hexString)
        {
            if (string.IsNullOrWhiteSpace(hexString))
            {
                return null;
            }

            int size = hexString.Length / 2;
            byte[] bytes = new byte[size];

            for (int i = 0; i < size; i++)
            {
                // blazing_fast.mp3
                int high = (hexString[i * 2] & 0xf) + ((hexString[i * 2] & 0x40) >> 6) * 9;
                int low = (hexString[i * 2 + 1] & 0xf) + ((hexString[i * 2 + 1] & 0x40) >> 6) * 9;
                bytes[i] = (byte)((high << 4) | low);
            }

            return bytes;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string MacAddressToString(byte[] bytes)
        {
            return string.Join(":", bytes.Select(e => e.ToString("X2")));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint[] CreateLookupTable()
        {
            uint[] result = new uint[256];

            for (int i = 0; i < 256; ++i)
            {
                string s = i.ToString("X2");

                if (BitConverter.IsLittleEndian)
                {
                    result[i] = s[0] + ((uint)s[1] << 16);
                }
                else
                {
                    result[i] = s[1] + ((uint)s[0] << 16);
                }
            }

            return result;
        }
    }
}