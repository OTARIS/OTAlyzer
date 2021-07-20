using System;
using System.Security.Cryptography;

namespace OTAlyzer.Common
{
    public static class PasswordUtils
    {
        /// <summary>
        /// Generate a password hash as stated in this RFC https://www.ietf.org/rfc/rfc2898.txt
        /// </summary>
        /// <param name="password"></param>
        /// <param name="base64Hash">the hash as base 64 string</param>
        /// <param name="base64Salt">the salt as base 64 string</param>
        /// <param name="salt">leave empty to generate a random salt value</param>
        /// <returns></returns>
        public static bool HashPassword(string password, out string base64Hash, out string base64Salt, byte[] salt = null)
        {
            try
            {
                if (salt == null)
                {
                    new RNGCryptoServiceProvider().GetBytes(salt = new byte[16]);
                }

                Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(password, salt, 10000);
                byte[] hash = pbkdf2.GetBytes(20);

                base64Salt = Convert.ToBase64String(salt);
                base64Hash = Convert.ToBase64String(hash);
                return true;
            }
            catch
            {
                // TODO: Logging
                base64Hash = string.Empty;
                base64Salt = string.Empty;
                return false;
            }
        }
    }
}