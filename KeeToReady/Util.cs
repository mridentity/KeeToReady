﻿using System;

namespace KeeToReady
{
    static class Util
    {
        /// <summary>
        /// Get the unix epoch time since 00:00:00 Jan. 1, 1970 
        /// </summary>
        /// <param name="dateTime">Local time.</param>
        /// <returns>Number of seconds since 00:00:00 Jan. 1, 1970</returns>
        public static double ToUnixEpoch1970(DateTime dateTime)
        {
            var unixTime = dateTime.ToUniversalTime() -
                new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

            return unixTime.TotalSeconds;
        }

        /// <summary>
        /// Get the reference time since 2001
        /// </summary>
        /// <param name="dateTime">Local time</param>
        /// <returns>Number of seconds since 00:00:00 Jan. 1, 2001</returns>
        public static double ToAbsoluteReference2001(DateTime dateTime)
        {
            var unixTime = dateTime.ToUniversalTime() -
                new DateTime(2001, 1, 1, 0, 0, 0, DateTimeKind.Utc);

            return unixTime.TotalSeconds;
        }

        /// <summary>
        /// Get local time from a unix epoch time
        /// </summary>
        /// <param name="unixTimeStamp">Number of seconds since 00:00:00 Jan. 1, 1970></param>
        /// <returns>Local time</returns>
        public static DateTime FromUnixEpochTime(double unixTimeStamp)
        {
            // Unix timestamp is seconds past epoch
            System.DateTime dtDateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Utc);
            dtDateTime = dtDateTime.AddSeconds(unixTimeStamp).ToLocalTime();
            return dtDateTime;
        }

        /// <summary>
        /// Get local time from absolute time reference.
        /// </summary>
        /// <param name="absoluteTime">>Number of seconds since 00:00:00 Jan. 1, 2001</param>
        /// <returns>Local time</returns>
        public static DateTime FromAbsoluteReferenceTime(double absoluteTime)
        {
            // Unix timestamp is seconds past epoch
            System.DateTime dtDateTime = new DateTime(2001, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Utc);
            dtDateTime = dtDateTime.AddSeconds(absoluteTime).ToLocalTime();
            return dtDateTime;
        }


        //http://stackoverflow.com/questions/18648084/rfc2898-pbkdf2-with-sha256-as-digest-in-c-sharp
        // NOTE: The iteration count should
        // be as high as possible without causing
        // unreasonable delay.  Note also that the password
        // and salt are byte arrays, not strings.  After use,
        // the password and salt should be cleared (with Array.Clear)
        public static byte[] PBKDF2Sha256GetBytes(int dklen, byte[] password, byte[] salt, long iterationCount)
        {
            using (var hmac = new System.Security.Cryptography.HMACSHA256(password))
            {
                int hashLength = hmac.HashSize / 8;
                if ((hmac.HashSize & 7) != 0)
                    hashLength++;
                int keyLength = dklen / hashLength;
                if ((long)dklen > (0xFFFFFFFFL * hashLength) || dklen < 0)
                    throw new ArgumentOutOfRangeException("dklen");
                if (dklen % hashLength != 0)
                    keyLength++;
                byte[] extendedkey = new byte[salt.Length + 4];
                Buffer.BlockCopy(salt, 0, extendedkey, 0, salt.Length);
                using (var ms = new System.IO.MemoryStream())
                {
                    for (int i = 0; i < keyLength; i++)
                    {
                        extendedkey[salt.Length] = (byte)(((i + 1) >> 24) & 0xFF);
                        extendedkey[salt.Length + 1] = (byte)(((i + 1) >> 16) & 0xFF);
                        extendedkey[salt.Length + 2] = (byte)(((i + 1) >> 8) & 0xFF);
                        extendedkey[salt.Length + 3] = (byte)(((i + 1)) & 0xFF);
                        byte[] u = hmac.ComputeHash(extendedkey);
                        Array.Clear(extendedkey, salt.Length, 4);
                        byte[] f = u;
                        for (int j = 1; j < iterationCount; j++)
                        {
                            u = hmac.ComputeHash(u);
                            for (int k = 0; k < f.Length; k++)
                            {
                                f[k] ^= u[k];
                            }
                        }
                        ms.Write(f, 0, f.Length);
                        Array.Clear(u, 0, u.Length);
                        Array.Clear(f, 0, f.Length);
                    }
                    byte[] dk = new byte[dklen];
                    ms.Position = 0;
                    ms.Read(dk, 0, dklen);
                    ms.Position = 0;
                    for (long i = 0; i < ms.Length; i++)
                    {
                        ms.WriteByte(0);
                    }
                    Array.Clear(extendedkey, 0, extendedkey.Length);
                    return dk;
                }
            }
        }


    }
}
