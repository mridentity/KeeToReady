using KeePass;
using KeePassLib;
using KeePassLib.Cryptography;
using KeePassLib.Cryptography.Cipher;
using KeePassLib.Delegates;
using KeePassLib.Interfaces;
using KeePassLib.Keys;
using KeePassLib.Security;
using KeePassLib.Utility;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Windows.Forms;

namespace KeeToReady
{
    public sealed partial class RsrzFile
    {
        /// <summary>
        /// Save the contents of the current <c>PwDatabase</c> to a RSRZ file.
        /// </summary>
        /// <param name="sSaveTo">Stream to write the KDBX file into.</param>
        /// <param name="pgDataSource">Group containing all groups and
        /// entries to write. If <c>null</c>, the complete database will
        /// be written.</param>
        /// <param name="format">Format of the file to create.</param>
        /// <param name="slLogger">Logger that recieves status information.</param>
        public void Save(Stream sSaveTo, PwGroup pgDataSource, RsrzFormat format, IStatusLogger slLogger)
        {
            Debug.Assert(sSaveTo != null);
            if (sSaveTo == null) throw new ArgumentNullException("sSaveTo");

            m_format = format;
            m_slLogger = slLogger;

            HashingStreamEx hashedStream = new HashingStreamEx(sSaveTo, true, null);

            CryptoRandom cr = CryptoRandom.Instance;

            try
            {
                Stream writerStream;
                if (m_format == RsrzFormat.EncryptedJsonWithoutCompression)
                {
                    var aesEngine = new StandardAesEngine();
                    byte[] magicHeader = Convert.FromBase64String(kBased64MagicString);
                    byte[] salt = cr.GetRandomBytes(kExportSaltLength);
                    Debug.Assert(kMagicHeaderLength == magicHeader.Length);

                    hashedStream.Write(magicHeader, 0, kMagicHeaderLength);  // Prepend the magic header at the beginning of the file.

                    hashedStream.Write(salt, 0, salt.Length);              

                    bool bPassword = m_pwDatabase.MasterKey.ContainsType(typeof(KcpPassword));
                    bool bKeyFile = m_pwDatabase.MasterKey.ContainsType(typeof(KcpKeyFile));

                    if (m_newPasswordBytes != null && m_newPasswordBytes.Length > 0)
                    {
                        m_passwordBytes = m_newPasswordBytes;
                    }
                    else
                    {
                        m_strPassword = (bPassword ? (m_pwDatabase.MasterKey.GetUserKey(typeof(KcpPassword)) as KcpPassword).Password.ReadString() : string.Empty);
                        m_passwordBytes = (bPassword ? (m_pwDatabase.MasterKey.GetUserKey(typeof(KcpPassword)) as KcpPassword).Password.ReadUtf8() : new byte[0]);
                        m_strKeyFile = (bKeyFile ? (m_pwDatabase.MasterKey.GetUserKey(typeof(KcpKeyFile)) as KcpKeyFile).Path : string.Empty);
                    }

                    byte[] aes256Key = Util.PBKDF2Sha256GetBytes(kExportKeyLength, m_passwordBytes, salt, kKeyDerivationRoundForExport);
                    byte[] iv = new byte[kExportIVLength];

                    for (int i = 0; i < kExportIVLength; i++) iv[i] = salt[i];
                    
                    writerStream = aesEngine.EncryptStream(hashedStream, aes256Key, iv);

                    // TODO: wipe clean all memory used thus far.
                }
                else if (m_format == RsrzFormat.CompressedJsonWithoutEncryption)
                {
                    writerStream = new GZipStream(hashedStream, CompressionMode.Compress);
                }
                else { Debug.Assert(false); throw new FormatException("RsrzFormat"); }

                m_jsonWriter = new JsonTextWriter(new StreamWriter(writerStream));

                WriteDocument(pgDataSource);

                m_jsonWriter.Flush();
                m_jsonWriter.Close();
                writerStream.Close();
            }
            finally { CommonCleanUpWrite(sSaveTo, hashedStream); }
        }

        private void CommonCleanUpWrite(Stream sSaveTo, HashingStreamEx hashedStream)
        {
            hashedStream.Close();
            m_pbHashOfFileOnDisk = hashedStream.Hash;

            sSaveTo.Close();

            m_jsonWriter = null;
        }

        private void WriteDocument(PwGroup pgDataSource)
        {
            Debug.Assert(m_jsonWriter != null);
            if (m_jsonWriter == null) throw new InvalidOperationException();

            PwGroup pgRoot = (pgDataSource ?? m_pwDatabase.RootGroup);

            uint uNumGroups, uNumEntries, uCurEntry = 0;
            pgRoot.GetCounts(true, out uNumGroups, out uNumEntries);

            RsoRecord[] records = new RsoRecord[uNumEntries];

            Stack<PwGroup> groupStack = new Stack<PwGroup>();
            groupStack.Push(pgRoot);

            GroupHandler gh = delegate (PwGroup pg)
            {
                Debug.Assert(pg != null);
                if (pg == null) throw new ArgumentNullException("pg");

                while (true)
                {
                    if (pg.ParentGroup == groupStack.Peek())
                    {
                        groupStack.Push(pg);
                        break;
                    }
                    else
                    {
                        groupStack.Pop();
                        if (groupStack.Count <= 0) return false;
                    }
                }

                return true;
            };

            EntryHandler eh = delegate (PwEntry pe)
            {
                Debug.Assert(pe != null);

                RsoRecord r = new RsoRecord();

                // Assign record type
                switch (pe.ParentGroup.Name)
                {
                    case "App":
                    case "Application":
                        r.categoryType = (int)CategoryType.App;
                        break;
                    case "Windows":
                    case "Computer":
                        r.categoryType = (int)CategoryType.Computer;
                        break;
                    case "File":
                        r.categoryType = (int)CategoryType.File;
                        break;
                    case "Network":
                        r.categoryType = (int)CategoryType.Network;
                        break;
                    case "Homebanking":
                    case "Credit Cards":
                        r.categoryType = (int)CategoryType.Card;
                        break;
                    case "Internet":
                    case "Web Logins":
                        r.categoryType = (int)CategoryType.Website;
                        break;
                    case "eMail":
                    case "Email Accts":
                        r.categoryType = (int)CategoryType.Email;
                        break;
                    case "Vehicle Info":
                        r.categoryType = (int)CategoryType.Vehicle;
                        break;
                    case "Identification":
                    case "Identity":
                        r.categoryType = (int)CategoryType.Identity;
                        break;
                    case "General":
                    case "Combinations":
                    case "Serial Numbers":
                    default:
                        r.categoryType = (int)CategoryType.Generic;
                        break;
                }

                // Assign basic record info
                try
                {
                    r.name = pe.Strings.Get("Title").ReadString() ?? pe.Uuid.ToString();
                    var strNotes = pe.Strings.Get("Notes").ReadString();
                    r.desc = strNotes.Substring(0,Math.Min(64,strNotes.Length));
                }
                catch (NullReferenceException)
                {
                    // Swallow exceptions that null.ReadString() may throw. 
                }

                // Assign record logo
                if (pe.CustomIconUuid.Equals(PwUuid.Zero))
                    r.logoImage = null;
                else
                    r.logoImage = ImageToBase64(m_pwDatabase.GetCustomIcon(pe.CustomIconUuid, 100, 100), System.Drawing.Imaging.ImageFormat.Png);

                if (r.logoImage == null)
                {
                    ImageList.ImageCollection icons = Program.MainForm.ClientIcons.Images;
                    Image img = new Bitmap(icons[(int)pe.IconId]);
                    if (img != null)
                    {
                        r.logoImage = ImageToBase64(img, System.Drawing.Imaging.ImageFormat.Png);
                    }
                }

                r.asTempalte = r.isTemplate = 0;
                r.cloudID = null;

                // Record timestamp
                r.lastUpdated = Util.ToAbsoluteReference2001( pe.LastModificationTime);

                // Export record fields
                List<RsoField> fields = new List<RsoField>();

                int order = 0;

                // Assign field type
                foreach (KeyValuePair<string, ProtectedString> ps in pe.Strings)
                {
                    RsoField f = new RsoField();

                    switch (ps.Key)
                    {
                        case "UserName":
                            f.type = (int)FieldType.Username;
                            break;
                        case "Password":
                            f.type = (int)FieldType.Password;
                            break;
                        case "URL":
                            f.type = (int)FieldType.WebsiteURL;
                            break;
                        case "Notes":
                            f.type = (int)FieldType.Note;
                            break;
                        case "Title":   // This is assigned to the record name.
                            continue;
                        default:
                            f.type = (int)FieldType.GenericText;
                            break;
                    }

                    f.displayOrder = order++;
                    f.label = ps.Key;

                    // Protect sensitive field if password is set
                    if (m_format == RsrzFormat.EncryptedJsonWithoutCompression && ps.Value.IsProtected)
                    {
                        f.isSensitive = 1;
                        f.stringValue = ProtectStringWithPassword(m_passwordBytes, ps.Value.ReadUtf8(), kSensitiveProtectionRoundForExport);
                    }
                    else
                    {
                        f.isSensitive = 0;
                        f.stringValue = ps.Value.ReadString();
                    }

                    fields.Add(f);
                }

                // Add fields to record
                r.fields = fields.Count > 0 ? fields.ToArray() : null;

                records[uCurEntry++] = r;

                if (m_slLogger != null)
                    if (!m_slLogger.SetProgress((100 * uCurEntry) / uNumEntries))
                        return false;

                return true;
            };

            if (!pgRoot.TraverseTree(TraversalMethod.PreOrder, gh, eh))
                throw new InvalidOperationException();

            while (groupStack.Count > 1)
            {
                groupStack.Pop();
            }


            //string jsonString = JsonConvert.SerializeObject(records);

            JsonSerializer serializer = JsonSerializer.Create();
            //serializer.Converters.Add(new JavaScriptDateTimeConverter());
            serializer.NullValueHandling = NullValueHandling.Ignore;
            serializer.Formatting = Newtonsoft.Json.Formatting.Indented;

            serializer.Serialize(m_jsonWriter, records);

        }

        // This function is used for protecting the sensitive fields of the records.

        public string ProtectStringWithPassword(byte[] password, byte[] plainText, long interation)
        {
            if (plainText == null || plainText.Length < 1) return null;

            CryptoRandom cr = CryptoRandom.Instance;

            byte[] salt = cr.GetRandomBytes(kKeyXoredSaltLength);

            byte[] xorKey = Util.PBKDF2Sha256GetBytes(plainText.Length, password, salt, interation);

            if (xorKey == null || xorKey.Length < 1) return null;

            byte[] xorred = new byte[xorKey.Length];

            for (int i = 0; i < xorKey.Length; i++)
            {
                if (i < plainText.Length)
                {
                    byte b = plainText[i];
                    b ^=  xorKey[i];
                    xorred[i] = b;
                }
                else
                {
                    byte b = 0;
                    b ^=  xorKey[i];
                    xorred[i] = b;
                }
            }

            return MemUtil.ByteArrayToHexString(salt) + MemUtil.ByteArrayToHexString(xorred);
        }

        //http://www.dailycoding.com/posts/convert_image_to_base64_string_and_base64_string_to_image.aspx
        public string ImageToBase64(Image image, System.Drawing.Imaging.ImageFormat format)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                // Convert Image to byte[]
                image.Save(ms, format);
                byte[] imageBytes = ms.ToArray();

                // Convert byte[] to Base64 String
                string base64String = Convert.ToBase64String(imageBytes);
                return base64String;
            }
        }

        public Image Base64ToImage(string base64String)
        {
            // Convert Base64 String to byte[]
            byte[] imageBytes = Convert.FromBase64String(base64String);
            MemoryStream ms = new MemoryStream(imageBytes, 0,
              imageBytes.Length);

            // Convert byte[] to Image
            ms.Write(imageBytes, 0, imageBytes.Length);
            Image image = Image.FromStream(ms, true);
            return image;
        }

    }
}
