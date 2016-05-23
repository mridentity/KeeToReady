using KeePass;
using KeePass.UI;
using KeePassLib;
using KeePassLib.Collections;
using KeePassLib.Cryptography;
using KeePassLib.Cryptography.Cipher;
using KeePassLib.Delegates;
using KeePassLib.Interfaces;
using KeePassLib.Keys;
using KeePassLib.Security;
using KeePassLib.Utility;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Xml;

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

            UTF8Encoding encNoBom = StrUtil.Utf8;
            CryptoRandom cr = CryptoRandom.Instance;

            try
            {
                Stream writerStream;
                if (m_format == RsrzFormat.EncryptedJsonWithoutCompression)
                {
                    var aesEngine = new StandardAesEngine();
                    byte[] salt = cr.GetRandomBytes(kKeyXorredSaltLength);

                    hashedStream.Write(salt, 0, salt.Length);               // Prepend the salt at the beginning of the file.

                    bool bPassword = m_pwDatabase.MasterKey.ContainsType(typeof(KcpPassword));
                    bool bKeyFile = m_pwDatabase.MasterKey.ContainsType(typeof(KcpKeyFile));

                    string strPassword = (bPassword ? (m_pwDatabase.MasterKey.GetUserKey(typeof(KcpPassword)) as KcpPassword).Password.ReadString() : string.Empty);
                    byte[] passwordBytes = (bPassword ? (m_pwDatabase.MasterKey.GetUserKey(typeof(KcpPassword)) as KcpPassword).Password.ReadUtf8() : new byte[0]);
                    string strKeyFile = (bKeyFile ? (m_pwDatabase.MasterKey.GetUserKey(typeof(KcpKeyFile)) as KcpKeyFile).Path : string.Empty);

                    byte[] aes256Key = Util.PBKDF2Sha256GetBytes(kExportKeyLength, passwordBytes, salt, kKeyDerivationRoundForExport);
                    
                    writerStream = aesEngine.EncryptStream(hashedStream, aes256Key, salt.Take(kExportIVLength).ToArray());      
                    
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

                switch (pe.ParentGroup.Name)
                {
                    case "Windows":
                        r.categoryType = (int)CategoryType.Computer;
                        break;
                    case "Network":
                        r.categoryType = (int)CategoryType.Network;
                        break;
                    case "Homebanking":
                    case "Internet":
                        r.categoryType = (int)CategoryType.Website;
                        break;
                    case "eMail":
                        r.categoryType = (int)CategoryType.Email;
                        break;
                    case "General":
                    default:
                        r.categoryType = (int)CategoryType.Generic;
                        break;
                }

                try
                {
                    r.name = pe.Strings.Get("Title").ReadString() ?? pe.Uuid.ToString();
                    r.desc = pe.Strings.Get("Notes").ReadString();
                }
                catch (NullReferenceException)
                {
                    // Swallow exceptions that null.ReadString() may throw. 
                }

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

                r.lastUpdated = pe.LastModificationTime.GetAbsoluteReference2001();

                List<RsoField> fields = new List<RsoField>();

                int order = 0;

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
                    f.stringValue = ps.Value.ReadString();
                    f.label = ps.Key;
                    if (m_format == RsrzFormat.EncryptedJsonWithoutCompression && ps.Value.IsProtected)
                    {
                        f.isSensitive = 1;
                        // TODO: need to mark sensitive and protect the field.
                    }
                    else 
                        f.isSensitive = 0;   

                    fields.Add(f);
                }

                r.fields = fields.Count() > 0 ? fields.ToArray() : null;

                records[uCurEntry] = r;

                ++uCurEntry;

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


            string jsonString = JsonConvert.SerializeObject(records);

            JsonSerializer serializer = JsonSerializer.Create();
            //serializer.Converters.Add(new JavaScriptDateTimeConverter());
            serializer.NullValueHandling = NullValueHandling.Ignore;
            serializer.Formatting = Newtonsoft.Json.Formatting.Indented;

            serializer.Serialize(m_jsonWriter, records);

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
