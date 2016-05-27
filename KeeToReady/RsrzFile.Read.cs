using KeePass;
using KeePass.Forms;
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
        public void Read(PwDatabase pwStorage, Stream sInput, IStatusLogger slLogger)
        {
            Debug.Assert(sInput != null);
            if (sInput == null) throw new ArgumentException("sInput");

            byte[] magicHeader = new byte[kMagicHeaderLength];
            int ret = sInput.Read(magicHeader, 0, kMagicHeaderLength);

            Debug.Assert(kMagicHeaderLength == ret);
            if (ret != kMagicHeaderLength) return;

            try
            {
                string strHeader = Convert.ToBase64String(magicHeader);
                if (strHeader == kBased64MagicString)
                    m_format = RsrzFormat.EncryptedJsonWithoutCompression;
                else
                    m_format = RsrzFormat.CompressedJsonWithoutEncryption;
            }
            catch
            {
                m_format = RsrzFormat.CompressedJsonWithoutEncryption;
            }


            m_slLogger = slLogger;

            try
            {
                Stream readerStream;

                if (m_format == RsrzFormat.EncryptedJsonWithoutCompression)
                {
                    byte[] salt = new byte[kExportSaltLength];
                    ret = sInput.Read(salt, 0, kExportSaltLength);
                    if (ret != kExportSaltLength) return;

                    var aesEngine = new StandardAesEngine();

                    KeyCreationForm kcf = new KeyCreationForm();
                    DialogResult dr = kcf.ShowDialog();
                    if (dr == DialogResult.Cancel || dr == DialogResult.Abort)
                    {
                        return;
                    }

                    m_newPasswordBytes = (kcf.CompositeKey.GetUserKey(typeof(KcpPassword)) as KcpPassword).Password.ReadUtf8() ?? null;

                    byte[] aes256Key = Util.PBKDF2Sha256GetBytes(kExportKeyLength, m_passwordBytes, salt, kKeyDerivationRoundForExport);
                    byte[] iv = new byte[kExportIVLength];

                    for (int i = 0; i < kExportIVLength; i++) iv[i] = salt[i];

                    readerStream = aesEngine.DecryptStream(sInput, aes256Key, iv);
                }
                else if (m_format == RsrzFormat.CompressedJsonWithoutEncryption)
                {
                    readerStream = new GZipStream(sInput, CompressionMode.Decompress);
                }
                else {
                    Debug.Assert(false);
                    throw new FormatException("RsrzFormat");
                }

                m_jsonReader = new JsonTextReader(new StreamReader(readerStream));

                ReadDocument(pwStorage);

                m_jsonReader.Close();
                readerStream.Close();
            }
            finally
            {
                CommonCleanUpRead(sInput);
            }
        }

        public void CommonCleanUpRead(Stream sInput)
        {
            sInput.Close();
            m_jsonReader = null;
        }

        private void ReadDocument(PwDatabase storageDB)
        {
            JsonSerializer serializer = JsonSerializer.Create();
            var jarray = serializer.Deserialize<List<RsoRecord>>(m_jsonReader);

            foreach (RsoRecord r in jarray)
            {
                PwEntry pe = new PwEntry(true, true);

                // Basic record info
                if (r.name != null) pe.Strings.Set("Title", new ProtectedString(false, r.name));
                if (r.desc != null) pe.Strings.Set("Notes", new ProtectedString(false, r.desc));

                // Record logo
                switch(r.categoryType)
                {
                    case (int)CategoryType.App:
                        pe.IconId = PwIcon.ProgramIcons;
                        break;
                    case (int)CategoryType.Card:
                        pe.IconId = PwIcon.Homebanking;
                        break;
                    case (int)CategoryType.Certificate:
                        pe.IconId = PwIcon.Certificate;
                        break;
                    case (int)CategoryType.Computer:
                        pe.IconId = PwIcon.WorldComputer;
                        break;
                    case (int)CategoryType.Email:
                        pe.IconId = PwIcon.EMail;
                        break;
                    case (int)CategoryType.Encryption:
                        pe.IconId = PwIcon.TerminalEncrypted;
                        break;
                    case (int)CategoryType.File:
                        pe.IconId = PwIcon.FolderPackage;
                        break;
                    case (int)CategoryType.Generic:
                        pe.IconId = PwIcon.Info;
                        break;
                    case (int)CategoryType.Identity:
                        pe.IconId = PwIcon.Identity;
                        break;
                    case (int)CategoryType.Network:
                        pe.IconId = PwIcon.WorldSocket;
                        break;
                    case (int)CategoryType.Note:
                        pe.IconId = PwIcon.Note;
                        break;
                    case (int)CategoryType.Smartphone:
                        pe.IconId = PwIcon.BlackBerry;
                        break;
                    case (int)CategoryType.Vehicle:
                        pe.IconId = PwIcon.Info;
                        break;
                    case (int)CategoryType.Website:
                        pe.IconId = PwIcon.WorldComputer;
                        break;
                    default:
                        pe.IconId = PwIcon.Info;
                        break;
                }

                foreach (RsoField f in r.fields)
                {
                    var ps = pe.Strings;

                    string strValue = f.stringValue;        // TODO: Handle protected sensitive fields.

                    switch (f.type)
                    {
                        case (int)FieldType.Username:
                            ps.Set("UserName", new ProtectedString(f.isSensitive != 0, strValue));
                            break;
                        case (int)FieldType.Password:
                            ps.Set("Password", new ProtectedString(f.isSensitive != 0, strValue));
                            break;
                        case (int)FieldType.WebsiteURL:
                            ps.Set("URL", new ProtectedString(f.isSensitive != 0, strValue));
                            break;
                        case (int)FieldType.Note:
                            ps.Set("Notes", new ProtectedString(f.isSensitive != 0, strValue));
                            break;
                        default:
                            ps.Set(f.label, new ProtectedString(f.isSensitive != 0, strValue));
                            break;
                    }
                }

                pe.LastModificationTime = Util.FromAbsoluteReferenceTime(r.lastUpdated);

                // Add the record to root
                storageDB.RootGroup.AddEntry(pe, true);
            }
        }
    }
}
