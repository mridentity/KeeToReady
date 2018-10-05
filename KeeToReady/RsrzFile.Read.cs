using KeePass.Forms;
using KeePassLib;
using KeePassLib.Cryptography.Cipher;
using KeePassLib.Interfaces;
using KeePassLib.Keys;
using KeePassLib.Security;
using KeePassLib.Utility;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
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

                    KeyPromptForm kpf = new KeyPromptForm();

                    DialogResult dr = kpf.ShowDialog();
                    if (dr == DialogResult.Cancel || dr == DialogResult.Abort)
                    {
                        return;
                    }

                    m_passwordBytes = (kpf.CompositeKey.GetUserKey(typeof(KcpPassword)) as KcpPassword).Password.ReadUtf8() ?? null;

                    byte[] aes256Key = Util.PBKDF2Sha256GetBytes(kExportKeyLength, m_passwordBytes, salt, kKeyDerivationRoundForExport);
                    byte[] iv = new byte[kExportIVLength];

                    for (int i = 0; i < kExportIVLength; i++) iv[i] = salt[i];

                    readerStream = aesEngine.DecryptStream(sInput, aes256Key, iv);
                }
                else if (m_format == RsrzFormat.CompressedJsonWithoutEncryption)
                {
                    readerStream = new GZipStream(sInput, CompressionMode.Decompress);
                }
                else
                {
                    Debug.Assert(false);
                    throw new FormatException("Error: Unrecognized .rsrz file format.");
                }

                m_jsonReader = new JsonTextReader(new StreamReader(readerStream));

                ReadDocument(pwStorage);

                m_jsonReader.Close();
                readerStream.Close();
            }
            catch (Exception e)
            {
                throw new FormatException("Import cannot be completed due to incorrect password or file format.", e);
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
            JsonSerializerSettings jSettings = new JsonSerializerSettings();
            jSettings.CheckAdditionalContent = true;

            JsonSerializer serializer = JsonSerializer.Create(jSettings);
            serializer.CheckAdditionalContent = true;

            var jarray = serializer.Deserialize<List<RsoRecord>>(m_jsonReader);

            foreach (RsoRecord r in jarray)
            {
                PwEntry pe = new PwEntry(true, true);

                // Basic record info
                if (r.name != null) pe.Strings.Set("Title", new ProtectedString(false, r.name));
                if (r.desc != null) pe.Strings.Set("Notes", new ProtectedString(false, r.desc));

                // Record logo
                switch (r.categoryType)
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
                    case (int)CategoryType.Membership:
                        pe.IconId = PwIcon.Star;
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

                    if (m_format == RsrzFormat.EncryptedJsonWithoutCompression && f.isSensitive != 0)
                    {
                        // Decrypt using XOR key
                        strValue = CipherHexToString(m_passwordBytes, f.stringValue, kSensitiveProtectionRoundForExport);
                    }

                    if (strValue == null) strValue = string.Empty;  // KeePass doesn't like fields with null values.

                    switch (f.type)
                    {
                        case (int)FieldType.Username:
                            ps.Set("UserName", new ProtectedString(f.isSensitive != 0, strValue));
                            break;
                        case (int)FieldType.Password:
                            ps.Set("Password", new ProtectedString(f.isSensitive != 0, strValue));
                            break;
                        case (int)FieldType.eMailAddress:
                            ps.Set("Email", new ProtectedString(f.isSensitive != 0, strValue));
                            break;
                        case (int)FieldType.AccountName:
                            ps.Set("AccountName", new ProtectedString(f.isSensitive != 0, strValue));
                            break;
                        case (int)FieldType.AccountNumber:
                            ps.Set("AccountNumber", new ProtectedString(f.isSensitive != 0, strValue));
                            break;
                        case (int)FieldType.CardNumber:
                            ps.Set("CardNumber", new ProtectedString(f.isSensitive != 0, strValue));
                            break;
                        case (int)FieldType.SSN:
                            ps.Set("SSN", new ProtectedString(f.isSensitive != 0, strValue));
                            break;
                        case (int)FieldType.ComputerName:
                            ps.Set("ComputerName", new ProtectedString(f.isSensitive != 0, strValue));
                            break;
                        case (int)FieldType.NetworkDomain:
                            ps.Set("NetworkDomain", new ProtectedString(f.isSensitive != 0, strValue));
                            break;
                        case (int)FieldType.ServerHost:
                            ps.Set("ServerHost", new ProtectedString(f.isSensitive != 0, strValue));
                            break;
                        case (int)FieldType.IPAddress:
                            ps.Set("IPAddress", new ProtectedString(f.isSensitive != 0, strValue));
                            break;
                        case (int)FieldType.PostalAddress:
                            ps.Set("PostalAddress", new ProtectedString(f.isSensitive != 0, strValue));
                            break;
                        case (int)FieldType.PhoneNumber:
                            ps.Set("PhoneNumber", new ProtectedString(f.isSensitive != 0, strValue));
                            break;
                        case (int)FieldType.PassportNumber:
                            ps.Set("PassportNumber", new ProtectedString(f.isSensitive != 0, strValue));
                            break;
                        case (int)FieldType.ReadyIdPublicKey:
                            ps.Set("ReadyIdPublicKey", new ProtectedString(f.isSensitive != 0, strValue));
                            break;
                        case (int)FieldType.ReadyIdPrivateKey:
                            ps.Set("ReadyIdPrivateKey", new ProtectedString(f.isSensitive != 0, strValue));
                            break;
                        case (int)FieldType.BundleID:
                            ps.Set("BundleID", new ProtectedString(f.isSensitive != 0, strValue));
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

        public string CipherHexToString(byte[] password, string cipherHex, long interation)
        {
            if (string.IsNullOrEmpty(cipherHex)) return null;

            byte[] salt = MemUtil.HexStringToByteArray(cipherHex.Substring(0, kKeyXoredSaltLength * 2));

            byte[] cipherBytes = MemUtil.HexStringToByteArray(cipherHex.Substring(kKeyXoredSaltLength * 2, cipherHex.Length - kKeyXoredSaltLength * 2));

            if (salt == null || cipherBytes == null || salt.Length != kKeyXoredSaltLength || cipherBytes.Length <= 0) return null;

            byte[] xorKey = Util.PBKDF2Sha256GetBytes(cipherBytes.Length, password, salt, interation);

            byte[] xorred = new byte[xorKey.Length];

            for (int i = 0; i < xorKey.Length; i++)
            {
                if (i < cipherBytes.Length)
                {
                    byte b = cipherBytes[i];
                    b ^= xorKey[i];
                    xorred[i] = b;
                }
                else
                {
                    byte b = 0;
                    b ^= xorKey[i];
                    xorred[i] = b;
                }
            }

            return System.Text.Encoding.Default.GetString(xorred);
        }
    }
}
