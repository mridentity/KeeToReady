using KeePassLib;
using KeePassLib.Collections;
using KeePassLib.Cryptography;
using KeePassLib.Delegates;
using KeePassLib.Interfaces;
using KeePassLib.Security;
using KeePassLib.Utility;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
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
                    writerStream = null;
                }
                else if (m_format == RsrzFormat.CompressedJsonWithoutEncryption)
                    writerStream = hashedStream;
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

                r.asTempalte = r.isTemplate = 0;
                r.cloudID = null;

                r.lastUpdated = pe.LastModificationTime.GetAbsoluteReference2001();

                List<RsoField> fields = new List<RsoField>();

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
                        default:
                            continue;
                    }

                    f.stringValue = ps.Value.ReadString();
                    f.label = ps.Key;
                    f.isSensitive = ps.Value.IsProtected ? 0 : 0;   // TODO: need to mark sensitive and protect the field.
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
    }
  }
