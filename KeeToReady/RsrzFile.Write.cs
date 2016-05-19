using KeePassLib;
using KeePassLib.Collections;
using KeePassLib.Cryptography;
using KeePassLib.Delegates;
using KeePassLib.Interfaces;
using KeePassLib.Security;
using KeePassLib.Utility;
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
        public void Save(Stream sSaveTo, PwGroup pgDataSource, RsrzFormat format,IStatusLogger slLogger)
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

#if KeePassUAP
				XmlWriterSettings xws = new XmlWriterSettings();
				xws.Encoding = encNoBom;
				xws.Indent = true;
				xws.IndentChars = "\t";
				xws.NewLineOnAttributes = false;

				XmlWriter xw = XmlWriter.Create(writerStream, xws);
#else
                XmlTextWriter xw = new XmlTextWriter(writerStream, encNoBom);

                xw.Formatting = Formatting.Indented;
                xw.IndentChar = '\t';
                xw.Indentation = 1;
#endif

                m_xmlWriter = xw;

                WriteDocument(pgDataSource);

                m_xmlWriter.Flush();
                m_xmlWriter.Close();
                writerStream.Close();
            }
            finally { CommonCleanUpWrite(sSaveTo, hashedStream); }
        }

        private void CommonCleanUpWrite(Stream sSaveTo, HashingStreamEx hashedStream)
        {
            hashedStream.Close();
            m_pbHashOfFileOnDisk = hashedStream.Hash;

            sSaveTo.Close();

            m_xmlWriter = null;
            m_pbHashOfHeader = null;
        }

        private void SubWriteValue(ProtectedBinary value)
        {

            {
                if (m_pwDatabase.Compression == PwCompressionAlgorithm.GZip)
                {
                    m_xmlWriter.WriteAttributeString(AttrCompressed, ValTrue);

                    byte[] pbRaw = value.ReadData();
                    byte[] pbCmp = MemUtil.Compress(pbRaw);
                    m_xmlWriter.WriteBase64(pbCmp, 0, pbCmp.Length);
                }
                else
                {
                    byte[] pbRaw = value.ReadData();
                    m_xmlWriter.WriteBase64(pbRaw, 0, pbRaw.Length);
                }
            }
        }

        private void StartGroup(PwGroup pg)
        {
            m_xmlWriter.WriteStartElement(ElemGroup);
            WriteObject(ElemUuid, pg.Uuid);
            WriteObject(ElemName, pg.Name, true);
            WriteObject(ElemNotes, pg.Notes, true);
            WriteObject(ElemIcon, (int)pg.IconId);

            if (!pg.CustomIconUuid.Equals(PwUuid.Zero))
                WriteObject(ElemCustomIconID, pg.CustomIconUuid);

            WriteList(ElemTimes, pg);
            WriteObject(ElemIsExpanded, pg.IsExpanded);
            WriteObject(ElemGroupDefaultAutoTypeSeq, pg.DefaultAutoTypeSequence, true);
            WriteObject(ElemEnableAutoType, StrUtil.BoolToStringEx(pg.EnableAutoType), false);
            WriteObject(ElemEnableSearching, StrUtil.BoolToStringEx(pg.EnableSearching), false);
            WriteObject(ElemLastTopVisibleEntry, pg.LastTopVisibleEntry);
        }

        private void EndGroup()
        {
            m_xmlWriter.WriteEndElement(); // Close group element
        }


        private void WriteEntry(PwEntry pe, bool bIsHistory)
        {
            Debug.Assert(pe != null); if (pe == null) throw new ArgumentNullException("pe");

            m_xmlWriter.WriteStartElement(ElemEntry);

            WriteObject(ElemUuid, pe.Uuid);
            WriteObject(ElemIcon, (int)pe.IconId);

            if (!pe.CustomIconUuid.Equals(PwUuid.Zero))
                WriteObject(ElemCustomIconID, pe.CustomIconUuid);

            WriteObject(ElemFgColor, StrUtil.ColorToUnnamedHtml(pe.ForegroundColor, true), false);
            WriteObject(ElemBgColor, StrUtil.ColorToUnnamedHtml(pe.BackgroundColor, true), false);
            WriteObject(ElemOverrideUrl, pe.OverrideUrl, true);
            WriteObject(ElemTags, StrUtil.TagsToString(pe.Tags, false), true);

            WriteList(ElemTimes, pe);

            WriteList(pe.Strings, true);
            WriteList(pe.Binaries);
            WriteList(ElemAutoType, pe.AutoType);

            if (!bIsHistory) WriteList(ElemHistory, pe.History, true);
            else { Debug.Assert(pe.History.UCount == 0); }

            m_xmlWriter.WriteEndElement();
        }

        private void WriteList(ProtectedStringDictionary dictStrings, bool bEntryStrings)
        {
            Debug.Assert(dictStrings != null);
            if (dictStrings == null) throw new ArgumentNullException("dictStrings");

            foreach (KeyValuePair<string, ProtectedString> kvp in dictStrings)
                WriteObject(kvp.Key, kvp.Value, bEntryStrings);
        }

        private void WriteList(ProtectedBinaryDictionary dictBinaries)
        {
            Debug.Assert(dictBinaries != null);
            if (dictBinaries == null) throw new ArgumentNullException("dictBinaries");

            foreach (KeyValuePair<string, ProtectedBinary> kvp in dictBinaries)
                WriteObject(kvp.Key, kvp.Value, true);
        }

        private void WriteList(string name, AutoTypeConfig cfgAutoType)
        {
            Debug.Assert(name != null);
            Debug.Assert(cfgAutoType != null);
            if (cfgAutoType == null) throw new ArgumentNullException("cfgAutoType");

            m_xmlWriter.WriteStartElement(name);

            WriteObject(ElemAutoTypeEnabled, cfgAutoType.Enabled);
            WriteObject(ElemAutoTypeObfuscation, (int)cfgAutoType.ObfuscationOptions);

            if (cfgAutoType.DefaultSequence.Length > 0)
                WriteObject(ElemAutoTypeDefaultSeq, cfgAutoType.DefaultSequence, true);

            foreach (AutoTypeAssociation a in cfgAutoType.Associations)
                WriteObject(ElemAutoTypeItem, ElemWindow, ElemKeystrokeSequence,
                    new KeyValuePair<string, string>(a.WindowName, a.Sequence));

            m_xmlWriter.WriteEndElement();
        }

        private void WriteList(string name, ITimeLogger times)
        {
            Debug.Assert(name != null);
            Debug.Assert(times != null); if (times == null) throw new ArgumentNullException("times");

            m_xmlWriter.WriteStartElement(name);

            WriteObject(ElemCreationTime, times.CreationTime);
            WriteObject(ElemLastModTime, times.LastModificationTime);
            WriteObject(ElemLastAccessTime, times.LastAccessTime);
            WriteObject(ElemExpiryTime, times.ExpiryTime);
            WriteObject(ElemExpires, times.Expires);
            WriteObject(ElemUsageCount, times.UsageCount);
            WriteObject(ElemLocationChanged, times.LocationChanged);

            m_xmlWriter.WriteEndElement(); // Name
        }

        private void WriteList(string name, PwObjectList<PwEntry> value, bool bIsHistory)
        {
            Debug.Assert(name != null);
            Debug.Assert(value != null); if (value == null) throw new ArgumentNullException("value");

            m_xmlWriter.WriteStartElement(name);

            foreach (PwEntry pe in value)
                WriteEntry(pe, bIsHistory);

            m_xmlWriter.WriteEndElement();
        }

        private void WriteList(string name, PwObjectList<PwDeletedObject> value)
        {
            Debug.Assert(name != null);
            Debug.Assert(value != null); if (value == null) throw new ArgumentNullException("value");

            m_xmlWriter.WriteStartElement(name);

            foreach (PwDeletedObject pdo in value)
                WriteObject(ElemDeletedObject, pdo);

            m_xmlWriter.WriteEndElement();
        }

        private void WriteList(string name, MemoryProtectionConfig value)
        {
            Debug.Assert(name != null);
            Debug.Assert(value != null);

            m_xmlWriter.WriteStartElement(name);

            WriteObject(ElemProtTitle, value.ProtectTitle);
            WriteObject(ElemProtUserName, value.ProtectUserName);
            WriteObject(ElemProtPassword, value.ProtectPassword);
            WriteObject(ElemProtUrl, value.ProtectUrl);
            WriteObject(ElemProtNotes, value.ProtectNotes);
            // WriteObject(ElemProtAutoHide, value.AutoEnableVisualHiding);

            m_xmlWriter.WriteEndElement();
        }

        private void WriteList(string name, StringDictionaryEx value)
        {
            Debug.Assert(name != null);
            Debug.Assert(value != null); if (value == null) throw new ArgumentNullException("value");

            m_xmlWriter.WriteStartElement(name);

            foreach (KeyValuePair<string, string> kvp in value)
                WriteObject(ElemStringDictExItem, ElemKey, ElemValue, kvp);

            m_xmlWriter.WriteEndElement();
        }

        private void WriteCustomIconList()
        {
            if (m_pwDatabase.CustomIcons.Count == 0) return;

            m_xmlWriter.WriteStartElement(ElemCustomIcons);

            foreach (PwCustomIcon pwci in m_pwDatabase.CustomIcons)
            {
                m_xmlWriter.WriteStartElement(ElemCustomIconItem);

                WriteObject(ElemCustomIconItemID, pwci.Uuid);

                string strData = Convert.ToBase64String(pwci.ImageDataPng);
                WriteObject(ElemCustomIconItemData, strData, false);

                m_xmlWriter.WriteEndElement();
            }

            m_xmlWriter.WriteEndElement();
        }

        private void WriteObject(string name, PwDeletedObject value)
        {
            Debug.Assert(name != null);
            Debug.Assert(value != null); if (value == null) throw new ArgumentNullException("value");

            m_xmlWriter.WriteStartElement(name);
            WriteObject(ElemUuid, value.Uuid);
            WriteObject(ElemDeletionTime, value.DeletionTime);
            m_xmlWriter.WriteEndElement();
        }

        private void WriteObject(string name, string value,
            bool bFilterValueXmlChars)
        {
            Debug.Assert(name != null);
            Debug.Assert(value != null);

            m_xmlWriter.WriteStartElement(name);

            if (bFilterValueXmlChars)
                m_xmlWriter.WriteString(StrUtil.SafeXmlString(value));
            else m_xmlWriter.WriteString(value);

            m_xmlWriter.WriteEndElement();
        }

        private void WriteObject(string name, bool value)
        {
            Debug.Assert(name != null);

            WriteObject(name, value ? ValTrue : ValFalse, false);
        }

        private void WriteObject(string name, PwUuid value)
        {
            Debug.Assert(name != null);
            Debug.Assert(value != null); if (value == null) throw new ArgumentNullException("value");

            WriteObject(name, Convert.ToBase64String(value.UuidBytes), false);
        }

        private void WriteObject(string name, int value)
        {
            Debug.Assert(name != null);

            m_xmlWriter.WriteStartElement(name);
            m_xmlWriter.WriteString(value.ToString(NumberFormatInfo.InvariantInfo));
            m_xmlWriter.WriteEndElement();
        }

        private void WriteObject(string name, uint value)
        {
            Debug.Assert(name != null);

            m_xmlWriter.WriteStartElement(name);
            m_xmlWriter.WriteString(value.ToString(NumberFormatInfo.InvariantInfo));
            m_xmlWriter.WriteEndElement();
        }

        private void WriteObject(string name, long value)
        {
            Debug.Assert(name != null);

            m_xmlWriter.WriteStartElement(name);
            m_xmlWriter.WriteString(value.ToString(NumberFormatInfo.InvariantInfo));
            m_xmlWriter.WriteEndElement();
        }

        private void WriteObject(string name, ulong value)
        {
            Debug.Assert(name != null);

            m_xmlWriter.WriteStartElement(name);
            m_xmlWriter.WriteString(value.ToString(NumberFormatInfo.InvariantInfo));
            m_xmlWriter.WriteEndElement();
        }

        private void WriteObject(string name, DateTime value)
        {
            Debug.Assert(name != null);

            WriteObject(name, TimeUtil.SerializeUtc(value), false);
        }

        private void WriteObject(string name, string strKeyName,
            string strValueName, KeyValuePair<string, string> kvp)
        {
            m_xmlWriter.WriteStartElement(name);

            m_xmlWriter.WriteStartElement(strKeyName);
            m_xmlWriter.WriteString(StrUtil.SafeXmlString(kvp.Key));
            m_xmlWriter.WriteEndElement();
            m_xmlWriter.WriteStartElement(strValueName);
            m_xmlWriter.WriteString(StrUtil.SafeXmlString(kvp.Value));
            m_xmlWriter.WriteEndElement();

            m_xmlWriter.WriteEndElement();
        }

        private void WriteObject(string name, ProtectedString value, bool bIsEntryString)
        {
            Debug.Assert(name != null);
            Debug.Assert(value != null); if (value == null) throw new ArgumentNullException("value");

            m_xmlWriter.WriteStartElement(ElemString);
            m_xmlWriter.WriteStartElement(ElemKey);
            m_xmlWriter.WriteString(StrUtil.SafeXmlString(name));
            m_xmlWriter.WriteEndElement();
            m_xmlWriter.WriteStartElement(ElemValue);

            bool bProtected = value.IsProtected;
            if (bIsEntryString)
            {
                // Adjust memory protection setting (which might be different
                // from the database default, e.g. due to an import which
                // didn't specify the correct setting)
                if (name == PwDefs.TitleField)
                    bProtected = m_pwDatabase.MemoryProtection.ProtectTitle;
                else if (name == PwDefs.UserNameField)
                    bProtected = m_pwDatabase.MemoryProtection.ProtectUserName;
                else if (name == PwDefs.PasswordField)
                    bProtected = m_pwDatabase.MemoryProtection.ProtectPassword;
                else if (name == PwDefs.UrlField)
                    bProtected = m_pwDatabase.MemoryProtection.ProtectUrl;
                else if (name == PwDefs.NotesField)
                    bProtected = m_pwDatabase.MemoryProtection.ProtectNotes;
            }


            {
                string strValue = value.ReadString();

                // If names should be localized, we need to apply the language-dependent
                // string transformation here. By default, language-dependent conversions
                // should be applied, otherwise characters could be rendered incorrectly
                // (code page problems).
                if (m_bLocalizedNames)
                {
                    StringBuilder sb = new StringBuilder();
                    foreach (char ch in strValue)
                    {
                        char chMapped = ch;

                        // Symbols and surrogates must be moved into the correct code
                        // page area
                        if (char.IsSymbol(ch) || char.IsSurrogate(ch))
                        {
                            System.Globalization.UnicodeCategory cat =
                                CharUnicodeInfo.GetUnicodeCategory(ch);
                            // Map character to correct position in code page
                            chMapped = (char)((int)cat * 32 + ch);
                        }
                        else if (char.IsControl(ch))
                        {
                            if (ch >= 256) // Control character in high ANSI code page
                            {
                                // Some of the control characters map to corresponding ones
                                // in the low ANSI range (up to 255) when calling
                                // ToLower on them with invariant culture (see
                                // http://lists.ximian.com/pipermail/mono-patches/2002-February/086106.html )
#if !KeePassLibSD
                                chMapped = char.ToLowerInvariant(ch);
#else
								chMapped = char.ToLower(ch);
#endif
                            }
                        }

                        sb.Append(chMapped);
                    }

                    strValue = sb.ToString(); // Correct string for current code page
                }

                if ((m_format == RsrzFormat.CompressedJsonWithoutEncryption) && bProtected)
                    m_xmlWriter.WriteAttributeString(AttrProtectedInMemPlainXml, ValTrue);

                m_xmlWriter.WriteString(StrUtil.SafeXmlString(strValue));
            }

            m_xmlWriter.WriteEndElement(); // ElemValue
            m_xmlWriter.WriteEndElement(); // ElemString
        }

        private void WriteObject(string name, ProtectedBinary value, bool bAllowRef)
        {
            Debug.Assert(name != null);
            Debug.Assert(value != null); if (value == null) throw new ArgumentNullException("value");

            m_xmlWriter.WriteStartElement(ElemBinary);
            m_xmlWriter.WriteStartElement(ElemKey);
            m_xmlWriter.WriteString(StrUtil.SafeXmlString(name));
            m_xmlWriter.WriteEndElement();
            m_xmlWriter.WriteStartElement(ElemValue);

            string strRef = (bAllowRef ? BinPoolFind(value) : null);
            if (strRef != null)
            {
                m_xmlWriter.WriteAttributeString(AttrRef, strRef);
            }
            else SubWriteValue(value);

            m_xmlWriter.WriteEndElement(); // ElemValue
            m_xmlWriter.WriteEndElement(); // ElemBinary
        }


        private void WriteMeta()
        {
            m_xmlWriter.WriteStartElement(ElemMeta);

            WriteObject(ElemGenerator, PwDatabase.LocalizedAppName, false); // Generator name

            if (m_pbHashOfHeader != null)
                WriteObject(ElemHeaderHash, Convert.ToBase64String(
                    m_pbHashOfHeader), false);

            WriteObject(ElemDbName, m_pwDatabase.Name, true);
            WriteObject(ElemDbNameChanged, m_pwDatabase.NameChanged);
            WriteObject(ElemDbDesc, m_pwDatabase.Description, true);
            WriteObject(ElemDbDescChanged, m_pwDatabase.DescriptionChanged);
            WriteObject(ElemDbDefaultUser, m_pwDatabase.DefaultUserName, true);
            WriteObject(ElemDbDefaultUserChanged, m_pwDatabase.DefaultUserNameChanged);
            WriteObject(ElemDbMntncHistoryDays, m_pwDatabase.MaintenanceHistoryDays);
            WriteObject(ElemDbColor, StrUtil.ColorToUnnamedHtml(m_pwDatabase.Color, true), false);
            WriteObject(ElemDbKeyChanged, m_pwDatabase.MasterKeyChanged);
            WriteObject(ElemDbKeyChangeRec, m_pwDatabase.MasterKeyChangeRec);
            WriteObject(ElemDbKeyChangeForce, m_pwDatabase.MasterKeyChangeForce);

            WriteList(ElemMemoryProt, m_pwDatabase.MemoryProtection);

            WriteCustomIconList();

            WriteObject(ElemRecycleBinEnabled, m_pwDatabase.RecycleBinEnabled);
            WriteObject(ElemRecycleBinUuid, m_pwDatabase.RecycleBinUuid);
            WriteObject(ElemRecycleBinChanged, m_pwDatabase.RecycleBinChanged);
            WriteObject(ElemEntryTemplatesGroup, m_pwDatabase.EntryTemplatesGroup);
            WriteObject(ElemEntryTemplatesGroupChanged, m_pwDatabase.EntryTemplatesGroupChanged);
            WriteObject(ElemHistoryMaxItems, m_pwDatabase.HistoryMaxItems);
            WriteObject(ElemHistoryMaxSize, m_pwDatabase.HistoryMaxSize);

            WriteObject(ElemLastSelectedGroup, m_pwDatabase.LastSelectedGroup);
            WriteObject(ElemLastTopVisibleGroup, m_pwDatabase.LastTopVisibleGroup);

            WriteBinPool();
            WriteList(ElemCustomData, m_pwDatabase.CustomData);

            m_xmlWriter.WriteEndElement();
        }

        private void WriteBinPool()
        {
            m_xmlWriter.WriteStartElement(ElemBinaries);

            foreach (KeyValuePair<string, ProtectedBinary> kvp in m_dictBinPool)
            {
                m_xmlWriter.WriteStartElement(ElemBinary);
                m_xmlWriter.WriteAttributeString(AttrId, kvp.Key);
                SubWriteValue(kvp.Value);
                m_xmlWriter.WriteEndElement();
            }

            m_xmlWriter.WriteEndElement();
        }


        private void WriteDocument(PwGroup pgDataSource)
        {
            Debug.Assert(m_xmlWriter != null);
            if (m_xmlWriter == null) throw new InvalidOperationException();

            PwGroup pgRoot = (pgDataSource ?? m_pwDatabase.RootGroup);

            uint uNumGroups, uNumEntries, uCurEntry = 0;
            pgRoot.GetCounts(true, out uNumGroups, out uNumEntries);

            BinPoolBuild(pgRoot);

            m_xmlWriter.WriteStartDocument(true);
            m_xmlWriter.WriteStartElement(ElemDocNode);

            WriteMeta();

            m_xmlWriter.WriteStartElement(ElemRoot);
            StartGroup(pgRoot);

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
                        StartGroup(pg);
                        break;
                    }
                    else
                    {
                        groupStack.Pop();
                        if (groupStack.Count <= 0) return false;

                        EndGroup();
                    }
                }

                return true;
            };

            EntryHandler eh = delegate (PwEntry pe)
            {
                Debug.Assert(pe != null);
                WriteEntry(pe, false);

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
                m_xmlWriter.WriteEndElement();
                groupStack.Pop();
            }

            EndGroup();

            WriteList(ElemDeletedObjects, m_pwDatabase.DeletedObjects);
            m_xmlWriter.WriteEndElement(); // Root

            m_xmlWriter.WriteEndElement(); // ElemDocNode
            m_xmlWriter.WriteEndDocument();
        }
		private void BinPoolBuild(PwGroup pgDataSource)
		{
			m_dictBinPool = new Dictionary<string, ProtectedBinary>();

			if(pgDataSource == null) { Debug.Assert(false); return; }

			EntryHandler eh = delegate(PwEntry pe)
			{
				foreach(PwEntry peHistory in pe.History)
				{
					BinPoolAdd(peHistory.Binaries);
				}

				BinPoolAdd(pe.Binaries);
				return true;
			};

			pgDataSource.TraverseTree(TraversalMethod.PreOrder, null, eh);
		}

		private void BinPoolAdd(ProtectedBinaryDictionary dict)
		{
			foreach(KeyValuePair<string, ProtectedBinary> kvp in dict)
			{
				BinPoolAdd(kvp.Value);
			}
		}

		private void BinPoolAdd(ProtectedBinary pb)
		{
			if(pb == null) { Debug.Assert(false); return; }

			if(BinPoolFind(pb) != null) return; // Exists already

			m_dictBinPool.Add(m_dictBinPool.Count.ToString(
				NumberFormatInfo.InvariantInfo), pb);
		}

		private string BinPoolFind(ProtectedBinary pb)
		{
			if(pb == null) { Debug.Assert(false); return null; }

			foreach(KeyValuePair<string, ProtectedBinary> kvp in m_dictBinPool)
			{
				if(pb.Equals(kvp.Value)) return kvp.Key;
			}

			return null;
		}

		private ProtectedBinary BinPoolGet(string strKey)
		{
			if(strKey == null) { Debug.Assert(false); return null; }

			ProtectedBinary pb;
			if(m_dictBinPool.TryGetValue(strKey, out pb)) return pb;

			return null;
		}
    }
}
