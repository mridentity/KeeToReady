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
        public void Read(PwDatabase pwStorage, Stream sInput, IStatusLogger slLogger)
        {
            Debug.Assert(sInput != null);
            if (sInput == null) throw new ArgumentException("sInput");

            m_format = RsrzFormat.CompressedJsonWithoutEncryption;  // TODO: need to base teh format on the content of the file.
            m_slLogger = slLogger;

            try
            {
                Stream readerStream;

                if (m_format == RsrzFormat.EncryptedJsonWithoutCompression)
                {
                    readerStream = null;
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

        private void ReadDocument(PwDatabase targetDB)
        {
            JsonSerializer serializer = JsonSerializer.Create();
            var jarray = serializer.Deserialize<List<RsoRecord>>(m_jsonReader);

            foreach (RsoRecord r in jarray)
            {
                PwEntry pe = new PwEntry(true, true);

                if (r.name != null) pe.Strings.Set("Title", new ProtectedString(false, r.name));
                if (r.desc != null) pe.Strings.Set("Notes", new ProtectedString(false, r.desc));

                targetDB.RootGroup.AddEntry(pe, true);
            }
        }
    }
}
