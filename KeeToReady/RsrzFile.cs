﻿using KeePassLib;
using KeePassLib.Interfaces;
using KeePassLib.Security;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace KeeToReady
{
    /// <summary>
    /// The <c>RsrzFile</c> class supports saving records in different formats.
    /// </summary>
    public enum RsrzFormat
    {
        EncryptedJsonWithoutCompression = 0,
        CompressedJsonWithoutEncryption
    }

    public sealed partial class RsrzFile
    {
        private const int kExportSaltLength = 32;  // 256bits, this is the salt unique to each exported file.
        private const int kExportKeyLength = 32;   // 256bits, this is the encryption key protecting the exported file.
        private const int kExportIVLength = 16;    // 128 bits


        // This seemingly huge iteration count is necessary considering the exported
        // records may be sent via email, SMS or other public communication channels.
        // The delay associated with it should be acceptable from UX standpoint given
        // the export function is not frequently triggered by the end user anyway.    
        private const long kKeyDerivationRoundForExport = 1000000;

        private PwDatabase m_pwDatabase; // Not null, see constructor

        private IStatusLogger m_slLogger = null;

        private RsrzFormat m_format = RsrzFormat.CompressedJsonWithoutEncryption;

        private JsonTextWriter m_jsonWriter = null;

        private byte[] m_pbHashOfFileOnDisk = null;

        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="pwDataStore">The <c>PwDatabase</c> instance that the
        /// class will load file data into or use to create a RSRZ file.</param>
        public RsrzFile(PwDatabase pwDataStore)
        {
            Debug.Assert(pwDataStore != null);
            if (pwDataStore == null) throw new ArgumentNullException("pwDataStore");

            m_pwDatabase = pwDataStore;
        }
    }
}
