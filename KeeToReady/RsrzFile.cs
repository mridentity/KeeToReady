using KeePassLib;
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
        private const int kKeyXorredSaltLength = 32; // This seamingly large (256 bits) salt is necessary given the sensitive text field is directly xorred with the key derived from the master key.
        private const int kEncryptionRoundForSensitiveFields = 2;   // This is key derivation round for protecting the sensitive text field. Even the smallest number one(1) should be good enough given the direct xorred operation with a long salt.

        private const int kXorredKeySaltLength = 32; // Instead of using a stream cipher, sensitive fields are XORed with a key directly derived from the master password, therefore a unique large salt (256bit) is needed for each field.

        private const int kExportSaltLength = 32;  // 256bits, this is the salt unique to each exported file.
        private const int kExportKeyLength = 32;   // 256bits, this is the encryption key protecting the exported file.

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
