using KeePassLib;
using KeePassLib.Interfaces;
using KeePassLib.Security;
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
        private const int kKeyXoredSaltLength = 32; // This seamingly large (256 bits) salt is necessary given the sensitive text field is directly XORed with the key derived from the master key.
        private const int kEncryptionRoundForSensitiveFields = 2;   // This is key derivation round for protecting the sensitive text field. Even the smallest number one(1) should be good enough given the direct XORed operation with a long salt.

        private const int kXoredKeySaltLength = 32; // Instead of using a stream cipher, sensitive fields are XORed with a key directly derived from the master password, therefore a unique large salt (256bit) is needed for each field.

        private const int kExportSaltLength = 32;  // 256bits, this is the salt unique to each exported file.
        private const int kExportKeyLength = 32;   // 256bits, this is the encryption key protecting the exported file.

        // This seemingly huge iteration count is necessary considering the exported
        // records may be sent via email, SMS or other public communication channels.
        // The delay associated with it should be acceptable from UX standpoint given
        // the export function is not frequently triggered by the end user anyway.    
        private const long kKeyDerivationRoundForExport = 1000000;

        private const string ElemDocNode = "KeePassFile";
        private const string ElemMeta = "Meta";
        private const string ElemRoot = "Root";
        private const string ElemGroup = "Group";
        private const string ElemEntry = "Entry";

        private const string ElemGenerator = "Generator";
        private const string ElemHeaderHash = "HeaderHash";
        private const string ElemDbName = "DatabaseName";
        private const string ElemDbNameChanged = "DatabaseNameChanged";
        private const string ElemDbDesc = "DatabaseDescription";
        private const string ElemDbDescChanged = "DatabaseDescriptionChanged";
        private const string ElemDbDefaultUser = "DefaultUserName";
        private const string ElemDbDefaultUserChanged = "DefaultUserNameChanged";
        private const string ElemDbMntncHistoryDays = "MaintenanceHistoryDays";
        private const string ElemDbColor = "Color";
        private const string ElemDbKeyChanged = "MasterKeyChanged";
        private const string ElemDbKeyChangeRec = "MasterKeyChangeRec";
        private const string ElemDbKeyChangeForce = "MasterKeyChangeForce";
        private const string ElemRecycleBinEnabled = "RecycleBinEnabled";
        private const string ElemRecycleBinUuid = "RecycleBinUUID";
        private const string ElemRecycleBinChanged = "RecycleBinChanged";
        private const string ElemEntryTemplatesGroup = "EntryTemplatesGroup";
        private const string ElemEntryTemplatesGroupChanged = "EntryTemplatesGroupChanged";
        private const string ElemHistoryMaxItems = "HistoryMaxItems";
        private const string ElemHistoryMaxSize = "HistoryMaxSize";
        private const string ElemLastSelectedGroup = "LastSelectedGroup";
        private const string ElemLastTopVisibleGroup = "LastTopVisibleGroup";

        private const string ElemMemoryProt = "MemoryProtection";
        private const string ElemProtTitle = "ProtectTitle";
        private const string ElemProtUserName = "ProtectUserName";
        private const string ElemProtPassword = "ProtectPassword";
        private const string ElemProtUrl = "ProtectURL";
        private const string ElemProtNotes = "ProtectNotes";
        // private const string ElemProtAutoHide = "AutoEnableVisualHiding";

        private const string ElemCustomIcons = "CustomIcons";
        private const string ElemCustomIconItem = "Icon";
        private const string ElemCustomIconItemID = "UUID";
        private const string ElemCustomIconItemData = "Data";

        private const string ElemAutoType = "AutoType";
        private const string ElemHistory = "History";

        private const string ElemName = "Name";
        private const string ElemNotes = "Notes";
        private const string ElemUuid = "UUID";
        private const string ElemIcon = "IconID";
        private const string ElemCustomIconID = "CustomIconUUID";
        private const string ElemFgColor = "ForegroundColor";
        private const string ElemBgColor = "BackgroundColor";
        private const string ElemOverrideUrl = "OverrideURL";
        private const string ElemTimes = "Times";
        private const string ElemTags = "Tags";

        private const string ElemCreationTime = "CreationTime";
        private const string ElemLastModTime = "LastModificationTime";
        private const string ElemLastAccessTime = "LastAccessTime";
        private const string ElemExpiryTime = "ExpiryTime";
        private const string ElemExpires = "Expires";
        private const string ElemUsageCount = "UsageCount";
        private const string ElemLocationChanged = "LocationChanged";

        private const string ElemGroupDefaultAutoTypeSeq = "DefaultAutoTypeSequence";
        private const string ElemEnableAutoType = "EnableAutoType";
        private const string ElemEnableSearching = "EnableSearching";

        private const string ElemString = "String";
        private const string ElemBinary = "Binary";
        private const string ElemKey = "Key";
        private const string ElemValue = "Value";

        private const string ElemAutoTypeEnabled = "Enabled";
        private const string ElemAutoTypeObfuscation = "DataTransferObfuscation";
        private const string ElemAutoTypeDefaultSeq = "DefaultSequence";
        private const string ElemAutoTypeItem = "Association";
        private const string ElemWindow = "Window";
        private const string ElemKeystrokeSequence = "KeystrokeSequence";

        private const string ElemBinaries = "Binaries";

        private const string AttrId = "ID";
        private const string AttrRef = "Ref";
        private const string AttrProtected = "Protected";
        private const string AttrProtectedInMemPlainXml = "ProtectInMemory";
        private const string AttrCompressed = "Compressed";

        private const string ElemIsExpanded = "IsExpanded";
        private const string ElemLastTopVisibleEntry = "LastTopVisibleEntry";

        private const string ElemDeletedObjects = "DeletedObjects";
        private const string ElemDeletedObject = "DeletedObject";
        private const string ElemDeletionTime = "DeletionTime";

        private const string ValFalse = "False";
        private const string ValTrue = "True";

        private const string ElemCustomData = "CustomData";
        private const string ElemStringDictExItem = "Item";

        private PwDatabase m_pwDatabase; // Not null, see constructor

        private IStatusLogger m_slLogger = null;

        private RsrzFormat m_format = RsrzFormat.CompressedJsonWithoutEncryption;

        private XmlWriter m_xmlWriter = null;

        private static bool m_bLocalizedNames = false;

        private Dictionary<string, ProtectedBinary> m_dictBinPool = new Dictionary<string, ProtectedBinary>();

        private byte[] m_pbHashOfHeader = null;
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
