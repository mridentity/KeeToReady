using KeePass.DataExchange;
using KeePassLib.Interfaces;
using System.Drawing;
using System.IO;

namespace KeeToReady
{
    internal sealed class EncryptedProvider : FileFormatProvider
    {
        public override bool SupportsImport { get { return false; } }
        public override bool SupportsExport { get { return true; } }
        public override string FormatName { get { return "ReadySignOn (encrypted using current password)"; } }
        public override string DefaultExtension { get { return "rsrz"; } }
        public override string ApplicationGroup { get { return "ReadySignOn"; } }

        public override Image SmallIcon
        {
            get { return Properties.Resources.B16x16_KeePassPlus; }
        }

        public override bool Export(PwExportInfo pwExportInfo, Stream sOutput,
            IStatusLogger slLogger)
        {
            RsrzFile rsrz = new RsrzFile(pwExportInfo.ContextDatabase);

            rsrz.Save(sOutput, pwExportInfo.DataGroup, RsrzFormat.EncryptedJsonWithoutCompression, slLogger);

            return true;
        }
    }
}
