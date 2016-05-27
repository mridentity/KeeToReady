using KeePass.DataExchange;
using KeePass.Forms;
using KeePassLib.Interfaces;
using KeePassLib.Keys;
using System.Drawing;
using System.IO;
using System.Windows.Forms;

namespace KeeToReady
{
    class EncryptWithNewPasswordProvider : FileFormatProvider
    {
        public override bool SupportsImport { get { return false; } }
        public override bool SupportsExport { get { return true; } }
        public override string FormatName { get { return "ReadySignOn (encrypt with a new password)"; } }
        public override string DefaultExtension { get { return "rsrz"; } }
        public override string ApplicationGroup { get { return "ReadySignOn"; } }

        public override Image SmallIcon
        {
            get { return Properties.Resources.B16x16_KeePassPlus; }
        }

        public override bool Export(PwExportInfo pwExportInfo, Stream sOutput, IStatusLogger slLogger)
        {

            KeyCreationForm kcf = new KeyCreationForm();
            DialogResult dr = kcf.ShowDialog();
            if (dr == DialogResult.Cancel || dr == DialogResult.Abort)
            {
                return false;
            }

            RsrzFile rsrz = new RsrzFile(pwExportInfo.ContextDatabase);

            rsrz.m_newPasswordBytes = (kcf.CompositeKey.GetUserKey(typeof(KcpPassword)) as KcpPassword).Password.ReadUtf8() ?? null;
            rsrz.Save(sOutput, pwExportInfo.DataGroup, RsrzFormat.EncryptedJsonWithoutCompression, slLogger);

            return true;
        }
    }
}
