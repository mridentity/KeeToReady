
using KeePass.DataExchange;
using KeePass.Plugins;
using System.Drawing;

namespace KeeToReady
{
    public sealed class KeeToReadyExt : Plugin
    {
        private IPluginHost m_host = null;
        private FileFormatProvider encryptionProvider = null;
        private FileFormatProvider compressionProvider = null;
        private FileFormatProvider encryptWithNewPasswordProvider = null;

        public override Image SmallIcon
        {
            get { return Properties.Resources.B16x16_KeePassPlus; }
        }

        public override string UpdateUrl
        {
            get { return "https://github.com/mridentity/KeeToReady/tree/master/KeeToReady/plugin.version"; }
        }

        public override bool Initialize(IPluginHost host)
        {
            if (host == null) return false;

            this.m_host = host;

            host.FileFormatPool.Add(encryptionProvider = new EncryptedProvider());
            host.FileFormatPool.Add(encryptWithNewPasswordProvider = new EncryptWithNewPasswordProvider());
            host.FileFormatPool.Add(compressionProvider = new CompressedProvider());

            return true;
        }

        public override void Terminate()
        {
            if (m_host != null)
            {
                m_host.FileFormatPool.Remove(encryptionProvider);
                m_host.FileFormatPool.Remove(compressionProvider);
                m_host.FileFormatPool.Remove(encryptWithNewPasswordProvider);
            }
        }
    }
}
