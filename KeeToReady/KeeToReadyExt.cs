using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics.Contracts;

using KeePass.Plugins;
using KeePass.DataExchange;
using System.Drawing;

namespace KeeToReady
{
    public sealed class KeeToReadyExt : Plugin
    {
        private IPluginHost m_host = null;
        private FileFormatProvider provider = null;
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
            Contract.Requires(host != null);

            this.m_host = host;

            provider = new Rsrz();

            host.FileFormatPool.Add(provider);

            return true;
        }

        public override void Terminate()
        {
            if (m_host != null)
            {
                m_host.FileFormatPool.Remove(provider);
            }
        }
    }
}
