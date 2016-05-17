using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using KeePass.Plugins;

namespace KeeToReady
{
    public sealed class KeeToReadyExt : Plugin
    {
        private IPluginHost m_host = null;

        public override bool Initialize(IPluginHost host)
        {
            m_host = host;
            return true;
        }

        public override void Terminate()
        {
        }
    }
}
