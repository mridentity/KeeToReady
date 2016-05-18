using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using KeePass.DataExchange;

namespace KeeToReady
{
    internal sealed class RsrzProvider : FileFormatProvider
    {
        public override bool SupportsImport { get { return false; } }
        public override bool SupportsExport { get { return true; } }
        public override string FormatName
        {
            get
            {
                throw new NotImplementedException();
            }
        }
    }
}
