using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KeeToReady
{
    public enum FieldType : Int16
    {
        Username = 0, Password, DoB,
        WebsiteURL, eMailAddress, AccountName, AccountNumber, CardNumber, CVC, PIN, SSN,
        ComputerName, NetworkDomain, ServerHost, IPAddress,
        PostalAddress, PhoneNumber,
        PassportNumber,
        //Combination, MemberID, PolicyID, RxNumber, SerialNumber, ActivationCode, LicensePlate, VIN,
        Note, GenericText, GenericNumber, GenericDate,
        Gender, Segment, ReadyIdPublicKey, ReadyIdPrivateKey, // These are for identities
        BundleID
        // Must update count when adding new field types.
    }

    public class RsoField
    {
        public int type;
        public int displayOrder;
        public string label;
        public int isSensitive;        //  1 means "is"; 0 means "is not".
        public double? dateValue;      //This is timeIntervalSince1970 of NSTimeInterval type on iOS. Refer to this link on how to calculate the dateValue of a given .NET DateTime object http://stackoverflow.com/questions/3354893/how-can-i-convert-a-datetime-to-the-number-of-seconds-since-1970
        public decimal? numberValue;
        public string stringValue;
    }
}
