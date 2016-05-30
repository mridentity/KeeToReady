namespace KeeToReady
{
    public enum CategoryType
    {
        Generic = 0, Website, Card, App, Smartphone, Email, Computer, Network, Identity, Encryption, Certificate, Membership, Note, Vehicle
    }

    public class RsoRecord
    {
        public int categoryType;
        public string name;
        public string desc;
        public string cloudID;
        public int asTempalte;     //  1 means a regular record that can also be used as a template; 0 means regular record.
        public int isTemplate;     //  1 means is a template that cannot be used as a regular record; it must be zero for the asTemplate to be relevant.
        public string logoImage;   //  A base64 encoded JPEG or PNG image.  
        public RsoField[] fields;
        public double lastUpdated; //  This is timeIntervalSinceReferenceDate of NSTimeInterval type on iOS.
    }
}
