using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Runtime.InteropServices;
using System.Text;

namespace WinDump
{
  
    class DNSCache
    {
        internal static Dictionary<int,string> DnsTypes = new Dictionary<int, string> {
            {0x1,"A"},
            {0x2,"NS"},
            {0x3,"MD"},
            {0x4,"MF"},
            {0x5,"CNAME"},
            {0x6,"SOA"},
            {0x7,"MB"},
            {0x8,"MG"},
            {0x9,"MR"},
            {0xA,"NULL"},
            {0xB,"WKS"},
            {0xC,"PTR"},
            {0xD,"HINFO"},
            {0xE,"MINFO"},
            {0xF,"MX"},
            {0x10,"TEXT"},
            {0x11,"RP"},
            {0x12,"AFSDB"},
            {0x13,"X25"},
            {0x14,"ISDN"},
            {0x15,"RT"},
            {0x16,"NSAP"},
            {0x17,"NSAPPTR"},
            {0x18,"SIG"},
            {0x19,"KEY"},
            {0x1A,"PX"},
            {0x1B,"GPOS"},
            {0x1C,"AAAA"},
            {0x1D,"LOC"},
            {0x1E,"NXT"},
            {0x1F,"EID"},
            {0x20,"NIMLOC"},
            {0x21,"SRV"},
            {0x22,"ATMA"},
            {0x23,"NAPTR"},
            {0x24,"KX"},
            {0x25,"CERT"},
            {0x26,"A6"},
            {0x27,"DNAME"},
            {0x28,"SINK"},
            {0x29,"OPT"},
            {0x2B,"DS"},
            {0x2E,"RRSIG"},
            {0x2F,"NSEC"},
            {0x30,"DNSKEY"},
            {0x31,"DHCID"},
            {0x64,"UINFO"},
            {0x65,"UID"},
            {0x66,"GID"},
            {0x67,"UNSPEC"},
            {0xF8,"ADDRS"},
            {0xF9,"TKEY"},
            {0xFA,"TSIG"},
            {0xFB,"IXFR"},
            {0xFC,"AFXR"},
            {0xFD,"MAILB"},
            {0xFE,"MAILA"},
            {0xFF,"ALL"},
            {0xFF01,"WINS"},
            {0xFF02,"WINSR"},
        };
        internal static DataTable GetDNSCache()
        {
            try
            {
                var dt = Utils.Query("Select  Name, Type, TimeToLive, Data From MSFT_DNSClientCache WHERE Status = 0", Utils.StandardCimv2);
                foreach (DataRow row in dt.Rows)
                {
                    try
                    {
                        var typ = DnsTypes[Convert.ToInt32(row["Type"])];
                        row["Type"] = typ.ToString();
                    }
                    catch
                    {

                    }
                }
                return dt;
            }
            catch { }
            return null;
            
        }

    }
}
