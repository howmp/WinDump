using System;
using System.Collections.Generic;
using System.Data;
using System.Net;
using System.Text;

namespace WinDump
{
    class Interface
    {
        internal static DataTable GetInterface()
        {
            return Utils.Query("Select Description,InterfaceIndex,IPAddress,IPSubnet,MACAddress,DHCPServer,DNSServerSearchOrder FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=true");
        }
        internal static string GetIP()
        {

            var ips = Dns.GetHostAddresses(Dns.GetHostName());
            foreach (var ip in ips) {
                if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) { 
                    return ip.ToString();
                }
            }
            
            return "";
        }

    }
}
