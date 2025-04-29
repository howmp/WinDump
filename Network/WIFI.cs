using System;
using System.Collections.Generic;
using System.Data;
using System.Runtime.InteropServices;
using System.Text;
using System.Xml;

namespace WinDump
{
    internal class WIFI
    {
        internal static DataTable GetWIFI()
        {
            DataTable dt = new DataTable();
            dt.Columns.Add("SSID");
            dt.Columns.Add("Pwd");
            const int dwClientVersion = 2;
            IntPtr clientHandle = IntPtr.Zero;
            IntPtr pdwNegotiatedVersion = IntPtr.Zero;
            IntPtr pInterfaceList = IntPtr.Zero;
            WLAN_INTERFACE_INFO_LIST interfaceList;
            WLAN_PROFILE_INFO_LIST wifiProfileList;
            Guid InterfaceGuid;
            IntPtr pAvailableNetworkList = IntPtr.Zero;
            string wifiXmlProfile = null;
            IntPtr wlanAccess = IntPtr.Zero;
            IntPtr profileList = IntPtr.Zero;
            string profileName = "";
            try
            {
                // Open Wifi Handle
                WlanOpenHandle(dwClientVersion, IntPtr.Zero, out pdwNegotiatedVersion, ref clientHandle);

                WlanEnumInterfaces(clientHandle, IntPtr.Zero, ref pInterfaceList);
                interfaceList = new WLAN_INTERFACE_INFO_LIST(pInterfaceList);
                InterfaceGuid = interfaceList.InterfaceInfo[0].InterfaceGuid;
                WlanGetProfileList(clientHandle, InterfaceGuid, IntPtr.Zero, ref profileList);
                wifiProfileList = new WLAN_PROFILE_INFO_LIST(profileList);
                if (wifiProfileList.dwNumberOfItems <= 0) return null;


                for (int i = 0; i < wifiProfileList.dwNumberOfItems; i++)
                {
                    try
                    {
                        profileName = (wifiProfileList.ProfileInfo[i]).strProfileName;
                        int decryptKey = 63;
                        WlanGetProfile(clientHandle, InterfaceGuid, profileName, IntPtr.Zero, out wifiXmlProfile, ref decryptKey, out wlanAccess);
                        XmlDocument xmlProfileXml = new XmlDocument();
                        xmlProfileXml.LoadXml(wifiXmlProfile);
                        XmlNodeList pathToSSID = xmlProfileXml.SelectNodes("//*[name()='WLANProfile']/*[name()='SSIDConfig']/*[name()='SSID']/*[name()='name']");
                        XmlNodeList pathToPassword = xmlProfileXml.SelectNodes("//*[name()='WLANProfile']/*[name()='MSM']/*[name()='security']/*[name()='sharedKey']/*[name()='keyMaterial']");
                        foreach (XmlNode ssid in pathToSSID)
                        {

                            foreach (XmlNode password in pathToPassword)
                            {
                                dt.Rows.Add(ssid.InnerText, password.InnerText);

                            }

                        }
                    }
                    catch
                    {
                    }
                }
                WlanCloseHandle(clientHandle, IntPtr.Zero);
            }
            catch { }
            return dt;
        }
        [DllImport("Wlanapi.dll")]
        public static extern int WlanOpenHandle(int dwClientVersion, IntPtr pReserved, [Out] out IntPtr pdwNegotiatedVersion, ref IntPtr ClientHandle);

        [DllImport("Wlanapi", EntryPoint = "WlanCloseHandle")]
        public static extern uint WlanCloseHandle([In] IntPtr hClientHandle, IntPtr pReserved);


        [DllImport("Wlanapi", EntryPoint = "WlanEnumInterfaces")]
        public static extern uint WlanEnumInterfaces([In] IntPtr hClientHandle, IntPtr pReserved, ref IntPtr ppInterfaceList);


        [DllImport("wlanapi.dll", SetLastError = true)]
        public static extern uint WlanGetProfile([In] IntPtr clientHandle, [In, MarshalAs(UnmanagedType.LPStruct)] Guid interfaceGuid, [In, MarshalAs(UnmanagedType.LPWStr)] string profileName, [In] IntPtr pReserved, [Out, MarshalAs(UnmanagedType.LPWStr)] out string profileXml, [In, Out, Optional] ref int flags, [Out, Optional] out IntPtr pdwGrantedAccess);

        [DllImport("wlanapi.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
        public static extern uint WlanGetProfileList([In] IntPtr clientHandle, [In, MarshalAs(UnmanagedType.LPStruct)] Guid interfaceGuid, [In] IntPtr pReserved, ref IntPtr profileList);
        [StructLayout(LayoutKind.Sequential)]
        public struct WLAN_INTERFACE_INFO_LIST
        {

            public int dwNumberofItems;
            public int dwIndex;
            public WLAN_INTERFACE_INFO[] InterfaceInfo;


            public WLAN_INTERFACE_INFO_LIST(IntPtr pList)
            {
                dwNumberofItems = (int)Marshal.ReadInt64(pList, 0);
                dwIndex = (int)Marshal.ReadInt64(pList, 4);
                InterfaceInfo = new WLAN_INTERFACE_INFO[dwNumberofItems];
                for (int i = 0; i < dwNumberofItems; i++)
                {
                    IntPtr pItemList = new IntPtr(pList.ToInt64() + (i * 532) + 8);
                    WLAN_INTERFACE_INFO wii = new WLAN_INTERFACE_INFO();
                    wii = (WLAN_INTERFACE_INFO)Marshal.PtrToStructure(pItemList, typeof(WLAN_INTERFACE_INFO));
                    InterfaceInfo[i] = wii;
                }
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WLAN_INTERFACE_INFO
        {
            public Guid InterfaceGuid;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string strInterfaceDescription;

        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WLAN_PROFILE_INFO
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string strProfileName;
            public WlanProfileFlags ProfileFLags;
        }

        [Flags]
        public enum WlanProfileFlags
        {
            AllUser = 0,
            GroupPolicy = 1,
            User = 2
        }

        public struct WLAN_PROFILE_INFO_LIST
        {
            public int dwNumberOfItems;
            public int dwIndex;
            public WLAN_PROFILE_INFO[] ProfileInfo;

            public WLAN_PROFILE_INFO_LIST(IntPtr ppProfileList)
            {
                dwNumberOfItems = (int)Marshal.ReadInt64(ppProfileList);
                dwIndex = (int)Marshal.ReadInt64(ppProfileList, 4);
                ProfileInfo = new WLAN_PROFILE_INFO[dwNumberOfItems];
                IntPtr ppProfileListTemp = new IntPtr(ppProfileList.ToInt64() + 8);

                for (int i = 0; i < dwNumberOfItems; i++)
                {
                    ppProfileList = new IntPtr(ppProfileListTemp.ToInt64() + i * Marshal.SizeOf(typeof(WLAN_PROFILE_INFO)));
                    ProfileInfo[i] = (WLAN_PROFILE_INFO)Marshal.PtrToStructure(ppProfileList, typeof(WLAN_PROFILE_INFO));
                }
            }
        }
    }
}
