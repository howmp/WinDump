using System;
using System.Collections.Generic;
using System.Data;
using System.Runtime.InteropServices;
using System.Text;

namespace WinDump
{
    class User
    {
        internal static DataTable GetUser()
        {
            return Utils.Query("SELECT Name,SID,Status,Domain,LocalAccount FROM Win32_Account Where SIDType=1");
        }
    }
    class QUser
    {
        [DllImport("wtsapi32.dll")]
        static extern IntPtr WTSOpenServer([MarshalAs(UnmanagedType.LPStr)] string pServerName);

        [DllImport("wtsapi32.dll")]
        static extern void WTSCloseServer(IntPtr hServer);

        [DllImport("wtsapi32.dll")]
        static extern Int32 WTSEnumerateSessions(IntPtr hServer,
                                                 [MarshalAs(UnmanagedType.U4)] Int32 Reserved,
                                                 [MarshalAs(UnmanagedType.U4)] Int32 Version,
                                                 ref IntPtr ppSessionInfo,
                                                 [MarshalAs(UnmanagedType.U4)] ref Int32 pCount);

        [DllImport("wtsapi32.dll")]
        static extern void WTSFreeMemory(IntPtr pMemory);

        [DllImport("wtsapi32.dll")]
        static extern bool WTSQuerySessionInformation(IntPtr hServer,
                                                      int sessionId,
                                                      WTS_INFO_CLASS wtsInfoClass,
                                                      out IntPtr ppBuffer,
                                                      out uint pBytesReturned);

        [StructLayout(LayoutKind.Sequential)]
        private struct WTS_SESSION_INFO
        {
            public Int32 SessionID;
            [MarshalAs(UnmanagedType.LPStr)]
            public string pWinStationName;
            public WTS_CONNECTSTATE_CLASS State;
        }
        //https://social.technet.microsoft.com/Forums/windowsserver/en-US/cbfd802c-5add-49f3-b020-c901f1a8d3f4/retrieve-user-logontime-on-terminal-service-with-remote-desktop-services-api
        //https://docs.microsoft.com/en-us/windows/win32/api/wtsapi32/ns-wtsapi32-wtsinfoa
        [StructLayout(LayoutKind.Sequential)]
        public struct WTSINFOA
        {
            public const int WINSTATIONNAME_LENGTH = 32;
            public const int DOMAIN_LENGTH = 17;
            public const int USERNAME_LENGTH = 20;
            WTS_CONNECTSTATE_CLASS State;
            public int SessionId;
            public int IncomingBytes;
            public int OutgoingBytes;
            public int IncomingFrames;
            public int OutgoingFrames;
            public int IncomingCompressedBytes;
            public int OutgoingCompressedBytes;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = WINSTATIONNAME_LENGTH)]
            byte[] WinStationNameRaw;
            public string WinStationName
            {
                get
                {
                    return Encoding.ASCII.GetString(WinStationNameRaw);
                }
            }
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = DOMAIN_LENGTH)]
            public byte[] DomainRaw;
            public string Domain
            {
                get
                {
                    return Encoding.ASCII.GetString(DomainRaw);
                }
            }
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = USERNAME_LENGTH + 1)]
            public byte[] UserNameRaw;
            public string UserName
            {
                get
                {
                    return Encoding.ASCII.GetString(UserNameRaw);
                }
            }
            public long ConnectTimeUTC;
            public DateTime ConnectTime
            {
                get
                {
                    return DateTime.FromFileTimeUtc(ConnectTimeUTC);
                }
            }
            public long DisconnectTimeUTC;
            public DateTime DisconnectTime
            {
                get
                {
                    return DateTime.FromFileTimeUtc(DisconnectTimeUTC);
                }
            }
            public long LastInputTimeUTC;
            public DateTime LastInputTime
            {
                get
                {
                    return DateTime.FromFileTimeUtc(LastInputTimeUTC);
                }
            }
            public long LogonTimeUTC;
            public DateTime LogonTime
            {
                get
                {
                    return DateTime.FromFileTimeUtc(LogonTimeUTC);
                }
            }
            public long CurrentTimeUTC;
            public DateTime CurrentTime
            {
                get
                {
                    return DateTime.FromFileTimeUtc(CurrentTimeUTC);
                }
            }
        }
        public enum WTS_INFO_CLASS
        {
            WTSInitialProgram,
            WTSApplicationName,
            WTSWorkingDirectory,
            WTSOEMId,
            WTSSessionId,
            WTSUserName,
            WTSWinStationName,
            WTSDomainName,
            WTSConnectState,
            WTSClientBuildNumber,
            WTSClientName,
            WTSClientDirectory,
            WTSClientProductId,
            WTSClientHardwareId,
            WTSClientAddress,
            WTSClientDisplay,
            WTSClientProtocolType,
            WTSIdleTime,
            WTSLogonTime,
            WTSIncomingBytes,
            WTSOutgoingBytes,
            WTSIncomingFrames,
            WTSOutgoingFrames,
            WTSClientInfo,
            WTSSessionInfo
        }

        public enum WTS_CONNECTSTATE_CLASS
        {
            Active,
            Connected,
            ConnectQuery,
            Shadow,
            Disconnected,
            Idle,
            Listen,
            Reset,
            Down,
            Init
        }
        //https://stackoverflow.com/questions/32522545/retrieve-user-logontime-on-terminal-service-with-remote-desktop-services-api
        //https://social.technet.microsoft.com/Forums/windowsserver/en-US/cbfd802c-5add-49f3-b020-c901f1a8d3f4/retrieve-user-logontime-on-terminal-service-with-remote-desktop-services-api
        internal static DataTable GetQUser()
        {
            IntPtr serverHandle = WTSOpenServer("");
            var dt = new DataTable();
            dt.Columns.Add("UserName");
            dt.Columns.Add("Domain");
            dt.Columns.Add("WinStationName");
            dt.Columns.Add("SessionID");
            dt.Columns.Add("State");
            dt.Columns.Add("Idle");
            dt.Columns.Add("LoginTime");
            try
            {
                IntPtr sessionInfoPtr = IntPtr.Zero;
                IntPtr userPtr = IntPtr.Zero;
                IntPtr domainPtr = IntPtr.Zero;
                IntPtr wtsinfoPtr = IntPtr.Zero;
                Int32 sessionCount = 0;
                //https://docs.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsenumeratesessionsa
                //Retrieves a list of sessions on a Remote Desktop Session Host (RD Session Host) server.
                Int32 retVal = WTSEnumerateSessions(serverHandle, 0, 1, ref sessionInfoPtr, ref sessionCount);
                Int32 dataSize = Marshal.SizeOf(typeof(WTS_SESSION_INFO));
                IntPtr currentSession = sessionInfoPtr;
                uint bytes = 0;


                if (retVal != 0)
                {
                    //collect sessions - may contain duplicates
                    for (int i = 0; i < sessionCount; i++)
                    {
                        WTS_SESSION_INFO si = (WTS_SESSION_INFO)Marshal.PtrToStructure(currentSession, typeof(WTS_SESSION_INFO));
                        currentSession = new IntPtr(currentSession.ToInt64() + dataSize);

                        WTSQuerySessionInformation(serverHandle, si.SessionID, WTS_INFO_CLASS.WTSUserName, out userPtr, out bytes);
                        WTSQuerySessionInformation(serverHandle, si.SessionID, WTS_INFO_CLASS.WTSDomainName, out domainPtr, out bytes);
                        WTSQuerySessionInformation(serverHandle, si.SessionID, WTS_INFO_CLASS.WTSSessionInfo, out wtsinfoPtr, out bytes);

                        string domain = Marshal.PtrToStringAnsi(domainPtr);
                        string username = Marshal.PtrToStringAnsi(userPtr);

                        var wtsinfo = (WTSINFOA)Marshal.PtrToStructure(wtsinfoPtr, typeof(WTSINFOA));

                        //if username is not null
                        if (!String.IsNullOrEmpty(Marshal.PtrToStringAnsi(userPtr)))
                        {
                            var idle = wtsinfo.LastInputTimeUTC == 0 ? "none" : wtsinfo.LastInputTime.ToString();
                            dt.Rows.Add(
                            username,
                            domain,
                            si.pWinStationName,
                            si.SessionID,
                            si.State.ToString(),
                            idle,
                            wtsinfo.LogonTime
                          );
                        }
                        WTSFreeMemory(userPtr);
                        WTSFreeMemory(domainPtr);
                        WTSFreeMemory(wtsinfoPtr);
                    }

                    WTSFreeMemory(sessionInfoPtr);

                }

            }
            finally
            {
                WTSCloseServer(serverHandle);

            }

            return dt;
        }
    }

}
