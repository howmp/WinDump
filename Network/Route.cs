using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Runtime.InteropServices;
using System.Text;

namespace WinDump
{

    internal class Routing
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_IPFORWARDROW
        {
            [MarshalAs(UnmanagedType.U4)]
            public uint dwForwardDest; // IP addr of destination
            [MarshalAs(UnmanagedType.U4)]
            public uint dwForwardMask; // subnetwork mask of destination
            [MarshalAs(UnmanagedType.U4)]
            public int dwForwardPolicy; // conditions for multi-path route
            [MarshalAs(UnmanagedType.U4)]
            public uint dwForwardNextHop; // IP address of next hop
            [MarshalAs(UnmanagedType.U4)]
            public int dwForwardIfIndex; // index of interface
            [MarshalAs(UnmanagedType.U4)]
            public int dwForwardType; // route type
            [MarshalAs(UnmanagedType.U4)]
            public int dwForwardProto; // protocol that generated route
            [MarshalAs(UnmanagedType.U4)]
            public int dwForwardAge; // age of route
            [MarshalAs(UnmanagedType.U4)]
            public int dwForwardNextHopAS; // autonomous system number
            [MarshalAs(UnmanagedType.U4)]
            public int dwForwardMetric1; // protocol-specific metric
            [MarshalAs(UnmanagedType.U4)]
            public int dwForwardMetric2; // protocol-specific metric
            [MarshalAs(UnmanagedType.U4)]
            public int dwForwardMetric3; // protocol-specific metric
            [MarshalAs(UnmanagedType.U4)]
            public int dwForwardMetric4; // protocol-specific metric
            [MarshalAs(UnmanagedType.U4)]
            public int dwForwardMetric5; // protocol-specific metric            
            public System.Net.IPAddress ForwardDest
            {
                get
                {
                    return new System.Net.IPAddress(dwForwardDest);
                }
            }
            public System.Net.IPAddress ForwardNextHop
            {
                get
                {
                    return new System.Net.IPAddress(dwForwardNextHop);
                }
            }
            public System.Net.IPAddress ForwardMask
            {
                get
                {
                    return new System.Net.IPAddress(dwForwardMask);
                }
            }
        }

        [DllImport("IpHlpApi.dll")]
        [return: MarshalAs(UnmanagedType.U4)]
        static extern int GetIpForwardTable(IntPtr pIpForwardTable, [MarshalAs(UnmanagedType.U4)] ref int pdwSize, bool bOrder);
        const int ERROR_INSUFFICIENT_BUFFER = 122;

        internal static DataTable GetRoute()
        {
            var dataTable = new DataTable();
            // The number of bytes needed.
            int bytesNeeded = 0;
            // The result from the API call.
            int result = GetIpForwardTable(IntPtr.Zero, ref bytesNeeded, false);

            // Call the function, expecting an insufficient buffer.
            if (result != ERROR_INSUFFICIENT_BUFFER)
            {
                // Throw an exception.
                throw new Win32Exception(result);
            }

            // Allocate the memory, do it in a try/finally block, to ensure
            // that it is released.
            IntPtr buffer = IntPtr.Zero;

            try
            {
                // Allocate the memory.
                buffer = Marshal.AllocCoTaskMem(bytesNeeded);

                // Make the call again.  If it did not succeed, then
                // raise an error.
                result = GetIpForwardTable(buffer, ref bytesNeeded, false);

                // If the result is not 0 (no error), then throw an exception.
                if (result != 0)
                {
                    // Throw an exception.
                    throw new Win32Exception(result);
                }

                // Now we have the buffer, we have to marshal it.  We can read
                // the first 4 bytes to get the length of the buffer.
                int entries = Marshal.ReadInt32(buffer);

                // Increment the memory pointer by the size of the int.
                IntPtr currentBuffer = new IntPtr(buffer.ToInt64() + Marshal.SizeOf(new int()));

                // Allocate an array of entries.
                ;
                dataTable.Columns.Add("ForwardDest");
                dataTable.Columns.Add("ForwardMask");
                dataTable.Columns.Add("ForwardNextHop");
                dataTable.Columns.Add("ForwardIfIndex");
                
                // Cycle through the entries.
                for (int index = 0; index < entries; index++)
                {
                    // Call PtrToStructure, getting the structure information.
                    MIB_IPFORWARDROW table = (MIB_IPFORWARDROW)Marshal.PtrToStructure(new
                    IntPtr(currentBuffer.ToInt64() + (index *
                            Marshal.SizeOf(typeof(MIB_IPFORWARDROW)))), typeof(MIB_IPFORWARDROW));
                    dataTable.Rows.Add(table.ForwardDest, table.ForwardMask, table.ForwardNextHop,table.dwForwardIfIndex);
                }

            }
            finally
            {
                // Release the memory.
                Marshal.FreeCoTaskMem(buffer);
            }
            return dataTable;
        }

    }
}
