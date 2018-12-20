If (-not ([System.Management.Automation.PSTypeName]'ADSiteFinder').Type)
{
Add-Type -Language CSharp -TypeDefinition `
@" 
using System;
using System.Net.Sockets;
using System.Runtime.InteropServices;

public class ADSiteFinder
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct ADDRINFOW
    {
        internal int ai_flags;
        internal int ai_family;
        internal int ai_socktype;
        internal int ai_protocol;
        internal uint ai_addrlen;
        internal string ai_canonname;
        internal IntPtr ai_addr;
        internal IntPtr ai_next;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SOCKET_ADDRESS
    {
        public IntPtr lpSockaddr;
        public int iSockaddrLength;
    }

    [DllImport("ws2_32.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
    extern static int GetAddrInfoW(string pNodeName, string pServiceName, IntPtr pHints, out IntPtr ppResult);

    [DllImport("ws2_32.dll", CallingConvention = CallingConvention.StdCall)]
    extern static void FreeAddrInfoW(IntPtr Buffer);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
    extern static int DsAddressToSiteNamesW(string ComputerName, uint EntryCount, [In] SOCKET_ADDRESS[] SocketAddresses, out IntPtr SiteNames);

    [DllImport("netapi32.dll")]
    extern static uint NetApiBufferFree(IntPtr Buffer);

    public static string GetSiteFromHost(string sHostName, string sDomainController)
    {
        // sanity check also initializes socket library
        if (!Socket.OSSupportsIPv4 && !Socket.OSSupportsIPv6) return null;

        // fetch the the address information
        IntPtr pAddressInfo;
        if (GetAddrInfoW(sHostName, null, IntPtr.Zero, out pAddressInfo) != 0)
        {
            return null;
        }

        // translate to a managed structure and free
        ADDRINFOW tAdressInfo = (ADDRINFOW)Marshal.PtrToStructure(pAddressInfo, typeof(ADDRINFOW));

        // point to our structure 
        SOCKET_ADDRESS[] tAddressArray = new SOCKET_ADDRESS[1];
        tAddressArray[0].lpSockaddr = tAdressInfo.ai_addr;
        tAddressArray[0].iSockaddrLength = (int)tAdressInfo.ai_addrlen;

        // query the domain controller for the site name
        IntPtr pStringArray;
        string sSiteName = null;
        if (DsAddressToSiteNamesW(sDomainController, 1, tAddressArray, out pStringArray) == 0)
        {
            IntPtr[] pIntPtrArray = new IntPtr[1];
            Marshal.Copy(pStringArray, pIntPtrArray, 0, 1);
            sSiteName = Marshal.PtrToStringUni(pIntPtrArray[0]);
            NetApiBufferFree(pStringArray);
        }

        // cleanup
        FreeAddrInfoW(pAddressInfo);
        return sSiteName;
    }
}
"@ 
}

Import-Module ActiveDirectory

<#
.SYNOPSIS

This function returns the Active Directory site for a given computer.

.PARAMETER ComputerName

The -ComputerName parameter specifies the computer to lookup.  This defaults
to the local computer name if not specified.

.PARAMETER DomainController

The -DomainController specifies the domain controller to use as part of the 
lookup.  This will default to the nearest domain controller if not specified.
If you are looking up thousands of records and performance is a concern, it 
is recommended to pass this parameter to speed up lookups.

.EXAMPLE

Get-ADSiteFromComputer -ComputerName 'SERVER' 
#>
Function Get-ADSiteFromComputer
{
    [CmdletBinding()]
    Param(
        [parameter(ValueFromPipeline)] $ComputerName = [Environment]::MachineName,
        [string] $DomainController = (Get-ADDomainController -Service GlobalCatalog -NextClosestSite -Discover).HostName[-1]
    )

    Process
    {
        # handle output from Get-ADComputer
        If ($ComputerName -is [Microsoft.ActiveDirectory.Management.ADComputer])
        {
            # grab the host name from the active directory object
            $ComputerName = $ComputerName.DnsHostName
        }

        [ADSiteFinder]::GetSiteFromHost($ComputerName, $DomainController)
    }
}
