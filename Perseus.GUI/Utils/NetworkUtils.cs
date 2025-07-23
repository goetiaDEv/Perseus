using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace Perseus.GUI.Utils;

public static class NetworkUtils
{
    public static List<string> ParseCidrNotation(string cidr)
    {
        var hosts = new List<string>();
        
        try
        {
            var parts = cidr.Split('/');
            if (parts.Length != 2) return hosts;

            var baseIp = IPAddress.Parse(parts[0]);
            var prefixLength = int.Parse(parts[1]);

            var ipBytes = baseIp.GetAddressBytes();
            var hostBits = 32 - prefixLength;
            var hostCount = (int)Math.Pow(2, hostBits);

            var baseAddress = BitConverter.ToUInt32(ipBytes.Reverse().ToArray(), 0);

            for (uint i = 1; i < hostCount - 1; i++) // Skip network and broadcast
            {
                var hostAddress = baseAddress + i;
                var hostBytes = BitConverter.GetBytes(hostAddress).Reverse().ToArray();
                var hostIp = new IPAddress(hostBytes);
                hosts.Add(hostIp.ToString());
            }
        }
        catch
        {
            // Return empty list on error
        }

        return hosts;
    }

    public static List<string> ParseIpRange(string range)
    {
        var hosts = new List<string>();
        
        try
        {
            var parts = range.Split('-');
            if (parts.Length != 2) return hosts;

            var startIp = IPAddress.Parse(parts[0].Trim());
            var endPart = parts[1].Trim();

            // Handle cases like "192.168.1.1-254" or "192.168.1.1-192.168.1.254"
            IPAddress endIp;
            if (endPart.Contains('.'))
            {
                endIp = IPAddress.Parse(endPart);
            }
            else
            {
                var startBytes = startIp.GetAddressBytes();
                startBytes[3] = byte.Parse(endPart);
                endIp = new IPAddress(startBytes);
            }

            var startIpBytes = startIp.GetAddressBytes();
            var endBytes = endIp.GetAddressBytes();

            var start = BitConverter.ToUInt32(startIpBytes.Reverse().ToArray(), 0);
            var end = BitConverter.ToUInt32(endBytes.Reverse().ToArray(), 0);

            for (uint i = start; i <= end; i++)
            {
                var hostBytes = BitConverter.GetBytes(i).Reverse().ToArray();
                var hostIp = new IPAddress(hostBytes);
                hosts.Add(hostIp.ToString());
            }
        }
        catch
        {
            // Return empty list on error
        }

        return hosts;
    }
}

