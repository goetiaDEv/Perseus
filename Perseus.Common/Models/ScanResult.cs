using System;
using System.Collections.Generic;

namespace Perseus.Common.Models
{
    public class ScanResult
    {
        public string Target { get; set; } = string.Empty;
        public DateTime ScanTime { get; set; }
        public ScanType Type { get; set; }
        public List<HostResult> Hosts { get; set; } = new();
        public List<VulnerabilityResult> Vulnerabilities { get; set; } = new();
        public ScanStatus Status { get; set; }
        public string? ErrorMessage { get; set; }
    }

    public class HostResult
    {
        public string IpAddress { get; set; } = string.Empty;
        public string? Hostname { get; set; }
        public bool IsAlive { get; set; }
        public List<PortResult> OpenPorts { get; set; } = new();
        public List<ServiceResult> Services { get; set; } = new();
        public string? OperatingSystem { get; set; }
    }

    public class PortResult
    {
        public int Port { get; set; }
        public string Protocol { get; set; } = "TCP";
        public string State { get; set; } = "Open";
        public string? Service { get; set; }
        public string? Version { get; set; }
        public string? Banner { get; set; }
    }

    public class ServiceResult
    {
        public string Name { get; set; } = string.Empty;
        public string? Version { get; set; }
        public int Port { get; set; }
        public string Protocol { get; set; } = "TCP";
        public Dictionary<string, string> Details { get; set; } = new();
    }

    public class VulnerabilityResult
    {
        public string CveId { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public double CvssScore { get; set; }
        public string Severity { get; set; } = string.Empty;
        public string AffectedService { get; set; } = string.Empty;
        public string? Solution { get; set; }
        public List<string> References { get; set; } = new();
        public bool IsExploitable { get; set; }
    }

    public enum ScanType
    {
        HostDiscovery,
        PortScan,
        ServiceEnumeration,
        VulnerabilityAssessment,
        NetworkMonitoring,
        LogAnalysis
    }

    public enum ScanStatus
    {
        NotStarted,
        Running,
        Completed,
        Failed,
        Cancelled
    }
}

