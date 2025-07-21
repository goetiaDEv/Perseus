namespace Perseus.Common.Models
{
    public enum OperationMode
    {
        Attack,
        Defense
    }

    public class OperationConfig
    {
        public OperationMode Mode { get; set; }
        public string Target { get; set; } = string.Empty;
        public List<string> Targets { get; set; } = new();
        public Dictionary<string, object> Parameters { get; set; } = new();
        public bool StealthMode { get; set; } = false;
        public int ThreadCount { get; set; } = 10;
        public int Timeout { get; set; } = 5000;
        public string? OutputPath { get; set; }
        public List<string> ExcludedTargets { get; set; } = new();
    }

    public class AttackConfig : OperationConfig
    {
        public bool EnableSubdomainEnum { get; set; } = true;
        public bool EnableVulnScan { get; set; } = true;
        public bool EnableExploitation { get; set; } = false;
        public List<string> PortRanges { get; set; } = new() { "1-1000" };
        public bool UseExternalTools { get; set; } = true;
        public string? ProxyUrl { get; set; }
    }

    public class DefenseConfig : OperationConfig
    {
        public bool EnableNetworkMonitoring { get; set; } = true;
        public bool EnableLogAnalysis { get; set; } = true;
        public bool EnableAnomalyDetection { get; set; } = true;
        public List<string> LogSources { get; set; } = new();
        public int MonitoringInterval { get; set; } = 60; // seconds
        public List<string> AlertRules { get; set; } = new();
    }
}

