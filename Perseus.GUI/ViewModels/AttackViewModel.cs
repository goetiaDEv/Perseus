using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Perseus.GUI.Models;
using Perseus.Common.Models;
using Perseus.Core.Network;
using Perseus.Core.Vulnerability;

namespace Perseus.GUI.ViewModels;

public partial class AttackViewModel : ViewModelBase
{
    [ObservableProperty]
    private ScanConfiguration _configuration = new();

    [ObservableProperty]
    private string _selectedOperation = "discover";

    [ObservableProperty]
    private string _output = string.Empty;

    [ObservableProperty]
    private bool _isScanning = false;

    [ObservableProperty]
    private string _progress = "Ready";

    [ObservableProperty]
    private ObservableCollection<string> _results = new();

    public ICommand StartScanCommand { get; }
    public ICommand StopScanCommand { get; }
    public ICommand ClearOutputCommand { get; }
    public ICommand SaveResultsCommand { get; }

    public AttackViewModel()
    {
        StartScanCommand = new AsyncRelayCommand(StartScanAsync);
        StopScanCommand = new RelayCommand(StopScan);
        ClearOutputCommand = new RelayCommand(ClearOutput);
        SaveResultsCommand = new AsyncRelayCommand(SaveResultsAsync);
    }

    private async Task StartScanAsync()
    {
        if (IsScanning) return;

        try
        {
            IsScanning = true;
            Progress = "Starting scan...";
            ClearOutput();

            switch (SelectedOperation)
            {
                case "discover":
                    await ExecuteDiscoverAsync();
                    break;
                case "scan":
                    await ExecuteScanAsync();
                    break;
                case "vuln":
                    await ExecuteVulnAsync();
                    break;
                case "full":
                    await ExecuteFullAsync();
                    break;
            }

            Progress = "Scan completed";
        }
        catch (Exception ex)
        {
            AddOutput($"Error: {ex.Message}");
            Progress = "Scan failed";
        }
        finally
        {
            IsScanning = false;
        }
    }

    private async Task ExecuteDiscoverAsync()
    {
        Progress = "Discovering hosts...";
        AddOutput($"Starting host discovery for: {Configuration.Target}");

        var discoverer = new HostDiscoverer();
        var hosts = await discoverer.DiscoverHostsAsync(Configuration.Target, timeout: Configuration.Timeout);

        foreach (var host in hosts)
        {
            AddOutput($"Host found: {host.IpAddress} ({host.Hostname ?? "Unknown"}) - Alive: {host.IsAlive}");
        }

        AddOutput($"Discovery completed. Found {hosts.Count} hosts.");
    }

    private async Task ExecuteScanAsync()
    {
        Progress = "Scanning ports...";
        AddOutput($"Starting port scan for: {Configuration.Target}");
        AddOutput($"Ports: {Configuration.Ports}, Timeout: {Configuration.Timeout}ms, Threads: {Configuration.Threads}");

        var scanner = new PortScanner();
        var portList = ParsePortList(Configuration.Ports);

        var results = await scanner.ScanPortsAsync(Configuration.Target, portList, timeout: Configuration.Timeout, maxConcurrency: Configuration.Threads, grabBanners: Configuration.BannerGrabbing);

        foreach (var result in results)
        {
            AddOutput($"Port {result.Port}/{result.Protocol}: {result.State}");
            if (Configuration.BannerGrabbing && !string.IsNullOrEmpty(result.Banner))
            {
                AddOutput($"  Banner: {result.Banner}");
            }
        }

        AddOutput($"Port scan completed. Found {results.Count(r => r.State == "Open")} open ports.");
    }

    private async Task ExecuteVulnAsync()
    {
        Progress = "Analyzing vulnerabilities...";
        AddOutput($"Starting vulnerability analysis for: {Configuration.Target}");

        var scanner = new PortScanner();
        var portList = ParsePortList(Configuration.Ports);
        var portResults = await scanner.ScanPortsAsync(Configuration.Target, portList, timeout: Configuration.Timeout, maxConcurrency: Configuration.Threads, grabBanners: Configuration.BannerGrabbing);

        var cveChecker = new CveChecker();
        var vulnerabilities = new List<VulnerabilityResult>();

        foreach (var port in portResults.Where(p => p.State == "Open"))
        {
            var services = new List<ServiceResult>
            {
                new ServiceResult
                {
                    Name = port.Service ?? "unknown",
                    Version = port.Version,
                    Port = port.Port,
                    Protocol = port.Protocol
                }
            };
            
            var vulns = await cveChecker.CheckVulnerabilitiesAsync(services, minimumCvssScore: Configuration.MinCvss);
            vulnerabilities.AddRange(vulns);
        }

        foreach (var vuln in vulnerabilities.OrderByDescending(v => v.CvssScore))
        {
            AddOutput($"CVE: {vuln.CveId} - Score: {vuln.CvssScore:F1} - {vuln.Title}");
            AddOutput($"  Service: {vuln.AffectedService} - Severity: {vuln.Severity}");
        }

        AddOutput($"Vulnerability analysis completed. Found {vulnerabilities.Count} vulnerabilities.");
    }

    private async Task ExecuteFullAsync()
    {
        Progress = "Running full assessment...";
        AddOutput($"Starting full assessment for: {Configuration.Target}");

        // Execute all operations in sequence
        await ExecuteDiscoverAsync();
        await ExecuteScanAsync();
        await ExecuteVulnAsync();

        AddOutput("Full assessment completed.");
    }

    private void StopScan()
    {
        // Implementation for stopping scan would go here
        IsScanning = false;
        Progress = "Scan stopped";
        AddOutput("Scan stopped by user.");
    }

    private void ClearOutput()
    {
        Results.Clear();
        Output = string.Empty;
    }

    private async Task SaveResultsAsync()
    {
        if (string.IsNullOrEmpty(Configuration.OutputFile))
        {
            Configuration.OutputFile = $"perseus_results_{DateTime.Now:yyyyMMdd_HHmmss}.json";
        }

        try
        {
            var results = new
            {
                Timestamp = DateTime.Now,
                Configuration = Configuration,
                Operation = SelectedOperation,
                Results = Results.ToList()
            };

            var json = JsonSerializer.Serialize(results, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(Configuration.OutputFile, json);

            AddOutput($"Results saved to: {Configuration.OutputFile}");
        }
        catch (Exception ex)
        {
            AddOutput($"Error saving results: {ex.Message}");
        }
    }

    private void AddOutput(string message)
    {
        var timestamp = DateTime.Now.ToString("HH:mm:ss");
        var formattedMessage = $"[{timestamp}] {message}";
        
        Results.Add(formattedMessage);
        Output += formattedMessage + Environment.NewLine;
    }

    private List<int> ParsePortList(string ports)
    {
        var portList = new List<int>();

        if (string.IsNullOrEmpty(ports))
            return portList;

        var parts = ports.Split(',');
        foreach (var part in parts)
        {
            if (part.Contains('-'))
            {
                var range = part.Split('-');
                if (range.Length == 2 && int.TryParse(range[0], out int start) && int.TryParse(range[1], out int end))
                {
                    for (int i = start; i <= end; i++)
                    {
                        portList.Add(i);
                    }
                }
            }
            else if (int.TryParse(part, out int port))
            {
                portList.Add(port);
            }
        }

        return portList;
    }
}

