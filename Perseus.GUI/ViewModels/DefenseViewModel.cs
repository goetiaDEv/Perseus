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

namespace Perseus.GUI.ViewModels;

public partial class DefenseViewModel : ViewModelBase
{
    [ObservableProperty]
    private DefenseConfiguration _configuration = new();

    [ObservableProperty]
    private string _selectedOperation = "monitor";

    [ObservableProperty]
    private string _output = string.Empty;

    [ObservableProperty]
    private bool _isRunning = false;

    [ObservableProperty]
    private string _status = "Ready";

    [ObservableProperty]
    private ObservableCollection<string> _results = new();

    [ObservableProperty]
    private ObservableCollection<string> _alerts = new();

    public ICommand StartOperationCommand { get; }
    public ICommand StopOperationCommand { get; }
    public ICommand ClearOutputCommand { get; }
    public ICommand SaveResultsCommand { get; }
    public ICommand CreateBaselineCommand { get; }

    public DefenseViewModel()
    {
        StartOperationCommand = new AsyncRelayCommand(StartOperationAsync);
        StopOperationCommand = new RelayCommand(StopOperation);
        ClearOutputCommand = new RelayCommand(ClearOutput);
        SaveResultsCommand = new AsyncRelayCommand(SaveResultsAsync);
        CreateBaselineCommand = new AsyncRelayCommand(CreateBaselineAsync);
    }

    private async Task StartOperationAsync()
    {
        if (IsRunning) return;

        try
        {
            IsRunning = true;
            Status = "Starting operation...";
            ClearOutput();

            switch (SelectedOperation)
            {
                case "monitor":
                    await ExecuteMonitorAsync();
                    break;
                case "baseline":
                    await CreateBaselineAsync();
                    break;
                case "logs":
                    await ExecuteLogAnalysisAsync();
                    break;
                case "hunt":
                    await ExecuteThreatHuntAsync();
                    break;
                case "incident":
                    await ExecuteIncidentResponseAsync();
                    break;
            }

            Status = "Operation completed";
        }
        catch (Exception ex)
        {
            AddOutput($"Error: {ex.Message}");
            Status = "Operation failed";
        }
        finally
        {
            IsRunning = false;
        }
    }

    private async Task ExecuteMonitorAsync()
    {
        Status = "Monitoring network...";
        AddOutput($"Starting network monitoring for: {Configuration.Target}");
        AddOutput($"Interval: {Configuration.MonitorInterval} seconds");

        if (!string.IsNullOrEmpty(Configuration.BaselineFile) && File.Exists(Configuration.BaselineFile))
        {
            AddOutput($"Using baseline: {Configuration.BaselineFile}");
        }

        // Simulate monitoring loop
        var monitoringTask = Task.Run(async () =>
        {
            var discoverer = new HostDiscoverer();
            var iteration = 0;

            while (IsRunning)
            {
                iteration++;
                AddOutput($"Monitoring iteration {iteration}...");

                try
                {
                    var hosts = await discoverer.DiscoverHostsAsync(Configuration.Target, timeout: 3000);
                    AddOutput($"Found {hosts.Count} active hosts");

                    // Simulate anomaly detection
                    if (iteration % 5 == 0) // Every 5th iteration, simulate an alert
                    {
                        var alert = $"ALERT: New device detected at {DateTime.Now:HH:mm:ss}";
                        AddAlert(alert);
                        AddOutput(alert);
                    }

                    await Task.Delay(Configuration.MonitorInterval * 1000);
                }
                catch (Exception ex)
                {
                    AddOutput($"Monitoring error: {ex.Message}");
                }
            }
        });

        await monitoringTask;
    }

    private async Task CreateBaselineAsync()
    {
        Status = "Creating baseline...";
        AddOutput($"Creating network baseline for: {Configuration.Target}");
        AddOutput($"Duration: {Configuration.BaselineDuration} seconds");

        var discoverer = new HostDiscoverer();
        var scanner = new PortScanner();
        var baselineData = new Dictionary<string, object>();

        // Discover hosts
        var hosts = await discoverer.DiscoverHostsAsync(Configuration.Target, timeout: 3000);
        AddOutput($"Baseline: Found {hosts.Count} hosts");

        // Scan common ports for each host
        foreach (var host in hosts.Take(5)) // Limit to first 5 hosts for demo
        {
            AddOutput($"Scanning baseline ports for {host.IpAddress}...");
            var commonPorts = new List<int> { 22, 23, 53, 80, 135, 139, 443, 445, 993, 995 };
            var portResults = await scanner.ScanPortsAsync(host.IpAddress, commonPorts, timeout: 2000, maxConcurrency: 10);
            
            var openPorts = portResults.Where(p => p.State == "Open").Select(p => p.Port).ToList();
            baselineData[host.IpAddress] = new { Hostname = host.Hostname, OpenPorts = openPorts };
            
            AddOutput($"  Open ports: {string.Join(", ", openPorts)}");
        }

        // Save baseline
        var baselineFile = Configuration.BaselineFile ?? $"baseline_{DateTime.Now:yyyyMMdd_HHmmss}.json";
        var json = JsonSerializer.Serialize(baselineData, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(baselineFile, json);

        AddOutput($"Baseline saved to: {baselineFile}");
        Configuration.BaselineFile = baselineFile;
    }

    private async Task ExecuteLogAnalysisAsync()
    {
        Status = "Analyzing logs...";
        AddOutput($"Starting log analysis for: {Configuration.LogFile}");
        AddOutput($"Log type: {Configuration.LogType}");

        if (!File.Exists(Configuration.LogFile))
        {
            AddOutput("Error: Log file not found");
            return;
        }

        try
        {
            var lines = await File.ReadAllLinesAsync(Configuration.LogFile);
            var suspiciousPatterns = new[]
            {
                "failed login", "authentication failed", "access denied",
                "suspicious activity", "malware", "virus", "trojan"
            };

            var alerts = 0;
            foreach (var line in lines.Take(100)) // Analyze first 100 lines for demo
            {
                foreach (var pattern in suspiciousPatterns)
                {
                    if (line.ToLower().Contains(pattern))
                    {
                        AddAlert($"Suspicious log entry: {line.Substring(0, Math.Min(100, line.Length))}...");
                        alerts++;
                        break;
                    }
                }
            }

            AddOutput($"Log analysis completed. Found {alerts} suspicious entries.");
        }
        catch (Exception ex)
        {
            AddOutput($"Error analyzing logs: {ex.Message}");
        }
    }

    private async Task ExecuteThreatHuntAsync()
    {
        Status = "Hunting threats...";
        AddOutput($"Starting threat hunting for: {Configuration.Target}");
        AddOutput($"Threats: {Configuration.Threats}");
        AddOutput($"Deep analysis: {Configuration.DeepAnalysis}");

        var discoverer = new HostDiscoverer();
        var scanner = new PortScanner();

        // Discover hosts
        var hosts = await discoverer.DiscoverHostsAsync(Configuration.Target, timeout: 3000);
        AddOutput($"Scanning {hosts.Count} hosts for threats...");

        foreach (var host in hosts.Take(3)) // Limit for demo
        {
            AddOutput($"Threat hunting on {host.IpAddress}...");

            // Scan for suspicious ports
            var suspiciousPorts = new List<int> { 1234, 4444, 5555, 6666, 31337 }; // Common backdoor ports
            var portResults = await scanner.ScanPortsAsync(host.IpAddress, suspiciousPorts, timeout: 2000, maxConcurrency: 10);

            var openSuspiciousPorts = portResults.Where(p => p.State == "Open").ToList();
            if (openSuspiciousPorts.Any())
            {
                var alert = $"THREAT DETECTED: Suspicious ports open on {host.IpAddress}: {string.Join(", ", openSuspiciousPorts.Select(p => p.Port))}";
                AddAlert(alert);
                AddOutput(alert);
            }

            // Simulate additional threat indicators
            if (Configuration.DeepAnalysis && host.IpAddress.EndsWith(".100"))
            {
                var alert = $"THREAT INDICATOR: Potential C&C communication detected from {host.IpAddress}";
                AddAlert(alert);
                AddOutput(alert);
            }
        }

        AddOutput("Threat hunting completed.");
    }

    private async Task ExecuteIncidentResponseAsync()
    {
        Status = "Responding to incident...";
        AddOutput($"Starting incident response for: {Configuration.Target}");
        AddOutput($"Incident type: {Configuration.IncidentType}");
        AddOutput($"Actions: {Configuration.Actions}");

        var actions = Configuration.Actions.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        foreach (var action in actions)
        {
            AddOutput($"Executing action: {action}");
            
            switch (action.ToLower())
            {
                case "isolate":
                    AddOutput($"  Isolating {Configuration.Target} from network...");
                    await Task.Delay(1000); // Simulate action time
                    AddOutput("  Isolation completed");
                    break;
                
                case "collect":
                    AddOutput($"  Collecting evidence from {Configuration.Target}...");
                    await Task.Delay(2000);
                    AddOutput("  Evidence collection completed");
                    break;
                
                case "analyze":
                    AddOutput($"  Analyzing {Configuration.IncidentType} indicators...");
                    await Task.Delay(1500);
                    AddOutput("  Analysis completed - threat confirmed");
                    break;
                
                default:
                    AddOutput($"  Unknown action: {action}");
                    break;
            }
        }

        AddOutput("Incident response completed.");
    }

    private void StopOperation()
    {
        IsRunning = false;
        Status = "Operation stopped";
        AddOutput("Operation stopped by user.");
    }

    private void ClearOutput()
    {
        Results.Clear();
        Alerts.Clear();
        Output = string.Empty;
    }

    private async Task SaveResultsAsync()
    {
        if (string.IsNullOrEmpty(Configuration.OutputFile))
        {
            Configuration.OutputFile = $"perseus_defense_{DateTime.Now:yyyyMMdd_HHmmss}.json";
        }

        try
        {
            var results = new
            {
                Timestamp = DateTime.Now,
                Configuration = Configuration,
                Operation = SelectedOperation,
                Results = Results.ToList(),
                Alerts = Alerts.ToList()
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

    private void AddAlert(string alert)
    {
        var timestamp = DateTime.Now.ToString("HH:mm:ss");
        var formattedAlert = $"[{timestamp}] {alert}";
        
        Alerts.Add(formattedAlert);
    }
}

