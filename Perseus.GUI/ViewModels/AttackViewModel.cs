using Microsoft.Extensions.Logging;
using Perseus.Common.Models;
using Perseus.Core.Network;
using Perseus.Core.Vulnerability;
using Perseus.GUI.Utils;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;

namespace Perseus.GUI.ViewModels;

public class AttackViewModel : ViewModelBase
{
    private readonly HostDiscoverer _hostDiscoverer;
    private readonly PortScanner _portScanner;
    private readonly BannerGrabber _bannerGrabber;
    private readonly CveChecker _cveChecker;
    private readonly ILogger<AttackViewModel> _logger;

    private string _target = "192.168.1.0/24";
    private string _ports = "1-1000";
    private int _timeout = 1000;
    private int _threads = 50;
    private bool _enableBannerGrab = true;
    private bool _enableVulnScan = true;
    private double _minCvssScore = 4.0;
    private bool _isScanning = false;
    private string _scanProgress = "";
    private CancellationTokenSource? _cancellationTokenSource;

    public AttackViewModel(
        HostDiscoverer hostDiscoverer,
        PortScanner portScanner,
        BannerGrabber bannerGrabber,
        CveChecker cveChecker,
        ILogger<AttackViewModel> logger)
    {
        _hostDiscoverer = hostDiscoverer;
        _portScanner = portScanner;
        _bannerGrabber = bannerGrabber;
        _cveChecker = cveChecker;
        _logger = logger;

        ScanResults = new ObservableCollection<ScanResultItem>();
        
        StartScanCommand = new RelayCommand(async () => await StartScan(), () => !IsScanning);
        StopScanCommand = new RelayCommand(StopScan, () => IsScanning);
        ClearResultsCommand = new RelayCommand(ClearResults);
        ExportResultsCommand = new RelayCommand(async () => await ExportResults());
    }

    public ObservableCollection<ScanResultItem> ScanResults { get; }

    public string Target
    {
        get => _target;
        set => SetField(ref _target, value);
    }

    public string Ports
    {
        get => _ports;
        set => SetField(ref _ports, value);
    }

    public int Timeout
    {
        get => _timeout;
        set => SetField(ref _timeout, value);
    }

    public int Threads
    {
        get => _threads;
        set => SetField(ref _threads, value);
    }

    public bool EnableBannerGrab
    {
        get => _enableBannerGrab;
        set => SetField(ref _enableBannerGrab, value);
    }

    public bool EnableVulnScan
    {
        get => _enableVulnScan;
        set => SetField(ref _enableVulnScan, value);
    }

    public double MinCvssScore
    {
        get => _minCvssScore;
        set => SetField(ref _minCvssScore, value);
    }

    public bool IsScanning
    {
        get => _isScanning;
        set
        {
            SetField(ref _isScanning, value);
            ((RelayCommand)StartScanCommand).RaiseCanExecuteChanged();
            ((RelayCommand)StopScanCommand).RaiseCanExecuteChanged();
        }
    }

    public string ScanProgress
    {
        get => _scanProgress;
        set => SetField(ref _scanProgress, value);
    }

    public ICommand StartScanCommand { get; }
    public ICommand StopScanCommand { get; }
    public ICommand ClearResultsCommand { get; }
    public ICommand ExportResultsCommand { get; }

    private async Task StartScan()
    {
        try
        {
            IsScanning = true;
            _cancellationTokenSource = new CancellationTokenSource();
            ScanProgress = "Iniciando varredura...";

            // Parse target
            var targets = ParseTarget(Target);
            if (!targets.Any())
            {
                ScanProgress = "Erro: Alvo inválido";
                return;
            }

            // Host discovery
            ScanProgress = $"Descobrindo hosts em {Target}...";
            var hosts = await _hostDiscoverer.DiscoverHostsFromListAsync(
                targets,
                _cancellationTokenSource.Token,
                (host) => 
                {
                    ScanProgress = $"Host descoberto: {host.IpAddress}";
                },
                Timeout,
                Threads);

            var aliveHosts = hosts.Where(h => h.IsAlive).ToList();
            ScanProgress = $"Encontrados {aliveHosts.Count} hosts ativos";

            // Port scanning
            var portList = ParsePorts(Ports);
            foreach (var host in aliveHosts)
            {
                if (_cancellationTokenSource.Token.IsCancellationRequested) break;

                ScanProgress = $"Escaneando portas em {host.IpAddress}...";
                var openPorts = await _portScanner.ScanPortsAsync(
                    host.IpAddress,
                    portList,
                    _cancellationTokenSource.Token,
                    null,
                    Timeout,
                    Math.Min(Threads, 100),
                    EnableBannerGrab);

                if (openPorts.Any())
                {
                    var resultItem = new ScanResultItem
                    {
                        Host = host.IpAddress,
                        Hostname = host.Hostname ?? "",
                        OpenPorts = string.Join(", ", openPorts.Select(p => p.Port)),
                        Services = string.Join(", ", openPorts.Where(p => !string.IsNullOrEmpty(p.Service)).Select(p => p.Service)),
                        Status = "Ativo"
                    };

                    // Vulnerability scanning
                    if (EnableVulnScan && openPorts.Any())
                    {
                        ScanProgress = $"Analisando vulnerabilidades em {host.IpAddress}...";
                        var vulnerabilities = new List<VulnerabilityResult>();
                        
                        foreach (var port in openPorts.Where(p => !string.IsNullOrEmpty(p.Service)))
                        {
                            if (_cancellationTokenSource.Token.IsCancellationRequested) break;
                            
                            var serviceResults = new List<ServiceResult>
                            {
                                new ServiceResult
                                {
                                    Name = port.Service ?? "",
                                    Version = port.Version ?? "",
                                    Port = port.Port
                                }
                            };
                            
                            var vulns = await _cveChecker.CheckVulnerabilitiesAsync(
                                serviceResults,
                                _cancellationTokenSource.Token,
                                MinCvssScore);
                            
                            vulnerabilities.AddRange(vulns);
                        }

                        if (vulnerabilities.Any())
                        {
                            resultItem.Vulnerabilities = vulnerabilities.Count.ToString();
                            resultItem.HighestCvss = vulnerabilities.Max(v => v.CvssScore).ToString("F1");
                            resultItem.Status = "Vulnerável";
                        }
                    }

                    ScanResults.Add(resultItem);
                }
            }

            ScanProgress = $"Varredura concluída. {ScanResults.Count} hosts com portas abertas encontrados.";
        }
        catch (OperationCanceledException)
        {
            ScanProgress = "Varredura cancelada pelo usuário";
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro durante varredura");
            ScanProgress = $"Erro: {ex.Message}";
        }
        finally
        {
            IsScanning = false;
            _cancellationTokenSource?.Dispose();
            _cancellationTokenSource = null;
        }
    }

    private void StopScan()
    {
        _cancellationTokenSource?.Cancel();
        ScanProgress = "Parando varredura...";
    }

    private void ClearResults()
    {
        ScanResults.Clear();
        ScanProgress = "Resultados limpos";
    }

    private async Task ExportResults()
    {
        try
        {
            var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var filename = $"perseus_attack_results_{timestamp}.json";
            
            var results = new
            {
                Timestamp = DateTime.Now,
                Target = Target,
                Configuration = new
                {
                    Ports = Ports,
                    Timeout = Timeout,
                    Threads = Threads,
                    EnableBannerGrab = EnableBannerGrab,
                    EnableVulnScan = EnableVulnScan,
                    MinCvssScore = MinCvssScore
                },
                Results = ScanResults.ToList()
            };

            var json = System.Text.Json.JsonSerializer.Serialize(results, new System.Text.Json.JsonSerializerOptions 
            { 
                WriteIndented = true 
            });

            await System.IO.File.WriteAllTextAsync(filename, json);
            ScanProgress = $"Resultados exportados para {filename}";
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao exportar resultados");
            ScanProgress = $"Erro ao exportar: {ex.Message}";
        }
    }

    private List<string> ParseTarget(string target)
    {
        try
        {
            if (target.Contains('/'))
            {
                // CIDR notation
                return NetworkUtils.ParseCidrNotation(target);
            }
            else if (target.Contains('-'))
            {
                // Range notation
                return NetworkUtils.ParseIpRange(target);
            }
            else
            {
                // Single IP
                return new List<string> { target };
            }
        }
        catch
        {
            return new List<string>();
        }
    }

    private List<int> ParsePorts(string ports)
    {
        var portList = new List<int>();
        
        try
        {
            var parts = ports.Split(',');
            foreach (var part in parts)
            {
                var trimmed = part.Trim();
                if (trimmed.Contains('-'))
                {
                    var range = trimmed.Split('-');
                    if (range.Length == 2 && 
                        int.TryParse(range[0], out int start) && 
                        int.TryParse(range[1], out int end))
                    {
                        for (int i = start; i <= end; i++)
                        {
                            if (i > 0 && i <= 65535)
                                portList.Add(i);
                        }
                    }
                }
                else if (int.TryParse(trimmed, out int port))
                {
                    if (port > 0 && port <= 65535)
                        portList.Add(port);
                }
            }
        }
        catch
        {
            // Default ports if parsing fails
            return new List<int> { 21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080 };
        }

        return portList.Any() ? portList : new List<int> { 21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080 };
    }
}

public class ScanResultItem
{
    public string Host { get; set; } = "";
    public string Hostname { get; set; } = "";
    public string OpenPorts { get; set; } = "";
    public string Services { get; set; } = "";
    public string Vulnerabilities { get; set; } = "0";
    public string HighestCvss { get; set; } = "0.0";
    public string Status { get; set; } = "";
}

