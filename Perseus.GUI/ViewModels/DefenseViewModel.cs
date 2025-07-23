using Microsoft.Extensions.Logging;
using Perseus.Core.Network;
using Perseus.GUI.Utils;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;

namespace Perseus.GUI.ViewModels;

public class DefenseViewModel : ViewModelBase
{
    private readonly HostDiscoverer _hostDiscoverer;
    private readonly ILogger<DefenseViewModel> _logger;

    private string _networkRange = "192.168.1.0/24";
    private int _monitoringInterval = 300; // 5 minutes
    private bool _isMonitoring = false;
    private string _monitoringStatus = "Parado";
    private CancellationTokenSource? _cancellationTokenSource;

    public DefenseViewModel(
        HostDiscoverer hostDiscoverer,
        ILogger<DefenseViewModel> logger)
    {
        _hostDiscoverer = hostDiscoverer;
        _logger = logger;

        MonitoringResults = new ObservableCollection<MonitoringEvent>();
        Alerts = new ObservableCollection<SecurityAlert>();

        StartMonitoringCommand = new RelayCommand(async () => await StartMonitoring(), () => !IsMonitoring);
        StopMonitoringCommand = new RelayCommand(StopMonitoring, () => IsMonitoring);
        CreateBaselineCommand = new RelayCommand(async () => await CreateBaseline());
        ClearAlertsCommand = new RelayCommand(ClearAlerts);
        ExportAlertsCommand = new RelayCommand(async () => await ExportAlerts());
    }

    public ObservableCollection<MonitoringEvent> MonitoringResults { get; }
    public ObservableCollection<SecurityAlert> Alerts { get; }

    public string NetworkRange
    {
        get => _networkRange;
        set => SetField(ref _networkRange, value);
    }

    public int MonitoringInterval
    {
        get => _monitoringInterval;
        set => SetField(ref _monitoringInterval, value);
    }

    public bool IsMonitoring
    {
        get => _isMonitoring;
        set
        {
            SetField(ref _isMonitoring, value);
            ((RelayCommand)StartMonitoringCommand).RaiseCanExecuteChanged();
            ((RelayCommand)StopMonitoringCommand).RaiseCanExecuteChanged();
        }
    }

    public string MonitoringStatus
    {
        get => _monitoringStatus;
        set => SetField(ref _monitoringStatus, value);
    }

    public ICommand StartMonitoringCommand { get; }
    public ICommand StopMonitoringCommand { get; }
    public ICommand CreateBaselineCommand { get; }
    public ICommand ClearAlertsCommand { get; }
    public ICommand ExportAlertsCommand { get; }

    private async Task StartMonitoring()
    {
        try
        {
            IsMonitoring = true;
            _cancellationTokenSource = new CancellationTokenSource();
            MonitoringStatus = "Iniciando monitoramento...";

            while (!_cancellationTokenSource.Token.IsCancellationRequested)
            {
                MonitoringStatus = $"Monitorando {NetworkRange}...";
                
                // Perform network scan
                var targets = ParseNetworkRange(NetworkRange);
                var hosts = await _hostDiscoverer.DiscoverHostsFromListAsync(
                    targets,
                    _cancellationTokenSource.Token,
                    null,
                    2000,
                    30);

                var timestamp = DateTime.Now;
                var activeHosts = 0;

                foreach (var host in hosts)
                {
                    if (host.IsAlive)
                    {
                        activeHosts++;
                        
                        // Check if this is a new host (simplified logic)
                        var isNewHost = !MonitoringResults.Any(r => r.Host == host.IpAddress);
                        
                        var monitoringEvent = new MonitoringEvent
                        {
                            Timestamp = timestamp,
                            Host = host.IpAddress,
                            Hostname = host.Hostname ?? "",
                            EventType = isNewHost ? "Novo Host Detectado" : "Host Ativo",
                            Details = $"Host {host.IpAddress} está ativo"
                        };

                        MonitoringResults.Add(monitoringEvent);

                        // Generate alert for new hosts
                        if (isNewHost)
                        {
                            var alert = new SecurityAlert
                            {
                                Timestamp = timestamp,
                                Severity = "Medium",
                                Type = "Novo Dispositivo",
                                Host = host.IpAddress,
                                Description = $"Novo dispositivo detectado na rede: {host.IpAddress}",
                                Status = "Novo"
                            };

                            Alerts.Add(alert);
                        }
                    }
                }

                MonitoringStatus = $"Monitoramento ativo - {activeHosts} hosts detectados";

                // Wait for next interval
                await Task.Delay(MonitoringInterval * 1000, _cancellationTokenSource.Token);
            }
        }
        catch (OperationCanceledException)
        {
            MonitoringStatus = "Monitoramento parado";
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro durante monitoramento");
            MonitoringStatus = $"Erro: {ex.Message}";
        }
        finally
        {
            IsMonitoring = false;
            _cancellationTokenSource?.Dispose();
            _cancellationTokenSource = null;
        }
    }

    private void StopMonitoring()
    {
        _cancellationTokenSource?.Cancel();
        MonitoringStatus = "Parando monitoramento...";
    }

    private async Task CreateBaseline()
    {
        try
        {
            MonitoringStatus = "Criando baseline da rede...";
            
            var targets = ParseNetworkRange(NetworkRange);
            var hosts = await _hostDiscoverer.DiscoverHostsFromListAsync(
                targets,
                CancellationToken.None,
                null,
                2000,
                50);

            var baseline = new
            {
                Timestamp = DateTime.Now,
                NetworkRange = NetworkRange,
                TotalHosts = hosts.Count(h => h.IsAlive),
                Hosts = hosts.Where(h => h.IsAlive).Select(h => new
                {
                    h.IpAddress,
                    h.Hostname
                }).ToList()
            };

            var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var filename = $"perseus_baseline_{timestamp}.json";
            
            var json = System.Text.Json.JsonSerializer.Serialize(baseline, new System.Text.Json.JsonSerializerOptions 
            { 
                WriteIndented = true 
            });

            await System.IO.File.WriteAllTextAsync(filename, json);
            MonitoringStatus = $"Baseline criado: {filename} ({baseline.TotalHosts} hosts)";
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao criar baseline");
            MonitoringStatus = $"Erro ao criar baseline: {ex.Message}";
        }
    }

    private void ClearAlerts()
    {
        Alerts.Clear();
        MonitoringStatus = "Alertas limpos";
    }

    private async Task ExportAlerts()
    {
        try
        {
            var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var filename = $"perseus_alerts_{timestamp}.json";
            
            var alertsData = new
            {
                Timestamp = DateTime.Now,
                NetworkRange = NetworkRange,
                TotalAlerts = Alerts.Count,
                Alerts = Alerts.ToList()
            };

            var json = System.Text.Json.JsonSerializer.Serialize(alertsData, new System.Text.Json.JsonSerializerOptions 
            { 
                WriteIndented = true 
            });

            await System.IO.File.WriteAllTextAsync(filename, json);
            MonitoringStatus = $"Alertas exportados para {filename}";
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao exportar alertas");
            MonitoringStatus = $"Erro ao exportar: {ex.Message}";
        }
    }

    private List<string> ParseNetworkRange(string range)
    {
        try
        {
            if (range.Contains('/'))
            {
                return NetworkUtils.ParseCidrNotation(range);
            }
            else
            {
                return new List<string> { range };
            }
        }
        catch
        {
            return new List<string>();
        }
    }
}

public class MonitoringEvent
{
    public DateTime Timestamp { get; set; }
    public string Host { get; set; } = "";
    public string Hostname { get; set; } = "";
    public string EventType { get; set; } = "";
    public string Details { get; set; } = "";
}

public class SecurityAlert
{
    public DateTime Timestamp { get; set; }
    public string Severity { get; set; } = "";
    public string Type { get; set; } = "";
    public string Host { get; set; } = "";
    public string Description { get; set; } = "";
    public string Status { get; set; } = "";
}

