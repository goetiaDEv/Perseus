using System;
using System.Net.Http;
using System.Threading.Tasks;
using System.Windows.Input;

namespace Perseus.GUI.ViewModels;

public class SettingsViewModel : ViewModelBase
{
    private int _defaultTimeout = 1000;
    private int _defaultThreads = 50;
    private bool _enableLogging = true;
    private string _logLevel = "Information";
    private bool _enableCveCache = true;
    private int _cveCacheTtl = 3600; // 1 hour
    private string _nvidApiKey = "";
    private bool _enableStealth = false;

    public SettingsViewModel()
    {
        SaveSettingsCommand = new RelayCommand(SaveSettings);
        ResetSettingsCommand = new RelayCommand(ResetSettings);
        TestConnectivityCommand = new RelayCommand(async () => await TestConnectivity());
    }

    public int DefaultTimeout
    {
        get => _defaultTimeout;
        set => SetField(ref _defaultTimeout, value);
    }

    public int DefaultThreads
    {
        get => _defaultThreads;
        set => SetField(ref _defaultThreads, value);
    }

    public bool EnableLogging
    {
        get => _enableLogging;
        set => SetField(ref _enableLogging, value);
    }

    public string LogLevel
    {
        get => _logLevel;
        set => SetField(ref _logLevel, value);
    }

    public bool EnableCveCache
    {
        get => _enableCveCache;
        set => SetField(ref _enableCveCache, value);
    }

    public int CveCacheTtl
    {
        get => _cveCacheTtl;
        set => SetField(ref _cveCacheTtl, value);
    }

    public string NvidApiKey
    {
        get => _nvidApiKey;
        set => SetField(ref _nvidApiKey, value);
    }

    public bool EnableStealth
    {
        get => _enableStealth;
        set => SetField(ref _enableStealth, value);
    }

    public ICommand SaveSettingsCommand { get; }
    public ICommand ResetSettingsCommand { get; }
    public ICommand TestConnectivityCommand { get; }

    public string[] LogLevels { get; } = { "Trace", "Debug", "Information", "Warning", "Error", "Critical" };

    private void SaveSettings()
    {
        try
        {
            var settings = new
            {
                DefaultTimeout,
                DefaultThreads,
                EnableLogging,
                LogLevel,
                EnableCveCache,
                CveCacheTtl,
                NvidApiKey,
                EnableStealth
            };

            var json = System.Text.Json.JsonSerializer.Serialize(settings, new System.Text.Json.JsonSerializerOptions 
            { 
                WriteIndented = true 
            });

            System.IO.File.WriteAllText("perseus_settings.json", json);
            
            // Here you would typically notify the user that settings were saved
            // For now, we'll just update a status (this would need to be connected to the main window)
        }
        catch (Exception ex)
        {
            // Handle error - in a real app, you'd show this to the user
            System.Diagnostics.Debug.WriteLine($"Error saving settings: {ex.Message}");
        }
    }

    private void ResetSettings()
    {
        DefaultTimeout = 1000;
        DefaultThreads = 50;
        EnableLogging = true;
        LogLevel = "Information";
        EnableCveCache = true;
        CveCacheTtl = 3600;
        NvidApiKey = "";
        EnableStealth = false;
    }

    private async Task TestConnectivity()
    {
        try
        {
            using var httpClient = new HttpClient();
            httpClient.Timeout = TimeSpan.FromSeconds(10);
            
            // Test internet connectivity
            var response = await httpClient.GetAsync("https://www.google.com");
            var internetStatus = response.IsSuccessStatusCode ? "✅ OK" : "❌ Falha";
            
            // Test NVD API
            var nvdResponse = await httpClient.GetAsync("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1");
            var nvdStatus = nvdResponse.IsSuccessStatusCode ? "✅ OK" : "❌ Falha";
            
            // In a real implementation, you'd update UI elements to show these results
            System.Diagnostics.Debug.WriteLine($"Internet: {internetStatus}, NVD API: {nvdStatus}");
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Connectivity test failed: {ex.Message}");
        }
    }
}

