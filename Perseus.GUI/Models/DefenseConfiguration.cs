using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace Perseus.GUI.Models;

public class DefenseConfiguration : INotifyPropertyChanged
{
    private string _target = string.Empty;
    private string _baselineFile = string.Empty;
    private string _logFile = string.Empty;
    private string _logType = "auto";
    private int _monitorInterval = 300;
    private int _baselineDuration = 300;
    private string _threats = "malware backdoors";
    private bool _deepAnalysis = false;
    private string _incidentType = "malware";
    private string _actions = "isolate collect analyze";
    private string _outputFile = string.Empty;

    public string Target
    {
        get => _target;
        set => SetProperty(ref _target, value);
    }

    public string BaselineFile
    {
        get => _baselineFile;
        set => SetProperty(ref _baselineFile, value);
    }

    public string LogFile
    {
        get => _logFile;
        set => SetProperty(ref _logFile, value);
    }

    public string LogType
    {
        get => _logType;
        set => SetProperty(ref _logType, value);
    }

    public int MonitorInterval
    {
        get => _monitorInterval;
        set => SetProperty(ref _monitorInterval, value);
    }

    public int BaselineDuration
    {
        get => _baselineDuration;
        set => SetProperty(ref _baselineDuration, value);
    }

    public string Threats
    {
        get => _threats;
        set => SetProperty(ref _threats, value);
    }

    public bool DeepAnalysis
    {
        get => _deepAnalysis;
        set => SetProperty(ref _deepAnalysis, value);
    }

    public string IncidentType
    {
        get => _incidentType;
        set => SetProperty(ref _incidentType, value);
    }

    public string Actions
    {
        get => _actions;
        set => SetProperty(ref _actions, value);
    }

    public string OutputFile
    {
        get => _outputFile;
        set => SetProperty(ref _outputFile, value);
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    protected bool SetProperty<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        OnPropertyChanged(propertyName);
        return true;
    }
}

