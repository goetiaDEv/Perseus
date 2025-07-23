using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace Perseus.GUI.Models;

public class ScanConfiguration : INotifyPropertyChanged
{
    private string _target = string.Empty;
    private string _ports = "1-1000";
    private int _timeout = 3000;
    private int _threads = 50;
    private bool _bannerGrabbing = true;
    private bool _stealthMode = false;
    private double _minCvss = 0.0;
    private string _outputFile = string.Empty;

    public string Target
    {
        get => _target;
        set => SetProperty(ref _target, value);
    }

    public string Ports
    {
        get => _ports;
        set => SetProperty(ref _ports, value);
    }

    public int Timeout
    {
        get => _timeout;
        set => SetProperty(ref _timeout, value);
    }

    public int Threads
    {
        get => _threads;
        set => SetProperty(ref _threads, value);
    }

    public bool BannerGrabbing
    {
        get => _bannerGrabbing;
        set => SetProperty(ref _bannerGrabbing, value);
    }

    public bool StealthMode
    {
        get => _stealthMode;
        set => SetProperty(ref _stealthMode, value);
    }

    public double MinCvss
    {
        get => _minCvss;
        set => SetProperty(ref _minCvss, value);
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

