# Perseus GUI - Documentação Técnica Completa

## Índice

1. [Visão Geral](#visão-geral)
2. [Arquitetura da Aplicação](#arquitetura-da-aplicação)
3. [Módulo Attack](#módulo-attack)
4. [Módulo Defense](#módulo-defense)
5. [Interface de Usuário](#interface-de-usuário)
6. [Integração com Perseus.Core](#integração-com-perseuscore)
7. [Configuração e Deployment](#configuração-e-deployment)
8. [Guia de Desenvolvimento](#guia-de-desenvolvimento)

## Visão Geral

A Perseus GUI é uma interface gráfica moderna desenvolvida com AvaloniaUI que fornece acesso completo às funcionalidades do Perseus Cybersecurity Scanner através de uma interface intuitiva e profissional. A aplicação foi projetada para atender às necessidades tanto de profissionais de Red Team quanto de Blue Team, oferecendo interfaces especializadas para cada tipo de operação.

### Características Principais

- **Arquitetura MVVM**: Implementação completa do padrão Model-View-ViewModel
- **Interface Responsiva**: Design adaptável para diferentes resoluções e tamanhos de tela
- **Tema Profissional**: Interface escura otimizada para operações de cybersecurity
- **Feedback em Tempo Real**: Atualizações instantâneas durante operações
- **Configuração Avançada**: Controles detalhados para todas as opções disponíveis no CLI
- **Separação de Contextos**: Módulos distintos para operações ofensivas e defensivas

## Arquitetura da Aplicação

### Estrutura de Projetos

A Perseus GUI está integrada à solução Perseus como um projeto adicional, mantendo a separação de responsabilidades:

```
Perseus.sln
├── Perseus.Common/     # Modelos compartilhados
├── Perseus.Core/       # Lógica de negócios
├── Perseus.CLI/        # Interface de linha de comando
├── Perseus.Reports/    # Geração de relatórios
├── Perseus.Tests/      # Testes unitários
└── Perseus.GUI/        # Interface gráfica (NOVO)
```

### Padrão MVVM

A aplicação segue rigorosamente o padrão MVVM (Model-View-ViewModel):

#### Models
- **ScanConfiguration**: Configurações para operações de Attack
- **DefenseConfiguration**: Configurações para operações de Defense

#### Views
- **MainWindow**: Janela principal com navegação entre módulos
- **AttackView**: Interface para operações ofensivas
- **DefenseView**: Interface para operações defensivas

#### ViewModels
- **MainWindowViewModel**: Gerenciamento da navegação principal
- **AttackViewModel**: Lógica para operações de Attack
- **DefenseViewModel**: Lógica para operações de Defense

### Dependências

```xml
<PackageReference Include="Avalonia" Version="11.3.2" />
<PackageReference Include="Avalonia.Desktop" Version="11.3.2" />
<PackageReference Include="Avalonia.Themes.Fluent" Version="11.3.2" />
<PackageReference Include="CommunityToolkit.Mvvm" Version="8.2.1" />
```

## Módulo Attack

### Funcionalidades Implementadas

O módulo Attack oferece acesso completo às operações ofensivas do Perseus:

#### 1. Host Discovery
- Descoberta de hosts ativos em redes
- Suporte a notação CIDR (192.168.1.0/24)
- Suporte a ranges de IP (192.168.1.1-254)
- Resolução de DNS reverso
- Feedback em tempo real de hosts descobertos

#### 2. Port Scanning
- Varredura de portas TCP
- Configuração flexível de portas (ranges, listas)
- Captura opcional de banners
- Controle de concorrência e timeouts
- Identificação automática de serviços

#### 3. Vulnerability Assessment
- Análise de vulnerabilidades baseada em CVE
- Integração com National Vulnerability Database
- Filtragem por score CVSS mínimo
- Correlação automática com serviços identificados
- Priorização por severidade

#### 4. Full Assessment
- Combinação de todas as operações em sequência
- Relatório consolidado de resultados
- Otimização de performance para avaliações completas

### Interface do Usuário

#### Painel de Configuração

O painel superior contém todos os controles necessários:

- **Operation**: ComboBox para seleção do tipo de operação
- **Target**: Campo de texto para especificação de alvos
- **Ports**: Campo para configuração de portas
- **Timeout**: Controle numérico para timeout de conexões
- **Threads**: Controle para número de threads simultâneas
- **Min CVSS**: Controle para score mínimo de vulnerabilidades
- **Banner Grabbing**: Checkbox para ativação da captura de banners
- **Stealth Mode**: Checkbox para modo discreto
- **Output File**: Campo para arquivo de saída

#### Controles de Operação

- **Start Scan**: Inicia a operação selecionada
- **Stop**: Interrompe operação em andamento
- **Clear**: Limpa a área de resultados
- **Save Results**: Salva resultados em arquivo JSON

#### Área de Resultados

- Display em tempo real de resultados
- Fonte monospace para melhor legibilidade
- Timestamps em todas as mensagens
- Scroll automático para acompanhar progresso

### Implementação Técnica

#### AttackViewModel

```csharp
public partial class AttackViewModel : ViewModelBase
{
    [ObservableProperty]
    private ScanConfiguration _configuration = new();
    
    [ObservableProperty]
    private string _selectedOperation = "discover";
    
    [ObservableProperty]
    private bool _isScanning = false;
    
    public ICommand StartScanCommand { get; }
    public ICommand StopScanCommand { get; }
    // ... outros comandos
}
```

#### Integração com Perseus.Core

```csharp
private async Task ExecuteDiscoverAsync()
{
    var discoverer = new HostDiscoverer();
    var hosts = await discoverer.DiscoverHostsAsync(
        Configuration.Target, 
        timeout: Configuration.Timeout
    );
    
    foreach (var host in hosts)
    {
        AddOutput($"Host found: {host.IpAddress} - Alive: {host.IsAlive}");
    }
}
```

## Módulo Defense

### Funcionalidades Implementadas

O módulo Defense oferece capacidades defensivas completas:

#### 1. Network Monitoring
- Monitoramento contínuo de rede
- Detecção de anomalias baseada em baseline
- Alertas em tempo real para novos dispositivos
- Configuração de intervalos de monitoramento

#### 2. Baseline Creation
- Criação de baselines de rede
- Captura de estado normal da infraestrutura
- Salvamento em formato JSON
- Duração configurável de coleta

#### 3. Log Analysis
- Análise de logs de segurança
- Suporte a múltiplos formatos (Apache, Nginx, System)
- Detecção automática de padrões suspeitos
- Geração de alertas baseada em heurísticas

#### 4. Threat Hunting
- Busca proativa por indicadores de comprometimento
- Varredura de portas suspeitas
- Análise profunda opcional
- Correlação de múltiplos indicadores

#### 5. Incident Response
- Resposta automatizada a incidentes
- Ações configuráveis (isolate, collect, analyze)
- Suporte a diferentes tipos de incidentes
- Workflow estruturado de resposta

### Interface do Usuário

#### Painel de Configuração

Controles específicos para operações defensivas:

- **Operation**: Seleção de operação defensiva
- **Target**: Rede ou hosts para monitoramento
- **Baseline File**: Arquivo de baseline para comparação
- **Log File**: Arquivo de log para análise
- **Log Type**: Tipo de log (auto-detecção ou específico)
- **Monitor Interval**: Intervalo de monitoramento em segundos
- **Baseline Duration**: Duração da criação de baseline
- **Threats**: Tipos de ameaças para busca
- **Deep Analysis**: Ativação de análise profunda
- **Incident Type**: Tipo de incidente para resposta
- **Actions**: Ações de resposta a executar

#### Layout Especializado

- **Área Principal**: Resultados de operações
- **Painel de Alertas**: Alertas de segurança em tempo real
- **Botão Create Baseline**: Ação dedicada para criação de baseline

#### Sistema de Alertas

```csharp
private void AddAlert(string alert)
{
    var timestamp = DateTime.Now.ToString("HH:mm:ss");
    var formattedAlert = $"[{timestamp}] {alert}";
    
    Alerts.Add(formattedAlert);
}
```

### Implementação Técnica

#### DefenseViewModel

```csharp
public partial class DefenseViewModel : ViewModelBase
{
    [ObservableProperty]
    private DefenseConfiguration _configuration = new();
    
    [ObservableProperty]
    private ObservableCollection<string> _alerts = new();
    
    [ObservableProperty]
    private bool _isRunning = false;
    
    public ICommand StartOperationCommand { get; }
    public ICommand CreateBaselineCommand { get; }
    // ... outros comandos
}
```

## Interface de Usuário

### Design System

#### Paleta de Cores

- **Background Principal**: #1E1E1E (cinza muito escuro)
- **Painéis**: #2D2D30 (cinza escuro)
- **Attack Theme**: #FF6B6B (vermelho coral)
- **Defense Theme**: #4CAF50 (verde material)
- **Texto Principal**: #FFFFFF (branco)
- **Texto Secundário**: #CCCCCC (cinza claro)
- **Alertas**: #FFB3B3 (vermelho claro)

#### Tipografia

- **Interface**: Fonte padrão do sistema
- **Código/Logs**: Consolas, Monaco, monospace
- **Tamanhos**: 12px (logs), 14px (texto), 16px (subtítulos), 18px+ (títulos)

#### Iconografia

- **Attack**: 🔴 (círculo vermelho)
- **Defense**: 🛡️ (escudo)
- **Logo**: ⚡ (raio)

### Responsividade

#### Breakpoints

- **Mínimo**: 800x600px
- **Recomendado**: 1200x800px
- **Máximo**: Sem limite

#### Adaptações

- Layout de grid responsivo
- Controles redimensionáveis
- Scroll automático em áreas de conteúdo
- Painéis colapsáveis em resoluções menores

### Acessibilidade

- Contraste adequado para leitura
- Navegação por teclado
- Indicadores visuais claros
- Feedback sonoro opcional (futuro)

## Integração com Perseus.Core

### Camada de Abstração

A GUI utiliza diretamente as classes do Perseus.Core:

```csharp
// Host Discovery
var discoverer = new HostDiscoverer();
var hosts = await discoverer.DiscoverHostsAsync(target, timeout: timeout);

// Port Scanning  
var scanner = new PortScanner();
var results = await scanner.ScanPortsAsync(target, ports, timeout: timeout);

// Vulnerability Assessment
var cveChecker = new CveChecker();
var vulns = await cveChecker.CheckVulnerabilitiesAsync(services);
```

### Tratamento de Erros

```csharp
try
{
    // Operação Perseus.Core
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
```

### Configuração de Parâmetros

A GUI mapeia configurações da interface para parâmetros do Core:

```csharp
var results = await scanner.ScanPortsAsync(
    Configuration.Target,
    portList,
    timeout: Configuration.Timeout,
    maxConcurrency: Configuration.Threads,
    grabBanners: Configuration.BannerGrabbing
);
```

## Configuração e Deployment

### Requisitos do Sistema

#### Desenvolvimento
- .NET 8.0 SDK
- Visual Studio 2022 ou VS Code
- Git para controle de versão

#### Execução
- .NET 8.0 Runtime
- Sistema operacional com suporte gráfico
- Mínimo 4GB RAM
- 100MB espaço em disco

### Compilação

```bash
# Debug
dotnet build Perseus.GUI

# Release
dotnet build Perseus.GUI -c Release
```

### Publicação

```bash
# Self-contained
dotnet publish Perseus.GUI -c Release -r win-x64 --self-contained

# Framework-dependent
dotnet publish Perseus.GUI -c Release
```

### Distribuição

#### Windows
- Executável único com dependências
- Instalador MSI (futuro)
- Portable ZIP

#### Linux
- AppImage (futuro)
- Flatpak (futuro)
- Tarball com scripts

#### macOS
- App Bundle (futuro)
- DMG installer (futuro)

## Guia de Desenvolvimento

### Configuração do Ambiente

1. **Clone do Repositório**
```bash
git clone <repository-url>
cd perseus
git checkout feature/gui-integration
```

2. **Instalação de Dependências**
```bash
dotnet restore
```

3. **Compilação**
```bash
dotnet build
```

### Estrutura de Desenvolvimento

#### Adicionando Nova Funcionalidade

1. **Modelo**: Adicione propriedades ao modelo de configuração apropriado
2. **ViewModel**: Implemente a lógica no ViewModel correspondente
3. **View**: Adicione controles na interface XAML
4. **Binding**: Configure o data binding entre View e ViewModel
5. **Teste**: Verifique funcionamento e integração

#### Padrões de Código

```csharp
// Propriedades observáveis
[ObservableProperty]
private string _myProperty = string.Empty;

// Comandos
public ICommand MyCommand { get; }

// Construtor
public MyViewModel()
{
    MyCommand = new AsyncRelayCommand(ExecuteMyCommandAsync);
}

// Implementação de comando
private async Task ExecuteMyCommandAsync()
{
    try
    {
        // Lógica do comando
    }
    catch (Exception ex)
    {
        // Tratamento de erro
    }
}
```

### Debugging

#### Logs de Debug
```csharp
#if DEBUG
Console.WriteLine($"Debug: {message}");
#endif
```

#### Breakpoints Condicionais
- Use breakpoints condicionais para debugging específico
- Evite logs excessivos em produção

### Testes

#### Testes de Interface
- Verificar responsividade
- Testar todos os controles
- Validar data binding
- Confirmar feedback visual

#### Testes de Integração
- Testar integração com Perseus.Core
- Verificar salvamento de arquivos
- Validar configurações
- Confirmar comandos

### Performance

#### Otimizações Implementadas
- Virtualização de listas longas
- Binding otimizado
- Operações assíncronas
- Garbage collection consciente

#### Monitoramento
- Memory profiling
- CPU usage monitoring
- UI thread responsiveness

### Manutenção

#### Atualizações de Dependências
```bash
dotnet list package --outdated
dotnet add package <PackageName> --version <Version>
```

#### Refatoração
- Mantenha ViewModels pequenos e focados
- Extraia lógica complexa para services
- Use injeção de dependência quando apropriado

---

**Desenvolvido por:** goetiaDEv  
**Data:** 2025  
**Versão:** 1.0.0  
**Framework:** AvaloniaUI 11.3.2

