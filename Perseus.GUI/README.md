# Perseus GUI - Interface Gráfica

A Perseus GUI é uma interface gráfica moderna e responsiva para o Perseus Cybersecurity Scanner, desenvolvida com AvaloniaUI e seguindo o padrão MVVM (Model-View-ViewModel).

## 🎯 Características

- **Interface Moderna**: Design escuro e profissional otimizado para operações de cybersecurity
- **Módulos Separados**: Interfaces distintas para operações de Attack (Red Team) e Defense (Blue Team)
- **Responsiva**: Interface adaptável que funciona em diferentes resoluções
- **Tempo Real**: Feedback em tempo real durante operações de varredura
- **Configuração Avançada**: Controles detalhados para todas as opções do CLI

## 🏗️ Arquitetura

### Estrutura do Projeto

```
Perseus.GUI/
├── Models/                 # Modelos de configuração
│   ├── ScanConfiguration.cs
│   └── DefenseConfiguration.cs
├── ViewModels/            # ViewModels MVVM
│   ├── MainWindowViewModel.cs
│   ├── AttackViewModel.cs
│   └── DefenseViewModel.cs
├── Views/                 # Interfaces de usuário
│   ├── MainWindow.axaml
│   ├── AttackView.axaml
│   └── DefenseView.axaml
└── Assets/               # Recursos visuais
```

### Padrão MVVM

A aplicação segue rigorosamente o padrão MVVM:

- **Models**: Representam os dados e configurações (`ScanConfiguration`, `DefenseConfiguration`)
- **Views**: Definem a interface do usuário em XAML
- **ViewModels**: Contêm a lógica de apresentação e comandos

## 🔴 Módulo Attack (Red Team)

### Funcionalidades

- **Host Discovery**: Descoberta de hosts ativos na rede
- **Port Scanning**: Varredura de portas com captura de banners
- **Vulnerability Assessment**: Análise de vulnerabilidades com integração CVE
- **Full Assessment**: Avaliação completa combinando todas as operações

### Configurações Disponíveis

- **Target**: Especificação de alvos (CIDR, ranges, IPs individuais)
- **Ports**: Configuração de portas (ranges, listas específicas)
- **Timeout**: Tempo limite para conexões (1000-30000ms)
- **Threads**: Número de threads simultâneas (1-200)
- **Min CVSS**: Score mínimo CVSS para vulnerabilidades (0.0-10.0)
- **Banner Grabbing**: Ativação/desativação da captura de banners
- **Stealth Mode**: Modo discreto para operações
- **Output File**: Arquivo de saída para resultados

### Interface

A interface do módulo Attack inclui:

- Painel de configuração com todos os controles necessários
- Seleção de operação via ComboBox
- Controles numéricos para timeout, threads e CVSS
- Checkboxes para opções booleanas
- Botões de controle (Start, Stop, Clear, Save)
- Área de resultados em tempo real com fonte monospace
- Indicador de status e progresso

## 🛡️ Módulo Defense (Blue Team)

### Funcionalidades

- **Network Monitoring**: Monitoramento contínuo da rede
- **Baseline Creation**: Criação de baselines de segurança
- **Log Analysis**: Análise de logs de segurança
- **Threat Hunting**: Busca proativa por ameaças
- **Incident Response**: Resposta automatizada a incidentes

### Configurações Disponíveis

- **Target**: Rede ou hosts para monitoramento
- **Baseline File**: Arquivo de baseline para comparação
- **Log File**: Arquivo de log para análise
- **Log Type**: Tipo de log (auto, apache, nginx, system)
- **Monitor Interval**: Intervalo de monitoramento (30-3600s)
- **Baseline Duration**: Duração da criação de baseline (60-1800s)
- **Threats**: Tipos de ameaças para busca
- **Deep Analysis**: Análise profunda ativada/desativada
- **Incident Type**: Tipo de incidente (malware, breach, ddos, insider)
- **Actions**: Ações de resposta (isolate, collect, analyze)

### Interface

A interface do módulo Defense inclui:

- Painel de configuração específico para operações defensivas
- Controles para arquivos de baseline e logs
- Configurações de monitoramento e análise
- Botão dedicado para criação de baseline
- Área principal de resultados
- Painel lateral de alertas de segurança em tempo real
- Indicadores visuais para diferentes tipos de alertas

## 🎨 Design e Usabilidade

### Tema Escuro

A interface utiliza um tema escuro profissional:

- **Background Principal**: #1E1E1E
- **Painéis**: #2D2D30
- **Attack Color**: #FF6B6B (vermelho)
- **Defense Color**: #4CAF50 (verde)
- **Texto**: Branco e tons de cinza
- **Alertas**: #FFB3B3 em fundo escuro

### Responsividade

- Largura mínima: 800px
- Altura mínima: 600px
- Tamanho recomendado: 1200x800px
- Layout adaptável para diferentes resoluções

### Feedback Visual

- Indicadores de progresso em tempo real
- Cores diferenciadas para status (sucesso, erro, alerta)
- Desabilitação de controles durante operações
- Timestamps em todas as mensagens

## 🚀 Execução

### Pré-requisitos

- .NET 8.0 SDK
- Sistema operacional com suporte gráfico
- Dependências do projeto Perseus.Core

### Compilação

```bash
dotnet build Perseus.GUI
```

### Execução

```bash
dotnet run --project Perseus.GUI
```

### Publicação

```bash
dotnet publish Perseus.GUI -c Release -o publish/
```

## 🔧 Desenvolvimento

### Adicionando Novas Funcionalidades

1. **Modelo**: Adicione propriedades aos modelos de configuração
2. **ViewModel**: Implemente a lógica no ViewModel apropriado
3. **View**: Adicione controles na interface XAML
4. **Binding**: Configure o data binding entre View e ViewModel

### Padrões de Código

- Use `ObservableProperty` para propriedades bindáveis
- Implemente comandos com `RelayCommand` ou `AsyncRelayCommand`
- Mantenha ViewModels independentes de Views
- Use injeção de dependência quando apropriado

### Tratamento de Erros

- Todos os métodos async devem ter try-catch
- Erros devem ser exibidos na área de output
- Status deve ser atualizado em caso de erro
- Operações devem ser interrompíveis

## 🧪 Testes

### Testes de Interface

- Verificar responsividade em diferentes resoluções
- Testar todos os controles e comandos
- Validar binding de dados
- Confirmar feedback visual

### Testes de Integração

- Testar integração com Perseus.Core
- Verificar salvamento de resultados
- Validar configurações de operações
- Confirmar funcionamento de comandos

## 📋 Limitações Conhecidas

- Requer ambiente gráfico (não funciona em headless)
- Algumas operações podem ser intensivas em recursos
- Logs extensos podem impactar performance da interface
- Operações de longa duração podem bloquear a UI temporariamente

## 🔮 Melhorias Futuras

- Gráficos e visualizações de dados
- Exportação de relatórios em múltiplos formatos
- Configurações persistentes
- Temas customizáveis
- Suporte a plugins visuais
- Dashboard executivo
- Integração com sistemas SIEM

## 📝 Contribuição

Para contribuir com a GUI:

1. Mantenha consistência visual
2. Siga o padrão MVVM
3. Documente novas funcionalidades
4. Teste em diferentes resoluções
5. Mantenha compatibilidade com o CLI

---

**Desenvolvido por:** goetiaDEv  
**Framework:** AvaloniaUI 11.3.2  
**Padrão:** MVVM  
**Versão:** 1.0.0

