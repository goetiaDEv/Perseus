```
 ____                                                    
/\  _`\                                                  
\ \ \L\ \   __    _ __    ____     __    __  __    ____  
 \ \ ,__/ /\'__`\ /\`\'__\ /\',__\  /\'__`\ /\ \/\ \  /\',__\ 
  \ \ \/ /\  __/ \ \ \/ /\__, `\/\  __/ \ \ \_\ \/\__, `\
   \ \_\ \ \____\ \ \_\ \/\____/\ \____\ \ \____/\/\____/
    \/_/  \/____/  \/_/  \/___/  \/____/  \/___/  \/___/ 
                                                         
                                                         
```
# Perseus - Ferramenta de Cybersecurity para Necessidades Ofensivas e Defensivas

Perseus é uma ferramenta de cybersecurity multifuncional desenvolvida em C# que atende às necessidades de segurança ofensiva e defensiva. Baseado na evolução do projeto Helius e inspirado na filosofia do SKEF (Speed Kill Execution Framework), o Perseus oferece uma abordagem unificada para operações de segurança cibernética.

## 🎯 Visão Geral

O Perseus foi projetado para superar as limitações de ferramentas especializadas, oferecendo uma solução integrada que permite aos profissionais de segurança alternar facilmente entre perspectivas ofensivas e defensivas. A ferramenta combina a robustez do .NET com a eficiência e objetividade necessárias no cenário atual de ameaças cibernéticas.

### Características Principais

- **Operação em Modos Distintos**: Modos para necessidades ofensivas e defensivas claramente separados
- **Modular Architecture**: Arquitetura extensível e modular
- **High Performance**: Programação assíncrona e paralela para máxima eficiência
- **CVE Integration**: Integração com bases de dados de vulnerabilidades (NVD)
- **Cross-Platform**: Compatível com Windows, Linux e macOS via .NET 8
- **CLI Interface**: Interface de linha de comando intuitiva e poderosa

## 🚀 Instalação

### Pré-requisitos

- .NET 8.0 SDK ou superior
- Sistema operacional: Windows 10+, Ubuntu 18.04+, macOS 10.15+
- Acesso à internet para consultas de CVE

### Compilação

```bash
git clone <repository-url>
cd perseus
dotnet build
```

### Execução

```bash
dotnet run --project Perseus.CLI -- --help
```

## 📖 Modos de Operação

### Modo de Segurança Ofensiva

O modo de segurança ofensiva é dedicado a funcionalidades ofensivas, otimizado para operações de pentest e simulações de ataque:

#### Descoberta de Hosts
```bash
# Descoberta básica de hosts
perseus attack discover 192.168.1.0/24

# Descoberta com timeout customizado
perseus attack discover 192.168.1.0/24 --timeout 2000 --threads 30
```

#### Varredura de Portas
```bash
# Varredura de portas com captura de banner
perseus attack scan 192.168.1.100 --ports 1-1000 --banner

# Varredura de portas específicas
perseus attack scan 192.168.1.100 --ports 22,80,443,8080
```

#### Avaliação de Vulnerabilidades
```bash
# Avaliação com CVSS mínimo
perseus attack vuln 192.168.1.100 --min-cvss 7.0

# Avaliação completa com relatório
perseus attack vuln 192.168.1.100 --output vulnerabilities.json
```

#### Avaliação Completa
```bash
# Avaliação completa em modo stealth
perseus attack full 192.168.1.0/24 --stealth --output results.json

# Avaliação completa com portas customizadas
perseus attack full 10.0.0.0/24 --ports 1-65535 --min-cvss 4.0
```

### Modo de Segurança Defensiva

O modo de segurança defensiva foca em capacidades defensivas para detecção, análise e resposta a incidentes:

#### Criação de Baseline
```bash
# Criar baseline da rede
perseus defense baseline 192.168.1.0/24 --output baseline.json --duration 300
```

#### Monitoramento de Rede
```bash
# Monitoramento contínuo com baseline
perseus defense monitor 192.168.1.0/24 --baseline baseline.json --alerts alerts.json

# Monitoramento com intervalo customizado
perseus defense monitor 192.168.1.0/24 --interval 120
```

#### Análise de Logs
```bash
# Análise de logs do Apache
perseus defense logs /var/log/apache2/access.log --type apache --output alerts.json

# Análise de logs com detecção automática
perseus defense logs /var/log/system.log --type auto
```

#### Threat Hunting
```bash
# Busca por malware e backdoors
perseus defense hunt 192.168.1.0/24 --threats malware backdoors --deep

# Busca por movimento lateral
perseus defense hunt 192.168.1.0/24 --threats lateral-movement --output hunt_results.json
```

#### Resposta a Incidentes
```bash
# Resposta a incidente de malware
perseus defense incident malware --target 192.168.1.100 --actions isolate collect analyze

# Resposta a violação de dados
perseus defense incident breach --target 192.168.1.50 --actions collect analyze
```

## 🛠️ Utilitários

### Testes de Conectividade
```bash
# Testar conectividade com host
perseus test connectivity 192.168.1.1

# Testar APIs de CVE
perseus test cve
```

## 🖥️ Interface Gráfica (GUI)

O Perseus inclui uma interface gráfica moderna desenvolvida em AvaloniaUI, oferecendo:

### Características da GUI
- **Interface Intuitiva**: Design moderno e responsivo
- **Modo de Segurança Ofensiva**: Interface visual para operações de segurança ofensiva
- **Modo de Segurança Defensiva**: Monitoramento em tempo real para necessidades defensivas
- **Configurações Avançadas**: Painel completo de personalização
- **Exportação de Relatórios**: Resultados em formato JSON
- **Multiplataforma**: Funciona em Windows, macOS e Linux

### Executando a GUI
```bash
# Compilar e executar a GUI
dotnet run --project Perseus.GUI

# Ou executar o binário compilado
./Perseus.GUI/bin/Debug/net8.0/Perseus.GUI
```

### Funcionalidades da GUI
- **Varredura Visual**: Interface gráfica para descoberta de hosts e portas
- **Monitoramento de Rede**: Detecção de anomalias em tempo real
- **Análise de Vulnerabilidades**: Integração com base de dados CVE
- **Relatórios Interativos**: Visualização e exportação de resultados
- **Configuração Avançada**: Personalização de parâmetros de varredura

## 🔧 Configuração

```bash
# Exibir configuração atual
perseus config show

# Exibir exemplos de uso
perseus examples

# Exibir ajuda dos modos
perseus help-modes
```

## 🏗️ Arquitetura

### Componentes Principais

- **Perseus.Core**: Lógica de negócios central e funcionalidades de rede
- **Perseus.CLI**: Interface de linha de comando
- **Perseus.Common**: Modelos de dados e utilitários compartilhados
- **Perseus.Reports**: Sistema de geração de relatórios
- **Perseus.Tests**: Testes unitários e de integração

### Módulos de Rede

- **HostDiscoverer**: Descoberta de hosts com suporte a CIDR e ranges
- **PortScanner**: Varredura de portas paralela e eficiente
- **BannerGrabber**: Captura e análise de banners de serviços
- **CveChecker**: Verificação de vulnerabilidades via NVD API

## 📊 Funcionalidades Avançadas

### Integração com CVE

O Perseus integra-se com a National Vulnerability Database (NVD) para fornecer informações atualizadas sobre vulnerabilidades:

- Consulta automática de CVEs baseada em serviços detectados
- Priorização por score CVSS
- Cache local para melhor performance
- Suporte a múltiplas fontes de dados de vulnerabilidades

### Detecção de Anomalias

O sistema de monitoramento inclui capacidades avançadas de detecção:

- Criação e comparação com baselines de rede
- Detecção de novos dispositivos
- Identificação de portas suspeitas
- Análise de padrões de tráfego

### Análise de Logs

Motor de análise de logs com suporte a múltiplos formatos:

- Detecção automática de tipo de log
- Padrões de detecção configuráveis
- Correlação de eventos
- Geração de alertas em tempo real

## 🔧 Desenvolvimento

### Estrutura do Projeto

```
Perseus/
├── Perseus.Core/           # Lógica principal
│   ├── Network/           # Módulos de rede
│   └── Vulnerability/     # Análise de vulnerabilidades
├── Perseus.CLI/           # Interface CLI
│   └── Commands/          # Comandos para segurança ofensiva e defensiva
├── Perseus.Common/        # Modelos compartilhados
├── Perseus.Reports/       # Geração de relatórios
└── Perseus.Tests/         # Testes
```

### Extensibilidade

O Perseus foi projetado para ser facilmente extensível:

- Arquitetura modular permite adição de novos módulos
- Interface de plugins para funcionalidades customizadas
- Suporte a scripts externos e ferramentas de terceiros
- API interna para integração com outras ferramentas

## 📈 Performance

### Otimizações Implementadas

- **Programação Assíncrona**: Uso extensivo de async/await para operações não-bloqueantes
- **Paralelização**: Execução paralela de varreduras e análises
- **Cache Inteligente**: Cache de resultados de CVE e DNS para reduzir latência
- **Throttling**: Controle de taxa para evitar sobrecarga de rede

### Benchmarks

Em testes internos, o Perseus demonstrou:

- Descoberta de hosts: até 254 IPs em menos de 5 segundos
- Varredura de portas: 1000 portas em menos de 10 segundos
- Consulta de CVE: cache local reduz tempo de resposta em 90%

## 🛡️ Segurança

### Práticas de Segurança Implementadas

- Validação rigorosa de entrada para prevenir injeções
- Tratamento seguro de credenciais e dados sensíveis
- Logging detalhado para auditoria
- Princípio de menor privilégio

### Considerações Éticas

O Perseus deve ser usado apenas em ambientes autorizados:

- Sempre obtenha autorização antes de executar varreduras
- Respeite os termos de serviço de APIs externas
- Use funcionalidades de stealth responsavelmente
- Documente todas as atividades para conformidade

## 📝 Contribuição

Contribuições são bem-vindas! Por favor:

1. Fork o repositório
2. Crie uma branch para sua feature
3. Implemente testes para novas funcionalidades
4. Envie um pull request com descrição detalhada

## 📄 Licença

Este projeto está licenciado sob a MIT License - veja o arquivo LICENSE para detalhes.

## 🤝 Suporte

Para suporte e questões:

- Abra uma issue no repositório
- Consulte a documentação técnica
- Participe das discussões da comunidade

---

**Desenvolvido por:** goetiaDEv  
**Baseado em:** Projeto Helius 
**Versão:** 1.0.0  
**Data:** 2025



