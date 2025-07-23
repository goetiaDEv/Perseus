# Perseus GUI - Interface Gráfica de Usuário

## Visão Geral

A interface gráfica do Perseus foi desenvolvida utilizando AvaloniaUI, um framework moderno e multiplataforma para criação de aplicações desktop em .NET. Esta implementação oferece uma experiência visual intuitiva para as funcionalidades de cybersecurity do Perseus, mantendo toda a robustez e eficiência da versão CLI.

## Arquitetura da GUI

### Estrutura do Projeto

O projeto Perseus.GUI está organizado seguindo o padrão MVVM (Model-View-ViewModel), proporcionando uma separação clara entre a lógica de apresentação e a lógica de negócios:

```
Perseus.GUI/
├── ViewModels/          # Lógica de apresentação
├── Views/               # Interfaces visuais (XAML)
├── Models/              # Modelos de dados específicos da GUI
├── Utils/               # Utilitários auxiliares
└── Assets/              # Recursos visuais
```

### Tecnologias Utilizadas

- **AvaloniaUI 11.0**: Framework principal para interface gráfica
- **.NET 8.0**: Plataforma de desenvolvimento
- **Microsoft.Extensions.DependencyInjection**: Injeção de dependências
- **Microsoft.Extensions.Logging**: Sistema de logging
- **System.Text.Json**: Serialização de dados

## Funcionalidades Implementadas

### 1. Modo Attack (Segurança Ofensiva)

A interface de ataque oferece uma experiência visual completa para operações ofensivas:

#### Configuração de Varredura
- **Campo de Alvo**: Suporte para notação CIDR, ranges de IP e endereços individuais
- **Configuração de Portas**: Especificação flexível de portas (ranges, listas, individuais)
- **Parâmetros Avançados**: Timeout, número de threads, modo stealth
- **Opções de Análise**: Captura de banners e análise de vulnerabilidades

#### Resultados em Tempo Real
- **Grid de Resultados**: Exibição tabular dos hosts descobertos
- **Informações Detalhadas**: Portas abertas, serviços identificados, vulnerabilidades
- **Indicadores Visuais**: Status colorido baseado no nível de risco
- **Progresso da Varredura**: Barra de progresso e mensagens de status

### 2. Modo Defense (Segurança Defensiva)

O módulo defensivo fornece capacidades de monitoramento contínuo:

#### Monitoramento de Rede
- **Configuração de Rede**: Especificação da rede a ser monitorada
- **Intervalos Personalizáveis**: Frequência de verificação ajustável
- **Detecção de Anomalias**: Identificação automática de novos dispositivos

#### Sistema de Alertas
- **Alertas em Tempo Real**: Notificações imediatas de eventos suspeitos
- **Classificação de Severidade**: Categorização automática de alertas
- **Histórico de Eventos**: Registro completo de atividades de rede

### 3. Configurações Avançadas

O painel de configurações permite personalização completa:

#### Parâmetros de Rede
- **Timeouts Padrão**: Configuração de tempos limite
- **Concorrência**: Número de threads para operações paralelas
- **Modo Stealth**: Operações discretas para evitar detecção

#### Sistema de Logging
- **Níveis de Log**: Controle granular da verbosidade
- **Destinos de Log**: Configuração de saídas de log
- **Rotação de Logs**: Gerenciamento automático de arquivos

## Integração com Perseus.Core

A GUI mantém total compatibilidade com a lógica de negócios existente:

### Serviços Integrados

1. **HostDiscoverer**: Descoberta de hosts ativos na rede
2. **PortScanner**: Varredura de portas com detecção de serviços
3. **BannerGrabber**: Captura e análise de banners de serviços
4. **CveChecker**: Verificação de vulnerabilidades via NVD API

### Injeção de Dependências

O sistema utiliza Microsoft.Extensions.DependencyInjection para gerenciar dependências:

```csharp
services.AddSingleton<HostDiscoverer>();
services.AddSingleton<PortScanner>();
services.AddSingleton<BannerGrabber>();
services.AddSingleton<CveChecker>();
```

## Interface de Usuário

### Design System

A interface segue princípios de design moderno:

- **Paleta de Cores**: Esquema profissional com destaque para status de segurança
- **Tipografia**: Fonte Inter para máxima legibilidade
- **Iconografia**: Emojis e símbolos intuitivos para navegação
- **Layout Responsivo**: Adaptação automática a diferentes tamanhos de tela

### Navegação

A navegação é organizada em três módulos principais:

1. **🔴 Attack**: Operações de segurança ofensiva e testes de penetração
2. **🛡️ Defense**: Monitoramento e detecção de ameaças
3. **⚙️ Settings**: Configurações e preferências do sistema

### Feedback Visual

- **Indicadores de Status**: Cores e ícones para comunicar estados
- **Barras de Progresso**: Feedback visual de operações em andamento
- **Mensagens de Status**: Informações contextuais em tempo real
- **Validação de Entrada**: Verificação imediata de dados inseridos

## Exportação e Relatórios

### Formatos Suportados

A GUI oferece capacidades robustas de exportação:

- **JSON**: Dados estruturados para integração com outras ferramentas
- **Timestamps**: Marcação temporal automática de todos os resultados
- **Metadados**: Inclusão de configurações utilizadas na varredura

### Estrutura dos Relatórios

Os relatórios exportados incluem:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "target": "192.168.1.0/24",
  "configuration": {
    "ports": "1-1000",
    "timeout": 1000,
    "threads": 50
  },
  "results": [...]
}
```

## Tratamento de Erros

### Estratégias de Recuperação

A GUI implementa tratamento robusto de erros:

- **Validação de Entrada**: Verificação prévia de dados inseridos
- **Timeouts Configuráveis**: Prevenção de travamentos em operações longas
- **Cancelamento Gracioso**: Interrupção segura de operações em andamento
- **Mensagens Informativas**: Feedback claro sobre problemas encontrados

### Logging e Diagnóstico

- **Logs Estruturados**: Registro detalhado de operações
- **Níveis de Severidade**: Classificação automática de eventos
- **Contexto de Erro**: Informações detalhadas para diagnóstico

## Performance e Otimização

### Operações Assíncronas

Todas as operações de rede são executadas de forma assíncrona:

- **Threading Eficiente**: Uso otimizado de threads do sistema
- **Cancelamento Cooperativo**: Suporte a CancellationToken
- **Pooling de Conexões**: Reutilização eficiente de recursos de rede

### Gerenciamento de Memória

- **Disposable Pattern**: Liberação adequada de recursos
- **Weak References**: Prevenção de vazamentos de memória
- **Garbage Collection**: Otimização para coleta de lixo

## Segurança

### Práticas Implementadas

A GUI mantém os mesmos padrões de segurança da versão CLI:

- **Validação de Entrada**: Sanitização de todos os dados inseridos
- **Princípio do Menor Privilégio**: Execução com permissões mínimas necessárias
- **Auditoria**: Registro completo de todas as operações realizadas

### Proteção de Dados

- **Não Persistência**: Credenciais não são armazenadas localmente
- **Criptografia em Trânsito**: Comunicações seguras com APIs externas
- **Logs Sanitizados**: Remoção de informações sensíveis dos logs

## Instalação e Configuração

### Requisitos do Sistema

- **.NET 8.0 Runtime**: Necessário para execução
- **Sistema Operacional**: Windows 10+, macOS 10.15+, Linux (distribuições suportadas)
- **Memória RAM**: Mínimo 512MB, recomendado 2GB
- **Espaço em Disco**: 100MB para instalação

### Processo de Instalação

1. **Download**: Obter o pacote de instalação apropriado
2. **Extração**: Descompactar arquivos em diretório de escolha
3. **Execução**: Iniciar Perseus.GUI.exe (Windows) ou Perseus.GUI (Linux/macOS)
4. **Configuração Inicial**: Definir preferências básicas na primeira execução

## Casos de Uso

### Cenário 1: Auditoria de Segurança

Um administrador de rede precisa realizar uma auditoria completa da infraestrutura:

1. **Configuração**: Define a rede alvo (192.168.0.0/16)
2. **Varredura**: Executa descoberta de hosts e varredura de portas
3. **Análise**: Revisa serviços identificados e vulnerabilidades encontradas
4. **Relatório**: Exporta resultados para documentação de auditoria

### Cenário 2: Monitoramento Contínuo

Uma equipe de SOC implementa monitoramento proativo:

1. **Baseline**: Cria linha de base da rede corporativa
2. **Monitoramento**: Configura verificações a cada 5 minutos
3. **Alertas**: Recebe notificações de novos dispositivos
4. **Resposta**: Investiga e responde a anomalias detectadas

### Cenário 3: Teste de Penetração

Um pentester realiza avaliação de segurança:

1. **Reconhecimento**: Mapeia a superfície de ataque
2. **Enumeração**: Identifica serviços e versões
3. **Vulnerabilidades**: Correlaciona achados com base CVE
4. **Documentação**: Gera relatório detalhado para cliente

## Roadmap e Melhorias Futuras

### Funcionalidades Planejadas

- **Dashboard Executivo**: Visão consolidada de métricas de segurança
- **Integração SIEM**: Conectores para plataformas de SIEM populares
- **Automação**: Scripts personalizáveis para resposta a incidentes
- **Machine Learning**: Detecção de anomalias baseada em IA

### Melhorias de Interface

- **Temas Personalizáveis**: Suporte a temas claro e escuro
- **Layouts Adaptativos**: Interface otimizada para tablets
- **Acessibilidade**: Conformidade com padrões WCAG
- **Internacionalização**: Suporte a múltiplos idiomas

## Conclusão

A interface gráfica do Perseus representa um avanço significativo na usabilidade da ferramenta, mantendo toda a robustez técnica da versão CLI. A implementação em AvaloniaUI garante compatibilidade multiplataforma e performance otimizada, enquanto o design MVVM facilita manutenção e extensibilidade futuras.

A GUI democratiza o acesso às funcionalidades avançadas do Perseus, permitindo que profissionais de segurança de todos os níveis de experiência possam aproveitar plenamente as capacidades da ferramenta. Com sua interface intuitiva e funcionalidades abrangentes, o Perseus GUI estabelece um novo padrão para ferramentas de cybersecurity desktop.

---

*Documentação gerada por goetiaDEv - Perseus Security Scanner v1.0.0*

