## Descrições  

# XSS Detector

A Extensão XSS Detector foi desenvolvida em Python utilizando o Modulo API do Burp Suite. Analisa todo e qualquer tipo de reposta HTTP através do Scanner Passivo em busca de potenciais XSS (Cross-Site Scripting) refletido. A lógica por trás da extensão é identificar se há alguma ``tag`` de entrada que está sendo refletido diretamente dentro de outra tag e unitilizando a mesma, quando identificado a Extensão irá gerar um Issue no Burp Suite com gravidade alta devido a falta de sanitização adequada.

Exemplo: 
```<h1>0 search results for '<script> Ola' /h1>```

_Nexte exemplo conseguimos identificar que a tag "<script>" foi adicionada dentro da tags `<h1> </h1>`, isso quebrou a tag </h1> e a tag <script> passou a ser interpretado, isso é falta de sanitização, essa é a lógica da extensão. Sempre que uma tag for adicionada e inativando a outra e sendo interpretada como parte do código html_ 

# PotentialXSS

Este script Python é uma extensão para o Burp Suite que visa identificar potenciais vulnerabilidades de XSS (Cross-Site Scripting) refletido básico em respostas HTTP. A lógica por trás da extensão é adicionar payloads que são propensos a refletir no response do request, dando assim uma indicação se a página está sanitizando corretamente cada entrada nos formulários de pesquisa.

A extensão realiza uma verificação passiva das respostas para identificar se algum campo de entrada é refletido diretamente na resposta sem ser sanitizado. O usuário pode configurar uma lista de strings `(Wordlist)` de pesquisa com (payloads XSS) que serão usadas para identificar possíveis casos de XSS refletidos.

## Funcionalidades

# XSS Detector
- Verifica de forma passiva as respostas HTTP em busca de potenciais casos de XSS refletido em tags `<script>`, `<h1>`, `<img>`, `<a>`, `<input>`, `<iframe>`, `<div>`.
- Gera um alerta caso seja identificada uma possível vulnerabilidade de XSS.

# PotentialXSS
- Verifica de forma passiva as respostas HTTP em busca de potenciais casos de XSS refletido.
- Permite ao usuário configurar uma lista de strings `(Wordlist)` de pesquisa para personalizar a detecção de XSS.

## Utilização

# XSS Detector
1. Instale a extensão no Burp Suite.
2. Navegue entre as páginas e em conjunto com varredura Live audit form proxy (all traffic) - Audit Checks - Passive no modo Capturing no Burp Suite para identificar potenciais vulnerabilidades de XSS refletido.
   
# PotentialXSS
1. Instale a extensão no Burp Suite.
2. Acesse a guia "Settings - Payload" na interface da extensão para configurar as strings de pesquisa.
3. Execute uma varredura ativa ou passiva no Burp Suite para identificar potenciais vulnerabilidades de XSS refletido.

## Instalação

1. Baixe o arquivo Jython [jython-standalone-2.7.2.jar](https://www.jython.org/download) e adicione-o ao Burp Suite nas configurações do extender.
2. Baixe o arquivo `potentialxss.py` e `xssdetector.py` e adicione-o ao Burp Suite nas configurações do extender.

## Requisitos

- Burp Suite
- Jython 2.7.2
- Python

## Exemplo

Após configurar a extensão e executar uma varredura no Burp Suite, a extensão identificará se há algum campo de entrada refletido diretamente na resposta, indicando a possibilidade de XSS refletido.

# Observação
## Utilizei o webserverxss.py como PoC para ter uma segunda perpectiva mais simples sobre a lógica do Response HTML e para evidência do teste.
