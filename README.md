## Descrição

Este script Python é uma extensão para o Burp Suite que visa identificar potenciais vulnerabilidades de XSS (Cross-Site Scripting) refletido básico em respostas HTTP. A lógica por trás da extensão é adicionar payloads que são propensos a refletir no response do request, dando assim uma indicação se a página está sanitizando corretamente cada entrada nos formulários de pesquisa.

A extensão realiza uma verificação passiva das respostas para identificar se algum campo de entrada é refletido diretamente na resposta sem ser sanitizado. O usuário pode configurar uma lista de strings `(Wordlist)` de pesquisa com (payloads XSS) que serão usadas para identificar possíveis casos de XSS refletidos.

## Funcionalidades

- Verifica de forma passiva as respostas HTTP em busca de potenciais casos de XSS refletido.
- Permite ao usuário configurar uma lista de strings de pesquisa para personalizar a detecção de XSS.

## Utilização

1. Instale a extensão no Burp Suite.
2. Acesse a guia "Settings - Payload" na interface da extensão para configurar as strings de pesquisa.
3. Execute uma varredura ativa ou passiva no Burp Suite para identificar potenciais vulnerabilidades de XSS refletido.

## Instalação

1. Baixe o arquivo Jython [jython-standalone-2.7.2.jar](https://www.jython.org/download) e adicione-o ao Burp Suite nas configurações do extender.
2. Baixe o arquivo `potentialxss.py` e adicione-o ao Burp Suite nas configurações do extender.

## Requisitos

- Burp Suite
- Jython 2.7.2

## Exemplo

Após configurar a extensão e executar uma varredura no Burp Suite, a extensão identificará se há algum campo de entrada refletido diretamente na resposta, indicando a possibilidade de XSS refletido.
