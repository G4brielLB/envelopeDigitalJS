# 📦 Sistema de Envelope Digital

## Autores
Gabriel Lopes Bastos (G4brielLB)
José Victor Vieira de Oliveira (@vickminari)
Pedro Emanuel Moreira Carvalho (@PedroEmanuelMoreiraCarvalho)

## 🔐 Introdução
A criação e abertura de envelopes digitais é uma técnica utilizada para garantir a confidencialidade e integridade de informações trocadas em meio eletrônico. O processo consiste em criptografar os dados com uma chave simétrica (geralmente aleatória) e, em seguida, proteger essa chave utilizando criptografia assimétrica. O "envelope" resultante só pode ser aberto pelo destinatário, que possui a chave privada correspondente à chave pública usada na criptografia.

## 🛠️ Implementação
O sistema foi desenvolvido com uma interface simples e funcional, utilizando:

HTML para a estrutura da interface;

CSS para a estilização;

JavaScript para a lógica de funcionamento;

Biblioteca: Node-FORGE para operações criptográficas.

Funcionalidades implementadas:
Geração de chaves públicas e privadas RSA;

Criação de envelope digital (criptografia AES + RSA);

Abertura de envelope digital (descriptografia RSA + AES);

Criptografia e descriptografia com AES;

Criptografia e descriptografia com RSA.

É possível executar o sistema localmente (via localhost) ou publicá-lo no GitHub Pages.

## ▶️ Modo de Uso
### 3.1. 🔑 Geração de Chaves RSA
Selecione o tamanho da chave: 1024 ou 2048 bits;

Clique em "Gerar Chaves";

As chaves pública e privada são exibidas e podem ser copiadas ou baixadas em .pem.

### 3.2. ✉️ Criação de Envelope Digital
Insira a chave pública RSA manualmente ou via arquivo .pem;

Escreva o texto ou envie um arquivo de texto a ser criptografado;

Escolha os parâmetros:

Tamanho da chave AES: 128, 192 ou 256 bits;

Modo de operação AES: CBC ou ECB;

Formato de saída: BASE64 ou HEX;

Clique em "Criar Envelope Digital";

Serão gerados:

Chave AES cifrada com RSA;

Vetor de Inicialização (IV), se for CBC;

Conteúdo cifrado com AES;

Todos os dados podem ser baixados individualmente.

### 3.3. 📬 Abertura de Envelope Digital
Insira a chave privada RSA (arquivo .pem ou colando);

Preencha os campos:

Chave AES cifrada com RSA;

Conteúdo cifrado com AES;

Vetor de Inicialização (se aplicável);

Selecione os mesmos parâmetros de criptografia utilizados;

Clique em "Abrir Envelope Digital" para ver o conteúdo original.

### 3.4. 🔒 Criptografia com AES
Insira o texto ou arquivo a ser criptografado;

Selecione:

Tamanho da chave AES: 128, 192, 256 bits;

Modo: CBC ou ECB;

Clique em "Criptografar com AES";

Serão exibidos:

Chave AES aleatória;

Vetor IV (se CBC);

Texto cifrado (em BASE64 ou HEX);

Todos os dados podem ser baixados.

### 3.5. 🔐 Criptografia com RSA
Insira a chave pública (arquivo .pem ou colando);

Digite a mensagem a ser criptografada;

Escolha o formato de saída: BASE64 ou HEX;

Clique em "Criptografar" e o resultado será exibido e poderá ser copiado ou baixado.

### 3.6. 🔓 Descriptografia com RSA
Insira a chave privada (arquivo .pem ou colando);

Forneça o texto cifrado (manual ou arquivo);

Escolha o formato de entrada (BASE64 ou HEX);

Clique em "Descriptografar" para obter o texto original.

### 3.7. 🧩 Descriptografia com AES
Insira:

Texto cifrado;

Chave AES;

Vetor IV (se aplicável);

Os dados podem ser inseridos manualmente ou por arquivos;

Clique em "Descriptografar com AES" para obter o texto original.
