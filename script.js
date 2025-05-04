let lastEncrypted = null;
let lastDecrypted = null;
let lastOutputFormat = "BASE64";

// Variáveis para armazenar os resultados do AES
let lastAesKey = null;
let lastAesIv = null;
let lastAesCiphertext = null;
let lastAesOutputFormat = "BASE64";

// Variável para armazenar resultado da descriptografia AES
let lastAesDecrypted = null;

// Variáveis para armazenar os resultados do Envelope Digital
let lastEnvelopeKey = null;
let lastEnvelopeIv = null;
let lastEnvelopeCipher = null;
let lastEnvelopeOutputFormat = "BASE64";
let lastOpenEnvelopeContent = null;

// Função para gerar chaves RSA
function generateRSAKeys() {
    const keySize = parseInt(document.getElementById('keySize').value);
    const rsaKeyPair = forge.pki.rsa.generateKeyPair({ bits: keySize, e: 0x10001 });
    const publicKeyPem = forge.pki.publicKeyToPem(rsaKeyPair.publicKey);
    const privateKeyPem = forge.pki.privateKeyToPem(rsaKeyPair.privateKey);
    
    document.getElementById('publicKey').value = publicKeyPem;
    document.getElementById('privateKey').value = privateKeyPem;
}

// Atualizar o rótulo do tamanho da chave AES quando a seleção mudar
document.querySelectorAll('input[name="aesKeySize"]').forEach(radio => {
    radio.addEventListener('change', function() {
        document.getElementById('aesKeyBitLabel').textContent = this.value;
    });
});

// Mostrar/ocultar o campo IV baseado no modo de operação AES
document.querySelectorAll('input[name="aesMode"]').forEach(radio => {
    radio.addEventListener('change', function() {
        const ivContainer = document.getElementById('aesIvContainer');
        ivContainer.style.display = this.value === 'CBC' ? 'block' : 'none';
    });
});

// Função para trocar entre as abas de entrada AES
function switchAesTab(tab) {
    document.getElementById('tabAesText').classList.remove('active');
    document.getElementById('tabAesFile').classList.remove('active');
    document.getElementById('contentAesText').classList.remove('active');
    document.getElementById('contentAesFile').classList.remove('active');
    
    document.getElementById('tabAes' + tab).classList.add('active');
    document.getElementById('contentAes' + tab).classList.add('active');
}

// Função para alternar entre as abas de entrada para descriptografia AES
function switchAesDecTab(tab) {
    document.getElementById('tabAesDecText').classList.remove('active');
    document.getElementById('tabAesDecFile').classList.remove('active');
    document.getElementById('contentAesDecText').classList.remove('active');
    document.getElementById('contentAesDecFile').classList.remove('active');
    
    document.getElementById('tabAesDec' + tab).classList.add('active');
    document.getElementById('contentAesDec' + tab).classList.add('active');
}

// Função para mostrar/ocultar o campo de IV
function toggleIvField(show) {
    document.getElementById('aesDecIvContainer').style.display = show ? 'block' : 'none';
}

// Inicializar a visibilidade do campo IV (CBC é o padrão, então mostramos)
document.addEventListener('DOMContentLoaded', function() {
    toggleIvField(true);
});

// Atualizar o rótulo do formato de saída quando a seleção mudar
document.querySelectorAll('input[name="outputFormat"]').forEach(radio => {
    radio.addEventListener('change', function() {
        document.getElementById('outputFormatLabel').textContent = this.value;
        lastOutputFormat = this.value;
    });
});

// Função para carregar a chave pública do arquivo .pem
function loadPublicKeyFromFile(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = function(event) {
            try {
                const pemContent = event.target.result;
                const publicKey = forge.pki.publicKeyFromPem(pemContent);
                resolve(publicKey);
            } catch (error) {
                reject('Erro ao carregar a chave pública: ' + error.message);
            }
        };
        reader.onerror = function() {
            reject('Erro ao ler o arquivo.');
        };
        reader.readAsText(file);
    });
}

// Função para carregar a chave privada do arquivo .pem
function loadPrivateKeyFromFile(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = function(event) {
            try {
                const pemContent = event.target.result;
                const privateKey = forge.pki.privateKeyFromPem(pemContent);
                resolve(privateKey);
            } catch (error) {
                reject('Erro ao carregar a chave privada: ' + error.message);
            }
        };
        reader.onerror = function() {
            reject('Erro ao ler o arquivo.');
        };
        reader.readAsText(file);
    });
}

// Função para ler o conteúdo de um arquivo de texto
function readTextFile(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = function(event) {
            resolve(event.target.result);
        };
        reader.onerror = function() {
            reject('Erro ao ler o arquivo.');
        };
        reader.readAsText(file);
    });
}

// Função para criptografar a mensagem com RSA
async function cryptMessage() {
    console.log('Iniciando a criptografia RSA...');
    const message = document.getElementById('messageInput').value;
    if (!message.trim()) {
        alert('Por favor, digite uma mensagem para criptografar.');
        return;
    }
    
    const fileInput = document.getElementById('encryptKeyFile');
    const textInput = document.getElementById('encryptKeyText').value.trim();
    if (!fileInput.files.length && !textInput) {
        alert('Por favor, carregue um arquivo .pem com a chave pública ou cole a chave pública.');
        return;
    }
    
    const outputFormat = document.querySelector('input[name="outputFormat"]:checked').value;
    const file = fileInput.files[0];

    try {
        // Carregar a chave pública do arquivo .pem ou do textarea
        let publicKey;
        if (file) {
            publicKey = await loadPublicKeyFromFile(file);
        } else {
            publicKey = forge.pki.publicKeyFromPem(textInput);
        }
        
        // Criptografar a mensagem com a chave pública usando PKCS#1 v1.5
        const encrypted = publicKey.encrypt(message, 'RSAES-PKCS1-V1_5');
        
        // Codificar o resultado no formato escolhido
        let encodedOutput;
        if (outputFormat === 'BASE64') {
            encodedOutput = forge.util.encode64(encrypted);
        } else { // HEX
            encodedOutput = forge.util.bytesToHex(encrypted);
        }
        
        lastEncrypted = encodedOutput;
        lastOutputFormat = outputFormat;
        
        // Exibir a mensagem criptografada
        document.getElementById('encryptedMessage').textContent = encodedOutput;
        
        // Mostrar o botão de download
        document.getElementById('downloadEncBtn').style.display = 'inline-block';
    } catch (error) {
        alert('Erro: ' + error);
        console.error(error);
    }
}

// Função para criptografar com AES
async function encryptAES() {
    console.log('Iniciando a criptografia AES...');
    
    try {
        // 1. Obter os dados para criptografar
        let plaintext;
        if (document.getElementById('tabAesText').classList.contains('active')) {
            plaintext = document.getElementById('aesTextInput').value;
            if (!plaintext.trim()) {
                alert('Por favor, digite um texto para criptografar.');
                return;
            }
        } else {
            const fileInput = document.getElementById('aesFileInput');
            if (!fileInput.files.length) {
                alert('Por favor, selecione um arquivo para criptografar.');
                return;
            }
            plaintext = await readTextFile(fileInput.files[0]);
        }
        
        // 2. Obter as configurações selecionadas
        const keySize = parseInt(document.querySelector('input[name="aesKeySize"]:checked').value);
        const mode = document.querySelector('input[name="aesMode"]:checked').value;
        const outputFormat = document.querySelector('input[name="aesOutputFormat"]:checked').value;
        lastAesOutputFormat = outputFormat;
        
        // 3. Gerar uma chave AES verdadeiramente aleatória
        const keyBytes = keySize / 8;
        const aesKey = forge.random.getBytesSync(keyBytes);
        console.log(`Chave AES de ${keySize} bits gerada`);
        
        // 4. Configurar o vetor de inicialização para CBC
        let iv = null;
        if (mode === 'CBC') {
            iv = forge.random.getBytesSync(16); // 16 bytes (128 bits) para AES
            console.log('IV gerado para modo CBC');
        }
        
        // 5. Configurar a cifra AES
        let cipher;
        if (mode === 'CBC') {
            cipher = forge.cipher.createCipher('AES-CBC', aesKey);
            cipher.start({iv: iv});
        } else { // ECB
            cipher = forge.cipher.createCipher('AES-ECB', aesKey);
            cipher.start();
        }
        
        // 6. Criptografar os dados
        cipher.update(forge.util.createBuffer(plaintext, 'utf8'));
        cipher.finish();
        
        // 7. Obter o texto cifrado
        const ciphertext = cipher.output.getBytes();
        
        // 8. Codificar os resultados no formato escolhido
        let formattedKey, formattedIv, formattedCiphertext;
        
        if (outputFormat === 'BASE64') {
            formattedKey = forge.util.encode64(aesKey);
            formattedCiphertext = forge.util.encode64(ciphertext);
            formattedIv = mode === 'CBC' ? forge.util.encode64(iv) : null;
        } else { // HEX
            formattedKey = forge.util.bytesToHex(aesKey);
            formattedCiphertext = forge.util.bytesToHex(ciphertext);
            formattedIv = mode === 'CBC' ? forge.util.bytesToHex(iv) : null;
        }
        
        // 9. Armazenar os dados formatados para possível download
        lastAesKey = formattedKey;
        lastAesIv = formattedIv;
        lastAesCiphertext = formattedCiphertext;
        
        // 10. Exibir os resultados
        document.getElementById('aesKeyOutput').textContent = formattedKey;
        document.getElementById('aesCipherOutput').textContent = formattedCiphertext;
        
        if (mode === 'CBC') {
            document.getElementById('aesIvOutput').textContent = formattedIv;
            document.getElementById('aesIvContainer').style.display = 'block';
        } else {
            document.getElementById('aesIvContainer').style.display = 'none';
        }
        
        document.getElementById('aesResultContainer').style.display = 'block';
        
    } catch (error) {
        alert('Erro na criptografia AES: ' + error.message);
        console.error(error);
    }
}

// Função para descriptografar a mensagem com RSA
async function decryptMessage() {
    console.log('Iniciando a descriptografia RSA...');
    
    // Verificar se uma chave privada foi carregada
    const keyFileInput = document.getElementById('decryptKeyFile');
    const keyTextInput = document.getElementById('decryptKeyText').value.trim();
    if (!keyFileInput.files.length && !keyTextInput) {
        alert('Por favor, carregue um arquivo .pem com a chave privada ou cole a chave privada.');
        return;
    }
    
    // Obter a mensagem criptografada - seja do textarea ou do arquivo
    let encryptedData;
    const textareaInput = document.getElementById('encryptedInput').value.trim();
    const fileInput = document.getElementById('encryptedFile');
    const inputFormat = document.querySelector('input[name="inputFormat"]:checked').value;
    
    if (textareaInput) {
        encryptedData = textareaInput;
    } else if (fileInput.files.length) {
        try {
            encryptedData = await readTextFile(fileInput.files[0]);
        } catch (error) {
            alert('Erro ao ler o arquivo cifrado: ' + error);
            return;
        }
    } else {
        alert('Por favor, forneça uma mensagem criptografada no campo de texto ou selecione um arquivo.');
        return;
    }
    
    try {
        // Carregar a chave privada
        let privateKey;
        if (keyFileInput.files.length) {
            privateKey = await loadPrivateKeyFromFile(keyFileInput.files[0]);
        } else {
            privateKey = forge.pki.privateKeyFromPem(keyTextInput);
        }
        
        // Converter a mensagem criptografada para bytes, dependendo do formato
        let encryptedBytes;
        if (inputFormat === 'BASE64') {
            encryptedBytes = forge.util.decode64(encryptedData);
        } else { // HEX
            encryptedBytes = forge.util.hexToBytes(encryptedData);
        }
        
        // Descriptografar a mensagem
        const decryptedText = privateKey.decrypt(encryptedBytes, 'RSAES-PKCS1-V1_5');
        lastDecrypted = decryptedText;
        
        // Exibir a mensagem descriptografada
        document.getElementById('decryptedMessage').textContent = decryptedText;
        
        // Mostrar o botão de download
        document.getElementById('downloadDecBtn').style.display = 'inline-block';
    } catch (error) {
        alert('Erro na descriptografia: ' + error);
        console.error(error);
        document.getElementById('decryptedMessage').textContent = "Erro ao descriptografar a mensagem.";
    }
}

// Função para descriptografar com AES
async function decryptAES() {
    console.log('Iniciando a descriptografia AES...');
    
    try {
        // 1. Obter o texto cifrado
        let ciphertext;
        if (document.getElementById('tabAesDecText').classList.contains('active')) {
            ciphertext = document.getElementById('aesDecTextInput').value.trim();
            if (!ciphertext) {
                alert('Por favor, insira o texto cifrado.');
                return;
            }
        } else {
            const fileInput = document.getElementById('aesDecFileInput');
            if (!fileInput.files.length) {
                alert('Por favor, selecione um arquivo com o texto cifrado.');
                return;
            }
            ciphertext = await readTextFile(fileInput.files[0]);
        }
        
        // 2. Obter a chave AES
        let aesKeyFormatted = document.getElementById('aesKeyInput').value.trim();
        if (!aesKeyFormatted) {
            alert('Por favor, insira a chave AES.');
            return;
        }
        
        // 3. Obter o IV, se necessário
        const mode = document.querySelector('input[name="aesDecMode"]:checked').value;
        let iv = null;
        if (mode === 'CBC') {
            const ivFormatted = document.getElementById('aesIvInput').value.trim();
            if (!ivFormatted) {
                alert('Para o modo CBC, é necessário fornecer o IV.');
                return;
            }
            iv = ivFormatted;
        }
        
        // 4. Obter as configurações
        const keySize = parseInt(document.querySelector('input[name="aesDecKeySize"]:checked').value);
        const inputFormat = document.querySelector('input[name="aesDecInputFormat"]:checked').value;
        
        // 5. Verificar o tamanho da chave de acordo com o formato
        const requiredKeyLength = keySize / 8;
        let aesKey;
        
        if (inputFormat === 'BASE64') {
            try {
                aesKey = forge.util.decode64(aesKeyFormatted);
            } catch (error) {
                alert('A chave AES não parece estar em formato Base64 válido.');
                return;
            }
        } else { // HEX
            if (!/^[0-9A-Fa-f]+$/.test(aesKeyFormatted)) {
                alert('A chave AES não parece estar em formato hexadecimal válido.');
                return;
            }
            aesKey = forge.util.hexToBytes(aesKeyFormatted);
        }
        
        if (aesKey.length !== requiredKeyLength) {
            alert(`A chave AES tem ${aesKey.length * 8} bits, mas o tamanho selecionado é ${keySize} bits.`);
            return;
        }
        
        // 6. Processar IV se estiver em modo CBC
        if (mode === 'CBC') {
            if (inputFormat === 'BASE64') {
                try {
                    iv = forge.util.decode64(iv);
                } catch (error) {
                    alert('O IV não parece estar em formato Base64 válido.');
                    return;
                }
            } else { // HEX
                if (!/^[0-9A-Fa-f]+$/.test(iv)) {
                    alert('O IV não parece estar em formato hexadecimal válido.');
                    return;
                }
                iv = forge.util.hexToBytes(iv);
            }
            
            if (iv.length !== 16) { // IV deve ter 16 bytes (128 bits) para AES
                alert(`O IV deve ter 16 bytes (128 bits), mas tem ${iv.length} bytes.`);
                return;
            }
        }
        
        // 7. Processar o texto cifrado
        let encryptedBytes;
        if (inputFormat === 'BASE64') {
            try {
                encryptedBytes = forge.util.decode64(ciphertext);
            } catch (error) {
                alert('O texto cifrado não parece estar em formato Base64 válido.');
                return;
            }
        } else { // HEX
            if (!/^[0-9A-Fa-f]+$/.test(ciphertext)) {
                alert('O texto cifrado não parece estar em formato hexadecimal válido.');
                return;
            }
            encryptedBytes = forge.util.hexToBytes(ciphertext);
        }
        
        // 8. Configurar a decifra AES
        let decipher;
        if (mode === 'CBC') {
            decipher = forge.cipher.createDecipher('AES-CBC', aesKey);
            decipher.start({iv: iv});
        } else { // ECB
            decipher = forge.cipher.createDecipher('AES-ECB', aesKey);
            decipher.start();
        }
        
        // 9. Decifrar os dados
        decipher.update(forge.util.createBuffer(encryptedBytes));
        const result = decipher.finish();
        
        if (!result) {
            alert('Falha na descriptografia. Verifique a chave, IV e o formato dos dados.');
            return;
        }
        
        // 10. Obter o texto decifrado
        const decrypted = decipher.output.toString('utf8');
        lastAesDecrypted = decrypted;
        
        // 11. Mostrar o resultado
        document.getElementById('aesDecOutput').textContent = decrypted;
        document.getElementById('aesDecResultContainer').style.display = 'block';
        document.getElementById('downloadAesDecBtn').style.display = 'inline-block';
        
    } catch (error) {
        alert('Erro na descriptografia AES: ' + error.message);
        console.error(error);
    }
}

// Função para baixar o conteúdo criptografado RSA como arquivo
function downloadEncrypted() {
    if (!lastEncrypted) {
        alert('Nenhum conteúdo criptografado disponível.');
        return;
    }
    
    const fileExtension = lastOutputFormat.toLowerCase();
    const filename = `mensagem_cifrada.${fileExtension}`;
    
    const blob = new Blob([lastEncrypted], {type: 'text/plain'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// Função para baixar os resultados da criptografia AES
function downloadAesOutput(elementId, defaultFilename) {
    const content = document.getElementById(elementId).textContent;
    if (!content) {
        alert('Nenhum conteúdo disponível para download.');
        return;
    }
    
    const blob = new Blob([content], {type: 'text/plain'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = defaultFilename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// Função para baixar o conteúdo descriptografado como arquivo
function downloadDecrypted() {
    if (!lastDecrypted) {
        alert('Nenhum conteúdo descriptografado disponível.');
        return;
    }
    
    const blob = new Blob([lastDecrypted], {type: 'text/plain'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'mensagem_decifrada.txt';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// Função para baixar o conteúdo descriptografado AES
function downloadAesDecrypted() {
    if (!lastAesDecrypted) {
        alert('Nenhum conteúdo AES descriptografado disponível.');
        return;
    }
    
    const blob = new Blob([lastAesDecrypted], {type: 'text/plain'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'texto_descriptografado_aes.txt';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// Detecção automática de formato ao colar ou carregar conteúdo
function detectFormat(text) {
    // Verificar se o texto parece ser hexadecimal
    const hexRegex = /^[0-9A-Fa-f]+$/;
    if (hexRegex.test(text)) {
        document.querySelector('input[name="inputFormat"][value="HEX"]').checked = true;
        return;
    }
    
    // Verificar se o texto parece ser Base64 (pode conter A-Z, a-z, 0-9, +, /, =)
    const base64Regex = /^[A-Za-z0-9+/=]+$/;
    if (base64Regex.test(text)) {
        document.querySelector('input[name="inputFormat"][value="BASE64"]').checked = true;
        return;
    }
    
    // Se não conseguir detectar, não muda a seleção
}

// Evento para carregar automaticamente o texto criptografado no textarea quando um arquivo é selecionado
document.getElementById('encryptedFile').addEventListener('change', async function(event) {
    if (this.files.length) {
        try {
            const content = await readTextFile(this.files[0]);
            document.getElementById('encryptedInput').value = content;
            detectFormat(content);
        } catch (error) {
            console.error('Erro ao ler arquivo:', error);
        }
    }
});

// Detectar formato quando o usuário cola texto no campo
document.getElementById('encryptedInput').addEventListener('paste', function(event) {
    // Usar setTimeout para garantir que o texto já foi colado
    setTimeout(() => {
        detectFormat(this.value);
    }, 100);
});

// Detecção automática do formato de entrada AES
document.getElementById('aesDecTextInput').addEventListener('paste', function(event) {
    // Usar setTimeout para garantir que o texto já foi colado
    setTimeout(() => detectAesInputFormat(this.value), 100);
});

document.getElementById('aesKeyInput').addEventListener('paste', function(event) {
    setTimeout(() => detectAesInputFormat(this.value), 100);
});

document.getElementById('aesIvInput').addEventListener('paste', function(event) {
    setTimeout(() => detectAesInputFormat(this.value), 100);
});

// Evento para carregar arquivo cifrado
document.getElementById('aesDecFileInput').addEventListener('change', async function(event) {
    if (this.files.length) {
        try {
            const content = await readTextFile(this.files[0]);
            detectAesInputFormat(content);
        } catch (error) {
            console.error('Erro ao ler arquivo:', error);
        }
    }
});

// Função para detectar formato de entrada AES (BASE64 ou HEX)
function detectAesInputFormat(text) {
    if (!text) return;
    
    // Verificar se o texto parece ser hexadecimal
    const hexRegex = /^[0-9A-Fa-f]+$/;
    if (hexRegex.test(text)) {
        document.querySelector('input[name="aesDecInputFormat"][value="HEX"]').checked = true;
        return;
    }
    
    // Verificar se o texto parece ser Base64
    const base64Regex = /^[A-Za-z0-9+/=]+$/;
    if (base64Regex.test(text)) {
        document.querySelector('input[name="aesDecInputFormat"][value="BASE64"]').checked = true;
        return;
    }
}

// Atualizar visibilidade do campo IV quando o modo é alterado
document.querySelectorAll('input[name="aesDecMode"]').forEach(radio => {
    radio.addEventListener('change', function() {
        toggleIvField(this.value === 'CBC');
    });
});

// Função para trocar entre as abas do envelope digital
function switchEnvelopeTab(tab) {
    document.getElementById('tabEnvelopeText').classList.remove('active');
    document.getElementById('tabEnvelopeFile').classList.remove('active');
    document.getElementById('contentEnvelopeText').classList.remove('active');
    document.getElementById('contentEnvelopeFile').classList.remove('active');
    
    document.getElementById('tabEnvelope' + tab).classList.add('active');
    document.getElementById('contentEnvelope' + tab).classList.add('active');
}

// Função para mostrar/ocultar o campo IV no envelope digital
function toggleOpenEnvelopeIvField(show) {
    document.getElementById('openEnvelopeIvContainer').style.display = show ? 'block' : 'none';
}

// Inicializar a visibilidade do campo IV (CBC é o padrão)
document.addEventListener('DOMContentLoaded', function() {
    toggleOpenEnvelopeIvField(true);
    
    // Atualizar rótulos quando as opções mudam
    document.querySelectorAll('input[name="envelopeKeySize"]').forEach(radio => {
        radio.addEventListener('change', function() {
            // Possível atualização de rótulos se necessário
        });
    });
    
    // Mostrar/ocultar o campo IV baseado no modo de operação
    document.querySelectorAll('input[name="envelopeMode"]').forEach(radio => {
        radio.addEventListener('change', function() {
            const ivContainer = document.getElementById('envelopeIvContainer');
            ivContainer.style.display = this.value === 'CBC' ? 'block' : 'none';
        });
    });
    
    // Atualizar visibilidade do campo IV quando o modo é alterado
    document.querySelectorAll('input[name="openEnvelopeMode"]').forEach(radio => {
        radio.addEventListener('change', function() {
            toggleOpenEnvelopeIvField(this.value === 'CBC');
        });
    });
});

// Função para criar um envelope digital (chave AES cifrada com RSA + conteúdo cifrado com AES)
async function createDigitalEnvelope() {
    console.log('Iniciando a criação do envelope digital...');
    
    try {
        // 1. Verificar se a chave pública RSA foi carregada
        const rsaKeyFileInput = document.getElementById('envelopeRsaKeyFile');
        if (!rsaKeyFileInput.files.length) {
            alert('Por favor, selecione o arquivo da chave pública RSA (.pem).');
            return;
        }
        
        // 2. Obter o texto/arquivo para criptografar
        let plaintext;
        if (document.getElementById('tabEnvelopeText').classList.contains('active')) {
            plaintext = document.getElementById('envelopeTextInput').value;
            if (!plaintext.trim()) {
                alert('Por favor, digite um texto para criptografar.');
                return;
            }
        } else {
            const fileInput = document.getElementById('envelopeFileInput');
            if (!fileInput.files.length) {
                alert('Por favor, selecione um arquivo para criptografar.');
                return;
            }
            plaintext = await readTextFile(fileInput.files[0]);
        }
        
        // 3. Obter as configurações selecionadas
        const keySize = parseInt(document.querySelector('input[name="envelopeKeySize"]:checked').value);
        const mode = document.querySelector('input[name="envelopeMode"]:checked').value;
        const outputFormat = document.querySelector('input[name="envelopeOutputFormat"]:checked').value;
        lastEnvelopeOutputFormat = outputFormat;
        
        // 4. Carregar a chave pública RSA
        const publicKey = await loadPublicKeyFromFile(rsaKeyFileInput.files[0]);
        
        // 5. Gerar uma chave AES aleatória
        const keyBytes = keySize / 8;
        const aesKey = forge.random.getBytesSync(keyBytes);
        console.log(`Chave AES de ${keySize} bits gerada para o envelope digital`);
        
        // 6. Converter a chave AES para o formato especificado (Base64 ou Hex) antes da criptografia RSA
        let formattedAesKey;
        if (outputFormat === 'BASE64') {
            formattedAesKey = forge.util.encode64(aesKey);
        } else { // HEX
            formattedAesKey = forge.util.bytesToHex(aesKey);
        }
        
        // 7. Cifrar a chave AES formatada com RSA
        const encryptedAesKey = publicKey.encrypt(formattedAesKey, 'RSAES-PKCS1-V1_5');
        
        // 8. Configurar o IV para o modo CBC
        let iv = null;
        if (mode === 'CBC') {
            iv = forge.random.getBytesSync(16); // 16 bytes (128 bits) para AES
            console.log('IV gerado para modo CBC');
        }
        
        // 9. Configurar a cifra AES
        let cipher;
        if (mode === 'CBC') {
            cipher = forge.cipher.createCipher('AES-CBC', aesKey);
            cipher.start({iv: iv});
        } else { // ECB
            cipher = forge.cipher.createCipher('AES-ECB', aesKey);
            cipher.start();
        }
        
        // 10. Criptografar os dados com AES
        cipher.update(forge.util.createBuffer(plaintext, 'utf8'));
        cipher.finish();
        
        // 11. Obter o texto cifrado
        const ciphertext = cipher.output.getBytes();
        
        // 12. Codificar os resultados para exibição
        let formattedEncKey, formattedIv, formattedCiphertext;
        
        if (outputFormat === 'BASE64') {
            formattedEncKey = forge.util.encode64(encryptedAesKey);
            formattedCiphertext = forge.util.encode64(ciphertext);
            formattedIv = mode === 'CBC' ? forge.util.encode64(iv) : null;
        } else { // HEX
            formattedEncKey = forge.util.bytesToHex(encryptedAesKey);
            formattedCiphertext = forge.util.bytesToHex(ciphertext);
            formattedIv = mode === 'CBC' ? forge.util.bytesToHex(iv) : null;
        }
        
        // 13. Armazenar os resultados
        lastEnvelopeKey = formattedEncKey;
        lastEnvelopeCipher = formattedCiphertext;
        lastEnvelopeIv = formattedIv;
        
        // 14. Exibir os resultados
        document.getElementById('envelopeKeyOutput').textContent = formattedEncKey;
        document.getElementById('envelopeCipherOutput').textContent = formattedCiphertext;
        
        if (mode === 'CBC') {
            document.getElementById('envelopeIvOutput').textContent = formattedIv;
            document.getElementById('envelopeIvContainer').style.display = 'block';
        } else {
            document.getElementById('envelopeIvContainer').style.display = 'none';
        }
        
        document.getElementById('envelopeResultContainer').style.display = 'block';
        
    } catch (error) {
        alert('Erro na criação do envelope digital: ' + error.message);
        console.error(error);
    }
}

// Função para abrir o envelope digital
async function openDigitalEnvelope() {
    console.log('Iniciando a abertura do envelope digital...');
    
    try {
        // 1. Verificar se a chave privada RSA foi carregada
        const rsaKeyFileInput = document.getElementById('openEnvelopeKeyFile');
        if (!rsaKeyFileInput.files.length) {
            alert('Por favor, carregue um arquivo .pem com a chave privada RSA.');
            return;
        }
        
        // 2. Obter os dados cifrados
        const encryptedKeyText = document.getElementById('encryptedKeyInput').value.trim();
        if (!encryptedKeyText) {
            alert('Por favor, insira a chave AES cifrada com RSA.');
            return;
        }
        
        const encryptedContent = document.getElementById('envelopeCipherInput').value.trim();
        if (!encryptedContent) {
            alert('Por favor, insira o conteúdo cifrado com AES.');
            return;
        }
        
        // 3. Obter o IV se necessário
        const mode = document.querySelector('input[name="openEnvelopeMode"]:checked').value;
        let ivText = null;
        if (mode === 'CBC') {
            ivText = document.getElementById('envelopeIvInput').value.trim();
            if (!ivText) {
                alert('Para o modo CBC, é necessário fornecer o IV.');
                return;
            }
        }
        
        // 4. Obter outras configurações
        const keySize = parseInt(document.querySelector('input[name="openEnvelopeKeySize"]:checked').value);
        const inputFormat = document.querySelector('input[name="openEnvelopeFormat"]:checked').value;
        
        // 5. Carregar a chave privada RSA
        const privateKey = await loadPrivateKeyFromFile(rsaKeyFileInput.files[0]);
        
        // 6. Converter os dados do formato de entrada
        let encryptedKeyBytes, encryptedContentBytes, ivBytes = null;
        
        if (inputFormat === 'BASE64') {
            try {
                encryptedKeyBytes = forge.util.decode64(encryptedKeyText);
                encryptedContentBytes = forge.util.decode64(encryptedContent);
                if (mode === 'CBC') {
                    ivBytes = forge.util.decode64(ivText);
                }
            } catch (error) {
                alert('Erro ao decodificar os dados Base64: ' + error.message);
                return;
            }
        } else { // HEX
            try {
                if (!/^[0-9A-Fa-f]+$/.test(encryptedKeyText) || 
                    !/^[0-9A-Fa-f]+$/.test(encryptedContent) ||
                    (mode === 'CBC' && !/^[0-9A-Fa-f]+$/.test(ivText))) {
                    alert('Os dados não parecem estar em formato hexadecimal válido.');
                    return;
                }
                encryptedKeyBytes = forge.util.hexToBytes(encryptedKeyText);
                encryptedContentBytes = forge.util.hexToBytes(encryptedContent);
                if (mode === 'CBC') {
                    ivBytes = forge.util.hexToBytes(ivText);
                }
            } catch (error) {
                alert('Erro ao converter dados hexadecimais: ' + error.message);
                return;
            }
        }
        
        // 7. Descriptografar a chave AES cifrada com RSA
        let formattedAesKey;
        try {
            formattedAesKey = privateKey.decrypt(encryptedKeyBytes, 'RSAES-PKCS1-V1_5');
            console.log('Chave AES formatada decifrada:', formattedAesKey);
        } catch (error) {
            alert('Erro ao descriptografar a chave AES com RSA: ' + error.message);
            return;
        }
        
        // 8. Converter a chave AES formatada de volta para bytes
        let aesKey;
        if (inputFormat === 'BASE64') {
            try {
                aesKey = forge.util.decode64(formattedAesKey);
            } catch (error) {
                alert('A chave AES decifrada não está em um formato Base64 válido.');
                return;
            }
        } else { // HEX
            try {
                if (!/^[0-9A-Fa-f]+$/.test(formattedAesKey)) {
                    alert('A chave AES decifrada não está em um formato hexadecimal válido.');
                    return;
                }
                aesKey = forge.util.hexToBytes(formattedAesKey);
            } catch (error) {
                alert('Erro ao converter a chave AES de hexadecimal para bytes: ' + error.message);
                return;
            }
        }
        
        // 9. Verificar se o tamanho da chave AES está correto
        const requiredKeyLength = keySize / 8;
        if (aesKey.length !== requiredKeyLength) {
            alert(`A chave AES decifrada tem ${aesKey.length * 8} bits, mas o tamanho esperado é ${keySize} bits.`);
            return;
        }
        
        // 10. Verificar o IV para modo CBC
        if (mode === 'CBC') {
            if (ivBytes.length !== 16) {
                alert(`O IV deve ter 16 bytes (128 bits), mas tem ${ivBytes.length} bytes.`);
                return;
            }
        }
        
        // 11. Configurar a decifra AES
        let decipher;
        if (mode === 'CBC') {
            decipher = forge.cipher.createDecipher('AES-CBC', aesKey);
            decipher.start({iv: ivBytes});
        } else { // ECB
            decipher = forge.cipher.createDecipher('AES-ECB', aesKey);
            decipher.start();
        }
        
        // 12. Decifrar os dados
        decipher.update(forge.util.createBuffer(encryptedContentBytes));
        const result = decipher.finish();
        
        if (!result) {
            alert('Falha na descriptografia do conteúdo. Verifique os dados e as configurações.');
            return;
        }
        
        // 13. Obter o texto decifrado
        const decrypted = decipher.output.toString('utf8');
        lastOpenEnvelopeContent = decrypted;
        
        // 14. Mostrar o resultado
        document.getElementById('openEnvelopeOutput').textContent = decrypted;
        document.getElementById('openEnvelopeResultContainer').style.display = 'block';
        document.getElementById('downloadOpenEnvelopeBtn').style.display = 'inline-block';
        
    } catch (error) {
        alert('Erro na abertura do envelope digital: ' + error.message);
        console.error(error);
    }
}

// Função para baixar componentes do envelope digital
function downloadEnvelopeOutput(elementId, defaultFilename) {
    const content = document.getElementById(elementId).textContent;
    if (!content) {
        alert('Nenhum conteúdo disponível para download.');
        return;
    }
    
    const blob = new Blob([content], {type: 'text/plain'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = defaultFilename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// Função para baixar o conteúdo decifrado do envelope digital
function downloadOpenEnvelopeContent() {
    if (!lastOpenEnvelopeContent) {
        alert('Nenhum conteúdo decifrado disponível.');
        return;
    }
    
    const blob = new Blob([lastOpenEnvelopeContent], {type: 'text/plain'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'conteudo_decifrado.txt';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// Função para alternar entre as abas de envio de arquivo e entrada de texto para criptografia
function switchEncryptTab(tab) {
    document.getElementById('tabEncryptFile').classList.remove('active');
    document.getElementById('tabEncryptText').classList.remove('active');
    document.getElementById('contentEncryptFile').classList.remove('active');
    document.getElementById('contentEncryptText').classList.remove('active');
    
    document.getElementById('tabEncrypt' + tab).classList.add('active');
    document.getElementById('contentEncrypt' + tab).classList.add('active');
}

// Função para alternar entre as abas de envio de arquivo e entrada de texto para descriptografia
function switchDecryptTab(tab) {
    document.getElementById('tabDecryptFile').classList.remove('active');
    document.getElementById('tabDecryptText').classList.remove('active');
    document.getElementById('contentDecryptFile').classList.remove('active');
    document.getElementById('contentDecryptText').classList.remove('active');
    
    document.getElementById('tabDecrypt' + tab).classList.add('active');
    document.getElementById('contentDecrypt' + tab).classList.add('active');
}