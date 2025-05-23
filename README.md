# SegCompTP1

# Implementação do Algoritmo S-DES (Simplified DES)

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

Repositório contendo uma implementação educacional do algoritmo S-DES (Simplified DES), uma versão simplificada do Data Encryption Standard para fins didáticos em segurança computacional.

## 📌 **Descrição**

Este projeto implementa:

- Cifração/decifração básica do S-DES
- Modos de operação **ECB** e **CBC**
- Geração de subchaves (K1 e K2)
- Interface via linha de comando (CLI)

**Dados de exemplo do trabalho:**

- Chave: `1010000010`
- Bloco: `11010111`
- Mensagem (ECB/CBC): `11010111 01101100 10111010 11110000`
- IV (CBC): `01010101`

## 🚀 **Como Usar**

### **Opção 1: Executável (Windows)**

1. Navegue até a pasta `dist/`
2. Execute o arquivo `sdes.exe`:
   ```bash
   sdes.exe
   ```
   Ou
   clique duas vezes no arquivo `sdes.exe` para abrir a interface gráfica.
3. Siga as instruções na tela para cifrar ou decifrar uma mensagem.
4. Para cifrar uma mensagem, escolha o modo de operação (ECB ou CBC) e insira a chave e o bloco.
5. Para decifrar, insira a mensagem cifrada e a chave.
6. O resultado será exibido no terminal.
7. Para sair, digite `exit` ou `quit`.

### **Opção 2: Código Fonte (Python)**

1. Clone o repositório:
   ```bash
   git clone
   ```
2. cd SegCompTP1
   ```

   ```
3. rode o arquivo `main.py`:
   ```bash
   python main.py
   ```
