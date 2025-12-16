<p align="center">
  <img src="https://cdn.discordapp.com/avatars/1445245886526394547/40b9434fff525164716e8a09a71e7071.png?size=512" alt="CryptoBot Logo" width="200"/>
</p>

<h1 align="center">🔐 Encrypty - Discord Encryption Bot</h1>

<p align="center">
  <strong>The most complete encryption bot for Discord</strong>
</p>

<p align="center">
  <em>🏆 Built for Discord Buildathon 2025 🏆</em>
</p>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-commands">Commands</a> •
  <a href="#-algorithms">Algorithms</a> •
  <a href="#-security">Security</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/Discord.py-2.0+-5865F2?style=for-the-badge&logo=discord&logoColor=white" alt="Discord.py"/>
  <img src="https://img.shields.io/badge/Encryption-AES--256-green?style=for-the-badge&logo=letsencrypt&logoColor=white" alt="Encryption"/>
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Algorithms-25+-blue?style=flat-square" alt="Algorithms"/>
  <img src="https://img.shields.io/badge/Hash_Functions-7-orange?style=flat-square" alt="Hash Functions"/>
  <img src="https://img.shields.io/badge/Storage-Encrypted-success?style=flat-square" alt="Storage"/>
  <img src="https://img.shields.io/badge/Master_Key-Global-red?style=flat-square" alt="Global Key"/>
</p>

---

## 📋 Table of Contents

- [🌟 Features](#-features)
- [🚀 Installation](#-installation)
- [⚙️ Configuration](#️-configuration)
- [💬 Commands](#-commands)
- [🔒 Encryption Algorithms](#-encryption-algorithms)
- [🛡️ Security](#️-security)
- [📁 File Structure](#-file-structure)
- [🔧 Troubleshooting](#-troubleshooting)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)

---

## 🌟 Features

<table>
<tr>
<td width="50%">

### 🔐 Advanced Encryption
- **25+ encryption algorithms**
- Classic and modern ciphers
- Authenticated encryption (AES-GCM)
- Support for multiple operation modes

</td>
<td width="50%">

### 🛡️ Secure Storage
- Data file **encrypted with AES-256-GCM**
- Passwords hashed with **PBKDF2** (100,000 iterations)
- **GLOBAL master key** (works on any server)
- Automatic backups

</td>
</tr>
<tr>
<td width="50%">

### ⚡ Bot Features
- Interface with elegant **Containers**
- Modals with selectors for data input
- Ephemeral messages for privacy
- Persistence after restarts
- Rate limiting (5s between commands)

</td>
<td width="50%">

### 🛠️ Utilities
- Secure password generator
- **Strength analyzer** with crack time
- 7 hash functions available
- Automatic message expiration (24h)

</td>
</tr>
</table>

---

## 🚀 Installation

### Prerequisites

- Python 3.10 or higher
- pip (Python package manager)
- A Discord bot created in the [Developer Portal](https://discord.com/developers/applications)

### Step 1: Clone the Repository

```bash
git clone https://github.com/your-username/cryptobot-discord.git
cd cryptobot-discord
```

### Step 2: Create Virtual Environment (Recommended)

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/macOS
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -U "discord.py[voice] @ git+https://github.com/nicholaswc/discord.py"
pip install cryptography aiohttp
```

<details>
<summary>📦 <strong>requirements.txt</strong></summary>

```txt
discord.py @ git+https://github.com/nicholaswc/discord.py
cryptography>=41.0.0
aiohttp>=3.8.0
```

</details>

### Step 4: Configure Environment Variables

```bash
# ⚠️ BOTH VARIABLES ARE MANDATORY

# Windows (PowerShell)
$env:DISCORD_BOT_TOKEN = "your_token_here"
$env:BOT_MASTER_KEY = "your_secret_master_key"

# Windows (CMD)
set DISCORD_BOT_TOKEN=your_token_here
set BOT_MASTER_KEY=your_secret_master_key

# Linux/macOS
export DISCORD_BOT_TOKEN="your_token_here"
export BOT_MASTER_KEY="your_secret_master_key"
```

### Step 5: Run the Bot

```bash
python bot.py
```

---

## ⚙️ Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DISCORD_BOT_TOKEN` | ✅ **Mandatory** | Discord bot token |
| `BOT_MASTER_KEY` | ✅ **Mandatory** | GLOBAL master key to encrypt storage |

> ⚠️ **IMPORTANT:** The `BOT_MASTER_KEY` must be the **SAME** on all servers where you run the bot. It's a GLOBAL key that allows encrypted messages to work on any server.

### Internal Configuration

You can modify these constants in `bot.py`:

```python
MESSAGE_EXPIRY_HOURS = 24      # Message expiration time
MAX_MESSAGES_STORED = 1000     # Maximum stored messages
RATE_LIMIT_SECONDS = 5         # Cooldown between commands
```

---

## 💬 Commands

### `/encrypt`
> 🔐 Encrypt a message with the algorithm and password of your choice

<img src="https://cdn.discordapp.com/attachments/1448112945732128870/1450564650281209986/image.png?ex=6942ff1a&is=6941ad9a&hm=69220733dc821dee40e31691742ad30f568f4090aceeafa88787bc246f14abb8" alt="Encrypt Command" width="500"/>

**Usage:**
1. Run `/encrypt`
2. Select the encryption method from the dropdown menu
3. Write your secret message
4. Enter a secure password
5. Share the encrypted message!

**Features:**
- 25+ available algorithms
- "Decrypt" button to decrypt
- Password saved as hash (PBKDF2)

---

### `/hash`
> 🔢 Generate hashes of text with multiple algorithms

<img src="https://cdn.discordapp.com/attachments/1448112945732128870/1450565043430096997/image.png?ex=6942ff78&is=6941adf8&hm=9eaacc508cb7f0541d7278abfb1ebcc945362a469559599d0325e3edde83cf5c" alt="Hash Command" width="500"/>

**Available algorithms:**

| Algorithm | Bits | Recommended Use |
|-----------|------|-----------------|
| MD5 | 128 | Checksums (not security) |
| SHA-1 | 160 | Legacy (not recommended) |
| SHA-256 | 256 | General use |
| SHA-512 | 512 | High security |
| SHA3-256 | 256 | Modern standard |
| BLAKE2b | 512 | High performance |
| BLAKE2s | 256 | Limited devices |

---

### `/generate_password`
> 🔑 Generate a secure random password

<img src="https://cdn.discordapp.com/attachments/1448112945732128870/1450565288750874844/image.png?ex=6942ffb3&is=6941ae33&hm=2bc12c6cdbb9d8ba0130d6ea9d6f5256d947cfea885b8e0720432cad6c7bd4bc" alt="Generate Password Command" width="500"/>

**Parameters:**
- `length` (optional): Password length (8-64, default 16)

**Example output:**
```
Generated Secure Password

Password: Kx#9mP$2vLnQ@8wR

Length: 16 characters
Strength: Very strong (95/100)
Entropy: 98.4 bits
Time to crack: 2.4 million years
```

---

### `/check_password`
> 🔍 Analyze password strength and estimate crack time

<img src="https://cdn.discordapp.com/attachments/1448112945732128870/1450565640426623097/image.png?ex=69430006&is=6941ae86&hm=48638e491719d4ed5c64c47b58631b342e9b004dfb8b013111e058bcf1d9685a" alt="Check Password Command" width="500"/>

**Parameters:**
- `password`: The password to analyze

**Information provided:**
- **Score:** Score from 0 to 100
- **Strength:** Very weak, Weak, Moderate, Strong, Very strong
- **Entropy:** Bits of entropy
- **Crack time:** Estimated at 10 trillion attempts/second

**Evaluated criteria:**
```diff
+ Length: 16 characters
+ Has lowercase letters
+ Has uppercase letters
+ Has numbers
+ Has special characters
```

**Crack time examples:**
| Password | Estimated Time |
|----------|----------------|
| `123456` | Instant |
| `password123` | 2.5 seconds |
| `MyP@ssw0rd!` | 3.2 years |
| `Kx#9mP$2vLnQ@8wR` | 2.4 million years |
| `Tr0ub4dor&3#Horse` | Longer than the age of the universe |

---

### `/crypto_info`
> ℹ️ Show information about all available encryption algorithms

<img src="https://cdn.discordapp.com/attachments/1448112945732128870/1450565844353421413/image.png?ex=69430037&is=6941aeb7&hm=0124628cfdf6ddf855ce13280a5729d3fd3fe7be64fe1277ee118e6e9bc2824a" alt="Crypto Info Command" width="500"/>

**Categories shown:**
- Classic Ciphers (9)
- Encoding Methods (6)
- Stream Ciphers (3)
- Block Ciphers (9)

---

### `/stats`
> 📊 Show bot statistics

<img src="https://cdn.discordapp.com/attachments/1448112945732128870/1450566015758106715/image.png?ex=69430060&is=6941aee0&hm=7c56a942c493a7345a4940653c6051e3fa54409b99e182bff42145f27603f94b" alt="Stats Command" width="500"/>

**Information shown:**
- Stored messages
- Available ciphers
- Hash functions
- Expiration time
- Storage limit
- Rate limit

---

### `/security_info`
> 🔒 Information about storage security status

<img src="https://cdn.discordapp.com/attachments/1448112945732128870/1450566160868315136/image.png?ex=69430082&is=6941af02&hm=f2020f90047995d6ba1f0fb9e54700c36073ccbd092c7db260cc5b6259fde040" alt="Security Info Command" width="500"/>

**Information shown:**
- Storage status (encrypted/not created)
- Master key status (configured/not configured)
- Total stored messages
- Key format (secure hash vs legacy)
- Security warnings

---

## 🔒 Encryption Algorithms

### 📜 Classic Ciphers

| Algorithm | Key | Description |
|-----------|-----|-------------|
| **Caesar** | Number | Letter shift |
| **ROT13** | None | Caesar with shift 13 |
| **Atbash** | None | Alphabet inversion |
| **Vigenère** | Word | Polyalphabetic cipher |
| **Beaufort** | Word | Vigenère variant |
| **Autokey** | Word | Auto-extended key |
| **Playfair** | Word | 5x5 matrix |
| **Columnar** | Word | Columnar transposition |
| **Rail Fence** | Number | Zigzag transposition |

### 🔤 Encodings

| Algorithm | Description |
|-----------|-------------|
| **Base64** | Standard encoding |
| **Base32** | Uppercase only |
| **Hexadecimal** | Hex representation |
| **Binary** | Binary representation |
| **Morse** | Morse code |
| **Reverse** | Reversed text |

### 🌊 Stream Ciphers

| Algorithm | Bits | Description |
|-----------|------|-------------|
| **XOR** | Variable | Simple XOR operation |
| **RC4** | Variable | Fast stream cipher |
| **ChaCha20** | 256 | Modern stream cipher |

### 🧱 Block Ciphers

| Algorithm | Bits | Mode | Description |
|-----------|------|------|-------------|
| **Fernet** | 256 | CBC+HMAC | AES with authentication |
| **AES-GCM** | 256 | GCM | Authenticated AES |
| **AES-CBC** | 256 | CBC | Classic AES |
| **AES-CTR** | 256 | CTR | AES in stream mode |
| **Triple DES** | 168 | CBC | Legacy, 3 passes |
| **Blowfish** | 448 | CBC | Fast, variable |
| **Camellia** | 256 | CBC | Japanese standard |
| **CAST5** | 128 | CBC | Used in PGP |
| **SEED** | 128 | CBC | Korean standard |

---

## 🛡️ Security

### Security Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    USER SENDS MESSAGE                        │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  1. Message encrypted with chosen algorithm + password      │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  2. Password → PBKDF2 (100,000 iterations) → Hash+Salt      │
│     ⚠️ Password is NEVER saved in plain text                │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  3. Data saved in encrypted_messages.enc                    │
│     🔐 File encrypted with AES-256-GCM + Master Key         │
│     🌐 Master key is GLOBAL (works on any server)           │
└─────────────────────────────────────────────────────────────┘
```

### Implemented Protections

| Protection | Description |
|------------|-------------|
| 🔐 **Encrypted Storage** | `.enc` file is encrypted with AES-256-GCM |
| 🔑 **Hashed Passwords** | PBKDF2 with 100,000 iterations and unique salt |
| 🌐 **Global Master Key** | Works on any server with the same key |
| ⏰ **Message Expiration** | Messages are deleted after 24 hours |
| 🚫 **Rate Limiting** | 5 seconds between commands per user |
| 📝 **Logging** | Activity log for auditing |
| 💾 **Automatic Backups** | Backup before each save |
| 🔄 **Automatic Migration** | Migrates old format to new secure format |

### Global Master Key

The master key is **MANDATORY** and must be configured as an environment variable:

```bash
# The master key MUST be the SAME on all servers
export BOT_MASTER_KEY="your_very_long_and_secure_secret_key"
```

> ⚠️ **VERY IMPORTANT:** 
> - The `BOT_MASTER_KEY` is **GLOBAL** - works on any server
> - Without this key, the bot **CANNOT START**
> - If you change the key, you **lose access to all previous messages**
> - Use a long and secure key (minimum 32 characters recommended)

### Why is it Global?

The global master key allows:
1. ✅ Use the same bot on multiple servers
2. ✅ Encrypted messages work on any server
3. ✅ Doesn't depend on local files that can be lost
4. ✅ Easy to configure on hosting services

---

## 📁 File Structure

```
cryptobot-discord/
│
├── 📄 bot.py                         # Main bot code
├── 📄 requirements.txt               # Python dependencies
├── 📄 README.md                      # This file
│
├── 🔐 encrypted_messages.enc         # Encrypted messages (AES-256-GCM)
├── 💾 encrypted_messages_backup.enc  # Automatic backup
│
├── 📝 bot.log                        # Activity log
│
└── ⚠️ encrypted_messages.json.old    # Legacy file (delete if exists)
```

### Sensitive Files (add to .gitignore)

```gitignore
# Secrets
*.enc
bot.log

# Environment
.env
venv/

# Python
__pycache__/
*.pyc
```

---

## 🔧 Troubleshooting

<details>
<summary><strong>❌ "DISCORD_BOT_TOKEN not found"</strong></summary>

Make sure to configure the environment variable:
```bash
export DISCORD_BOT_TOKEN="your_token_here"
```

</details>

<details>
<summary><strong>❌ "BOT_MASTER_KEY not found"</strong></summary>

The master key is **MANDATORY**. Configure it like this:
```bash
export BOT_MASTER_KEY="your_secret_key_here"
```

This key must be the SAME on all servers where you run the bot.

</details>

<details>
<summary><strong>❌ "Error decrypting storage"</strong></summary>

Possible causes:
1. Master key changed → Use the original key
2. Corrupted file → Use the backup `encrypted_messages_backup.enc`
3. File from another bot → Delete the `.enc` and start fresh

</details>

<details>
<summary><strong>❌ "Message expired or not found"</strong></summary>

Messages expire after 24 hours. This is a security feature to protect data.

</details>

<details>
<summary><strong>❌ Discord permission errors</strong></summary>

The bot needs these permissions:
- `Send Messages`
- `Use Slash Commands`
- `Embed Links`

</details>

<details>
<summary><strong>❌ "Wrong password" when decrypting</strong></summary>

- Verify you're using the correct password
- Passwords are case-sensitive
- If you forgot the password, there's no way to recover the message

</details>

---

## 🤝 Contributing

Contributions are welcome! 

1. 🍴 Fork the repository
2. 🌿 Create a branch (`git checkout -b feature/new-feature`)
3. 💾 Commit your changes (`git commit -m 'Add new feature'`)
4. 📤 Push to the branch (`git push origin feature/new-feature`)
5. 🔃 Open a Pull Request

### Ideas for Contributing

- [ ] Add more encryption algorithms
- [ ] Support for encrypted attachments
- [ ] Web interface for management
- [ ] Multi-language support
- [ ] Unit tests
- [ ] Command for self-destructing messages
- [ ] Image encryption

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2025 Encrypty

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software...
```

---

<p align="center">
  <strong>Made with ❤️ for the Discord community</strong><br>
  <em>🏆 Discord Buildathon 2025 Project 🏆</em>
</p>

<p align="center">
  <a href="https://discord.gg/your-server">
    <img src="https://img.shields.io/badge/Discord-Join-5865F2?style=for-the-badge&logo=discord&logoColor=white" alt="Discord"/>
  </a>
  <a href="https://github.com/your-username/cryptobot-discord">
    <img src="https://img.shields.io/badge/GitHub-Repo-181717?style=for-the-badge&logo=github&logoColor=white" alt="GitHub"/>
  </a>
</p>

<p align="center">
  ⭐ If you like the project, give it a star on GitHub! ⭐
</p>
