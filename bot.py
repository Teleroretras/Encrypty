import discord
from discord import app_commands, PartialEmoji
from discord.ui import Modal, TextInput
import base64
import os
import hashlib
import hmac
import secrets
import string
import time
import logging
import asyncio
import math
from datetime import datetime, timedelta
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import json
import aiohttp
from collections import defaultdict
from functools import wraps

# ==================== LOGGING SETUP ====================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('bot.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ==================== CONFIGURATION ====================
TOKEN = os.getenv('DISCORD_BOT_TOKEN')
if not TOKEN:
    logger.warning("DISCORD_BOT_TOKEN no encontrado en variables de entorno")
    logger.warning("Usa: export DISCORD_BOT_TOKEN='tu_token_aqui'")
    TOKEN = None

# CLAVE MAESTRA GLOBAL para encriptar el archivo JSON
# Esta clave debe ser la MISMA en todas las instancias del bot
# OBLIGATORIA desde variable de entorno para funcionar en múltiples servidores
MASTER_KEY_ENV = os.getenv('BOT_MASTER_KEY')

if not MASTER_KEY_ENV:
    logger.error("=" * 60)
    logger.error("BOT_MASTER_KEY no encontrada en variables de entorno!")
    logger.error("Esta clave es OBLIGATORIA para que el bot funcione.")
    logger.error("Configura: export BOT_MASTER_KEY='tu_clave_secreta_aqui'")
    logger.error("La clave debe ser la MISMA en todos los servidores.")
    logger.error("=" * 60)
    MASTER_KEY = None
else:
    # Derivar clave de 32 bytes desde la variable de entorno
    MASTER_KEY = hashlib.sha256(MASTER_KEY_ENV.encode()).digest()
    logger.info("Clave maestra cargada desde variable de entorno")

# Configuración del bot
MESSAGE_EXPIRY_HOURS = 24
MAX_MESSAGES_STORED = 1000
RATE_LIMIT_SECONDS = 5
STORAGE_FILE = "encrypted_messages.enc"
BACKUP_FILE = "encrypted_messages_backup.enc"
STORAGE_FILE_LEGACY = "encrypted_messages.json"

# Color principal para containers (mismo que encrypt)
MAIN_COLOR = 14021125

intents = discord.Intents.default()
client = discord.Client(intents=intents)
tree = app_commands.CommandTree(client)

# Rate limiting storage
user_cooldowns = defaultdict(float)

# ==================== RATE LIMITING ====================
def check_rate_limit(user_id: int) -> tuple[bool, float]:
    """Verifica si el usuario puede ejecutar un comando"""
    current_time = time.time()
    last_use = user_cooldowns[user_id]
    
    if current_time - last_use < RATE_LIMIT_SECONDS:
        remaining = RATE_LIMIT_SECONDS - (current_time - last_use)
        return False, remaining
    
    user_cooldowns[user_id] = current_time
    return True, 0

# ==================== SECURE STORAGE FUNCTIONS ====================

def encrypt_storage_data(data: dict) -> bytes:
    """Encripta los datos del almacenamiento usando AES-GCM con la clave maestra"""
    if not MASTER_KEY:
        raise ValueError("No hay clave maestra configurada")
    
    json_data = json.dumps(data, ensure_ascii=False).encode('utf-8')
    
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(MASTER_KEY), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(json_data) + encryptor.finalize()
    
    return nonce + encryptor.tag + ciphertext

def decrypt_storage_data(encrypted_data: bytes) -> dict:
    """Desencripta los datos del almacenamiento"""
    if not MASTER_KEY:
        raise ValueError("No hay clave maestra configurada")
    
    if len(encrypted_data) < 28:
        raise ValueError("Datos encriptados muy cortos")
    
    nonce = encrypted_data[:12]
    tag = encrypted_data[12:28]
    ciphertext = encrypted_data[28:]
    
    cipher = Cipher(algorithms.AES(MASTER_KEY), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    json_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    return json.loads(json_data.decode('utf-8'))

def hash_password(password: str, salt: bytes = None) -> tuple[str, str]:
    """Crea un hash seguro de la contraseña usando PBKDF2"""
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key.hex(), salt.hex()

def verify_password(password: str, stored_hash: str, salt_hex: str) -> bool:
    """Verifica si una contraseña coincide con el hash almacenado"""
    try:
        salt = bytes.fromhex(salt_hex)
        computed_hash, _ = hash_password(password, salt)
        return hmac.compare_digest(computed_hash, stored_hash)
    except Exception:
        return False

def migrate_legacy_storage() -> dict:
    """Migra el almacenamiento antiguo al nuevo formato encriptado"""
    if not os.path.exists(STORAGE_FILE_LEGACY):
        return {}
    
    try:
        logger.info("Migrando almacenamiento antiguo...")
        with open(STORAGE_FILE_LEGACY, 'r', encoding='utf-8') as f:
            old_data = json.load(f)
        
        if not isinstance(old_data, dict):
            return {}
        
        migrated_data = {}
        for msg_id, msg_data in old_data.items():
            if 'original_key' in msg_data:
                password = msg_data['original_key']
                pwd_hash, salt = hash_password(password)
                
                migrated_data[msg_id] = {
                    'cipher': msg_data.get('cipher'),
                    'encrypted': msg_data.get('encrypted'),
                    'key_hash': pwd_hash,
                    'key_salt': salt,
                    'message_id': msg_data.get('message_id'),
                    'timestamp': msg_data.get('timestamp', time.time()),
                    'author_id': msg_data.get('author_id')
                }
        
        backup_legacy = STORAGE_FILE_LEGACY + ".old"
        os.rename(STORAGE_FILE_LEGACY, backup_legacy)
        logger.info(f"Migración completa. Archivo antiguo guardado como {backup_legacy}")
        
        return migrated_data
        
    except Exception as e:
        logger.error(f"Error en migración: {e}")
        return {}

def load_encrypted_messages() -> dict:
    """Carga los mensajes desde el archivo encriptado"""
    if not MASTER_KEY:
        logger.warning("No se pueden cargar mensajes sin clave maestra")
        return {}
    
    if os.path.exists(STORAGE_FILE_LEGACY) and not os.path.exists(STORAGE_FILE):
        migrated = migrate_legacy_storage()
        if migrated:
            save_encrypted_messages_internal(migrated)
            return cleanup_expired_messages(migrated)
    
    if os.path.exists(STORAGE_FILE):
        try:
            with open(STORAGE_FILE, 'rb') as f:
                encrypted_data = f.read()
            
            data = decrypt_storage_data(encrypted_data)
            
            if isinstance(data, dict):
                cleaned = cleanup_expired_messages(data)
                logger.info(f"Cargados {len(cleaned)} mensajes (encriptados)")
                return cleaned
                
        except Exception as e:
            logger.error(f"Error desencriptando almacenamiento: {e}")
            return load_backup()
    
    return {}

def load_backup() -> dict:
    """Carga el backup encriptado si existe"""
    if os.path.exists(BACKUP_FILE):
        try:
            with open(BACKUP_FILE, 'rb') as f:
                encrypted_data = f.read()
            
            data = decrypt_storage_data(encrypted_data)
            logger.info("Cargado desde backup encriptado")
            return data if isinstance(data, dict) else {}
        except Exception as e:
            logger.error(f"Error cargando backup: {e}")
    return {}

def save_encrypted_messages_internal(data: dict):
    """Función interna para guardar datos encriptados"""
    if not MASTER_KEY:
        logger.warning("No se pueden guardar mensajes sin clave maestra")
        return
    
    try:
        encrypted_data = encrypt_storage_data(data)
        with open(STORAGE_FILE, 'wb') as f:
            f.write(encrypted_data)
    except Exception as e:
        logger.error(f"Error guardando almacenamiento encriptado: {e}")
        raise

def save_encrypted_messages():
    """Guarda los mensajes encriptados de forma segura"""
    if not MASTER_KEY:
        return
    
    try:
        if os.path.exists(STORAGE_FILE):
            try:
                import shutil
                shutil.copy2(STORAGE_FILE, BACKUP_FILE)
            except Exception as e:
                logger.warning(f"No se pudo crear backup: {e}")
        
        global encrypted_messages
        encrypted_messages = cleanup_expired_messages(encrypted_messages)
        
        if len(encrypted_messages) > MAX_MESSAGES_STORED:
            sorted_msgs = sorted(
                encrypted_messages.items(),
                key=lambda x: x[1].get('timestamp', 0)
            )
            encrypted_messages = dict(sorted_msgs[-MAX_MESSAGES_STORED:])
        
        save_encrypted_messages_internal(encrypted_messages)
        logger.debug(f"Guardados {len(encrypted_messages)} mensajes (encriptados)")
        
    except Exception as e:
        logger.error(f"Error guardando mensajes: {e}")

def cleanup_expired_messages(messages: dict) -> dict:
    """Elimina mensajes que han expirado"""
    current_time = time.time()
    expiry_seconds = MESSAGE_EXPIRY_HOURS * 3600
    
    cleaned = {}
    for msg_id, data in messages.items():
        timestamp = data.get('timestamp', current_time)
        if current_time - timestamp < expiry_seconds:
            cleaned[msg_id] = data
    
    removed = len(messages) - len(cleaned)
    if removed > 0:
        logger.info(f"Eliminados {removed} mensajes expirados")
    
    return cleaned

# Cargar mensajes al iniciar
encrypted_messages = load_encrypted_messages()

# ==================== HELPER FUNCTIONS ====================

def get_valid_key_bytes(key_str: str, length: int) -> bytes:
    """Genera una clave de bytes segura usando PBKDF2"""
    salt = b'discord_encryption_bot_v2'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(key_str.encode())

def get_key_bytes_simple(key_str: str, length: int) -> bytes:
    """Método simple para clásicos (compatibilidad)"""
    hashed = hashlib.sha256(key_str.encode()).digest()
    return hashed[:length]

def generate_secure_password(length: int = 16) -> str:
    """Genera una contraseña segura"""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def calculate_entropy(password: str) -> float:
    """Calcula la entropía de una contraseña en bits"""
    charset_size = 0
    
    if any(c.islower() for c in password):
        charset_size += 26
    if any(c.isupper() for c in password):
        charset_size += 26
    if any(c.isdigit() for c in password):
        charset_size += 10
    if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?/~`" for c in password):
        charset_size += 32
    if any(c == ' ' for c in password):
        charset_size += 1
    
    if charset_size == 0:
        return 0
    
    entropy = len(password) * math.log2(charset_size)
    return entropy

def estimate_crack_time(password: str) -> tuple[str, str]:
    """
    Estima el tiempo para crackear una contraseña
    Asume 10 billones de intentos por segundo (GPU moderna)
    """
    entropy = calculate_entropy(password)
    
    # 10 billones = 10^10 intentos por segundo
    attempts_per_second = 10_000_000_000
    
    # Número total de combinaciones posibles
    total_combinations = 2 ** entropy
    
    # Tiempo promedio (mitad de combinaciones)
    seconds = total_combinations / (2 * attempts_per_second)
    
    # Convertir a unidades legibles
    if seconds < 0.001:
        time_str = "Instantáneo"
        security = "Crítico"
    elif seconds < 1:
        time_str = f"{seconds * 1000:.2f} milisegundos"
        security = "Muy Bajo"
    elif seconds < 60:
        time_str = f"{seconds:.2f} segundos"
        security = "Bajo"
    elif seconds < 3600:
        time_str = f"{seconds / 60:.2f} minutos"
        security = "Bajo"
    elif seconds < 86400:
        time_str = f"{seconds / 3600:.2f} horas"
        security = "Medio"
    elif seconds < 86400 * 30:
        time_str = f"{seconds / 86400:.2f} días"
        security = "Medio"
    elif seconds < 86400 * 365:
        time_str = f"{seconds / (86400 * 30):.2f} meses"
        security = "Bueno"
    elif seconds < 86400 * 365 * 100:
        time_str = f"{seconds / (86400 * 365):.2f} años"
        security = "Muy Bueno"
    elif seconds < 86400 * 365 * 1000:
        time_str = f"{seconds / (86400 * 365):.0f} años"
        security = "Excelente"
    elif seconds < 86400 * 365 * 1_000_000:
        time_str = f"{seconds / (86400 * 365 * 1000):.0f} milenios"
        security = "Excelente"
    elif seconds < 86400 * 365 * 1_000_000_000:
        time_str = f"{seconds / (86400 * 365 * 1_000_000):.0f} millones de años"
        security = "Impenetrable"
    else:
        time_str = "Más que la edad del universo"
        security = "Impenetrable"
    
    return time_str, security

def calculate_password_strength(password: str) -> tuple[int, str, str, str]:
    """Calcula la fortaleza de una contraseña (0-100) y tiempo de crackeo"""
    score = 0
    
    # Longitud
    if len(password) >= 8: score += 20
    if len(password) >= 12: score += 10
    if len(password) >= 16: score += 10
    
    # Tipos de caracteres
    if any(c.islower() for c in password): score += 15
    if any(c.isupper() for c in password): score += 15
    if any(c.isdigit() for c in password): score += 15
    if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password): score += 15
    
    # Penalizaciones
    if password.lower() in ['password', '123456', 'qwerty', 'admin', '12345678']:
        score = 0
    
    if score < 30:
        strength = "Muy débil"
    elif score < 50:
        strength = "Débil"
    elif score < 70:
        strength = "Moderada"
    elif score < 90:
        strength = "Fuerte"
    else:
        strength = "Muy fuerte"
    
    crack_time, security_level = estimate_crack_time(password)
    entropy = calculate_entropy(password)
    
    return score, strength, crack_time, f"{entropy:.1f} bits"

# ==================== HASH FUNCTIONS ====================

def hash_md5(text: str) -> str:
    return hashlib.md5(text.encode()).hexdigest()

def hash_sha1(text: str) -> str:
    return hashlib.sha1(text.encode()).hexdigest()

def hash_sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()

def hash_sha512(text: str) -> str:
    return hashlib.sha512(text.encode()).hexdigest()

def hash_sha3_256(text: str) -> str:
    return hashlib.sha3_256(text.encode()).hexdigest()

def hash_blake2b(text: str) -> str:
    return hashlib.blake2b(text.encode()).hexdigest()

def hash_blake2s(text: str) -> str:
    return hashlib.blake2s(text.encode()).hexdigest()

HASH_FUNCTIONS = {
    'md5': {'func': hash_md5, 'name': 'MD5', 'bits': 128},
    'sha1': {'func': hash_sha1, 'name': 'SHA-1', 'bits': 160},
    'sha256': {'func': hash_sha256, 'name': 'SHA-256', 'bits': 256},
    'sha512': {'func': hash_sha512, 'name': 'SHA-512', 'bits': 512},
    'sha3_256': {'func': hash_sha3_256, 'name': 'SHA3-256', 'bits': 256},
    'blake2b': {'func': hash_blake2b, 'name': 'BLAKE2b', 'bits': 512},
    'blake2s': {'func': hash_blake2s, 'name': 'BLAKE2s', 'bits': 256},
}

# ==================== CLASSICAL ENCRYPTION FUNCTIONS ====================

def caesar_encrypt(text: str, key: str) -> str:
    try:
        shift = int(key) % 26
    except ValueError:
        shift = sum(ord(c) for c in key) % 26
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

def caesar_decrypt(text: str, key: str) -> str:
    try:
        shift = int(key) % 26
    except ValueError:
        shift = sum(ord(c) for c in key) % 26
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base - shift) % 26 + base)
        else:
            result += char
    return result

def rot13_encrypt(text: str, key: str = "") -> str:
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + 13) % 26 + base)
        else:
            result += char
    return result

def rot13_decrypt(text: str, key: str = "") -> str:
    return rot13_encrypt(text, key)

def atbash_encrypt(text: str, key: str = "") -> str:
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr(base + (25 - (ord(char) - base)))
        else:
            result += char
    return result

def atbash_decrypt(text: str, key: str = "") -> str:
    return atbash_encrypt(text, key)

def vigenere_encrypt(text: str, key: str) -> str:
    if not key: key = "A"
    key = ''.join(filter(str.isalpha, key.upper()))
    if not key: key = "A"
    result = ""
    key_index = 0
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_index % len(key)]) - ord('A')
            result += chr((ord(char) - base + shift) % 26 + base)
            key_index += 1
        else:
            result += char
    return result

def vigenere_decrypt(text: str, key: str) -> str:
    if not key: key = "A"
    key = ''.join(filter(str.isalpha, key.upper()))
    if not key: key = "A"
    result = ""
    key_index = 0
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_index % len(key)]) - ord('A')
            result += chr((ord(char) - base - shift) % 26 + base)
            key_index += 1
        else:
            result += char
    return result

def beaufort_encrypt(text: str, key: str) -> str:
    if not key: key = "A"
    key = ''.join(filter(str.isalpha, key.upper()))
    if not key: key = "A"
    result = ""
    key_index = 0
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            k_char = ord(key[key_index % len(key)]) - ord('A')
            p_char = ord(char) - base
            new_char = (k_char - p_char) % 26
            result += chr(new_char + base)
            key_index += 1
        else:
            result += char
    return result

def beaufort_decrypt(text: str, key: str) -> str:
    return beaufort_encrypt(text, key)

def autokey_encrypt(text: str, key: str) -> str:
    if not key: key = "A"
    key = ''.join(filter(str.isalpha, key.upper()))
    if not key: key = "A"
    
    result = ""
    keystream_queue = [ord(k) - ord('A') for k in key]
    
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            p_val = ord(char) - base
            k_val = keystream_queue.pop(0)
            keystream_queue.append(p_val)
            c_val = (p_val + k_val) % 26
            result += chr(c_val + base)
        else:
            result += char
    return result

def autokey_decrypt(text: str, key: str) -> str:
    if not key: key = "A"
    key = ''.join(filter(str.isalpha, key.upper()))
    if not key: key = "A"
    
    result = ""
    keystream_queue = [ord(k) - ord('A') for k in key]
    
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            c_val = ord(char) - base
            k_val = keystream_queue.pop(0)
            p_val = (c_val - k_val) % 26
            keystream_queue.append(p_val)
            result += chr(p_val + base)
        else:
            result += char
    return result

def rail_fence_encrypt(text: str, key: str) -> str:
    try:
        rails = int(key) if key.isdigit() else len(key)
        rails = max(2, min(rails, len(text)))
    except:
        rails = 3
    
    if rails >= len(text):
        return text
    
    fence = [[] for _ in range(rails)]
    rail = 0
    direction = 1
    
    for char in text:
        fence[rail].append(char)
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction *= -1
    
    return ''.join(''.join(row) for row in fence)

def rail_fence_decrypt(text: str, key: str) -> str:
    try:
        rails = int(key) if key.isdigit() else len(key)
        rails = max(2, min(rails, len(text)))
    except:
        rails = 3
    
    if rails >= len(text):
        return text
    
    lengths = [0] * rails
    rail = 0
    direction = 1
    for _ in text:
        lengths[rail] += 1
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction *= -1
    
    fence = []
    pos = 0
    for length in lengths:
        fence.append(list(text[pos:pos + length]))
        pos += length
    
    result = []
    rail = 0
    direction = 1
    indices = [0] * rails
    
    for _ in text:
        if indices[rail] < len(fence[rail]):
            result.append(fence[rail][indices[rail]])
            indices[rail] += 1
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction *= -1
    
    return ''.join(result)

def morse_encode(text: str, key: str = "") -> str:
    MORSE_CODE = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
        'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
        'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
        'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
        'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
        '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
        '8': '---..', '9': '----.', ' ': '/', '.': '.-.-.-', ',': '--..--',
        '?': '..--..', '!': '-.-.--', "'": '.----.', '"': '.-..-.', '(': '-.--.',
        ')': '-.--.-', '&': '.-...', ':': '---...', ';': '-.-.-.', '=': '-...-',
        '+': '.-.-.', '-': '-....-', '_': '..--.-', '$': '...-..-', '@': '.--.-.'
    }
    result = []
    for char in text.upper():
        if char in MORSE_CODE:
            result.append(MORSE_CODE[char])
        else:
            result.append(char)
    return ' '.join(result)

def morse_decode(text: str, key: str = "") -> str:
    MORSE_TO_CHAR = {
        '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F',
        '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
        '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R',
        '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
        '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
        '...--': '3', '....-': '4', '.....': '5', '-....': '6', '--...': '7',
        '---..': '8', '----.': '9', '/': ' ', '.-.-.-': '.', '--..--': ',',
        '..--..': '?', '-.-.--': '!', '.----.': "'", '.-..-.': '"', '-.--.': '(',
        '-.--.-': ')', '.-...': '&', '---...': ':', '-.-.-.': ';', '-...-': '=',
        '.-.-.': '+', '-....-': '-', '..--.-': '_', '...-..-': '$', '.--.-.': '@'
    }
    result = []
    for code in text.split(' '):
        if code in MORSE_TO_CHAR:
            result.append(MORSE_TO_CHAR[code])
        elif code:
            result.append(code)
    return ''.join(result)

def base64_encode(text: str, key: str = "") -> str:
    return base64.b64encode(text.encode()).decode()

def base64_decode(text: str, key: str = "") -> str:
    try:
        return base64.b64decode(text.encode()).decode()
    except:
        return "[Error: Invalid Base64]"

def base32_encode(text: str, key: str = "") -> str:
    return base64.b32encode(text.encode()).decode()

def base32_decode(text: str, key: str = "") -> str:
    try:
        return base64.b32decode(text.encode()).decode()
    except:
        return "[Error: Invalid Base32]"

def hex_encode(text: str, key: str = "") -> str:
    return text.encode().hex()

def hex_decode(text: str, key: str = "") -> str:
    try:
        return bytes.fromhex(text).decode()
    except:
        return "[Error: Invalid Hex]"

def binary_encode(text: str, key: str = "") -> str:
    return ' '.join(format(ord(c), '08b') for c in text)

def binary_decode(text: str, key: str = "") -> str:
    try:
        binary_values = text.replace(' ', '')
        chars = [binary_values[i:i+8] for i in range(0, len(binary_values), 8)]
        return ''.join(chr(int(b, 2)) for b in chars if len(b) == 8)
    except:
        return "[Error: Invalid Binary]"

def reverse_text(text: str, key: str = "") -> str:
    return text[::-1]

def playfair_matrix(key: str):
    key = ''.join(dict.fromkeys(filter(str.isalpha, key.upper().replace('J', 'I'))))
    alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
    matrix_str = key + ''.join([c for c in alphabet if c not in key])
    return [list(matrix_str[i:i+5]) for i in range(0, 25, 5)]

def find_pos(matrix, char):
    for r, row in enumerate(matrix):
        if char in row:
            return r, row.index(char)
    return None

def playfair_encrypt(text: str, key: str) -> str:
    if not key:
        key = "KEYWORD"
    matrix = playfair_matrix(key)
    text = ''.join(filter(str.isalpha, text.upper())).replace('J', 'I')
    if not text:
        return ""
    pairs = []
    i = 0
    while i < len(text):
        a = text[i]
        b = text[i+1] if i+1 < len(text) else 'X'
        if a == b:
            b = 'X'
            i += 1
        else:
            i += 2
        pairs.append((a, b))
    result = ""
    for a, b in pairs:
        pos1 = find_pos(matrix, a)
        pos2 = find_pos(matrix, b)
        if not pos1 or not pos2:
            continue
        r1, c1 = pos1
        r2, c2 = pos2
        if r1 == r2:
            result += matrix[r1][(c1+1)%5] + matrix[r2][(c2+1)%5]
        elif c1 == c2:
            result += matrix[(r1+1)%5][c1] + matrix[(r2+1)%5][c2]
        else:
            result += matrix[r1][c2] + matrix[r2][c1]
    return result

def playfair_decrypt(text: str, key: str) -> str:
    if not key:
        key = "KEYWORD"
    matrix = playfair_matrix(key)
    text = ''.join(filter(str.isalpha, text.upper())).replace('J', 'I')
    if len(text) % 2 != 0:
        text += 'X'
    pairs = [(text[i], text[i+1]) for i in range(0, len(text), 2)]
    result = ""
    for a, b in pairs:
        pos1 = find_pos(matrix, a)
        pos2 = find_pos(matrix, b)
        if not pos1 or not pos2:
            continue
        r1, c1 = pos1
        r2, c2 = pos2
        if r1 == r2:
            result += matrix[r1][(c1-1)%5] + matrix[r2][(c2-1)%5]
        elif c1 == c2:
            result += matrix[(r1-1)%5][c1] + matrix[(r2-1)%5][c2]
        else:
            result += matrix[r1][c2] + matrix[r2][c1]
    return result

def columnar_encrypt(text: str, key: str) -> str:
    if not key:
        return text
    key_len = len(key)
    order = sorted(range(key_len), key=lambda k: key[k])
    cols = [''] * key_len
    for i, char in enumerate(text):
        cols[i % key_len] += char
    return ''.join(cols[i] for i in order)

def columnar_decrypt(text: str, key: str) -> str:
    if not key or not text:
        return text
    key_len = len(key)
    order = sorted(range(key_len), key=lambda k: key[k])
    
    num_rows = len(text) // key_len
    extra = len(text) % key_len
    
    col_lens = []
    for i in range(key_len):
        original_pos = order.index(i)
        if original_pos < extra:
            col_lens.append(num_rows + 1)
        else:
            col_lens.append(num_rows)
    
    cols = [''] * key_len
    pos = 0
    for i in range(key_len):
        cols[order[i]] = text[pos:pos + col_lens[order[i]]]
        pos += col_lens[order[i]]
    
    result = ''
    max_len = max(len(c) for c in cols) if cols else 0
    for i in range(max_len):
        for col in cols:
            if i < len(col):
                result += col[i]
    return result

def xor_encrypt(text: str, key: str) -> str:
    if not key:
        return text
    result = bytearray()
    key_bytes = key.encode()
    text_bytes = text.encode()
    for i, byte in enumerate(text_bytes):
        result.append(byte ^ key_bytes[i % len(key_bytes)])
    return base64.b64encode(result).decode()

def xor_decrypt(text: str, key: str) -> str:
    if not key:
        return text
    try:
        data = base64.b64decode(text)
        result = bytearray()
        key_bytes = key.encode()
        for i, byte in enumerate(data):
            result.append(byte ^ key_bytes[i % len(key_bytes)])
        return result.decode()
    except Exception as e:
        return f"[Error: {str(e)[:50]}]"

# ==================== MODERN / BLOCK CIPHERS ====================

def rc4_encrypt(text: str, key: str) -> str:
    if not key:
        key = "default"
    S = list(range(256))
    j = 0
    k = key.encode()
    for i in range(256):
        j = (j + S[i] + k[i % len(k)]) % 256
        S[i], S[j] = S[j], S[i]
    
    i = j = 0
    res = bytearray()
    for byte in text.encode():
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        res.append(byte ^ S[(S[i] + S[j]) % 256])
    return base64.b64encode(res).decode()

def rc4_decrypt(text: str, key: str) -> str:
    try:
        if not key:
            key = "default"
        data = base64.b64decode(text)
        S = list(range(256))
        j = 0
        k = key.encode()
        for i in range(256):
            j = (j + S[i] + k[i % len(k)]) % 256
            S[i], S[j] = S[j], S[i]
        
        i = j = 0
        res = bytearray()
        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            res.append(byte ^ S[(S[i] + S[j]) % 256])
        return res.decode()
    except Exception as e:
        return f"[Error: {str(e)[:50]}]"

def fernet_encrypt(text: str, key: str) -> str:
    k = base64.urlsafe_b64encode(get_key_bytes_simple(key, 32))
    f = Fernet(k)
    return f.encrypt(text.encode()).decode()

def fernet_decrypt(text: str, key: str) -> str:
    try:
        k = base64.urlsafe_b64encode(get_key_bytes_simple(key, 32))
        f = Fernet(k)
        return f.decrypt(text.encode()).decode()
    except InvalidToken:
        return "[Error: Invalid token or wrong password]"
    except Exception as e:
        return f"[Error: {str(e)[:50]}]"

def aes_gcm_encrypt(text: str, key: str) -> str:
    k = get_key_bytes_simple(key, 32)
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(k), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(text.encode()) + encryptor.finalize()
    return base64.b64encode(nonce + encryptor.tag + ciphertext).decode()

def aes_gcm_decrypt(text: str, key: str) -> str:
    try:
        k = get_key_bytes_simple(key, 32)
        data = base64.b64decode(text)
        if len(data) < 28:
            return "[Error: Data too short]"
        nonce = data[:12]
        tag = data[12:28]
        ciphertext = data[28:]
        cipher = Cipher(algorithms.AES(k), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode()
    except Exception as e:
        return f"[Error: {str(e)[:50]}]"

def aes_cbc_encrypt(text: str, key: str) -> str:
    k = get_key_bytes_simple(key, 32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(k), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(text.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()

def aes_cbc_decrypt(text: str, key: str) -> str:
    try:
        k = get_key_bytes_simple(key, 32)
        data = base64.b64decode(text)
        if len(data) < 32:
            return "[Error: Data too short]"
        iv = data[:16]
        ciphertext = data[16:]
        cipher = Cipher(algorithms.AES(k), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return (unpadder.update(padded_data) + unpadder.finalize()).decode()
    except Exception as e:
        return f"[Error: {str(e)[:50]}]"

def aes_ctr_encrypt(text: str, key: str) -> str:
    k = get_key_bytes_simple(key, 32)
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(k), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(text.encode()) + encryptor.finalize()
    return base64.b64encode(nonce + ciphertext).decode()

def aes_ctr_decrypt(text: str, key: str) -> str:
    try:
        k = get_key_bytes_simple(key, 32)
        data = base64.b64decode(text)
        if len(data) < 17:
            return "[Error: Data too short]"
        nonce = data[:16]
        ciphertext = data[16:]
        cipher = Cipher(algorithms.AES(k), modes.CTR(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode()
    except Exception as e:
        return f"[Error: {str(e)[:50]}]"

def triple_des_encrypt(text: str, key: str) -> str:
    final_key = get_key_bytes_simple(key, 24)
    iv = os.urandom(8)
    cipher = Cipher(algorithms.TripleDES(final_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(64).padder()
    padded_data = padder.update(text.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()

def triple_des_decrypt(text: str, key: str) -> str:
    try:
        final_key = get_key_bytes_simple(key, 24)
        data = base64.b64decode(text)
        if len(data) < 16:
            return "[Error: Data too short]"
        iv = data[:8]
        ciphertext = data[8:]
        cipher = Cipher(algorithms.TripleDES(final_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(64).unpadder()
        return (unpadder.update(padded_data) + unpadder.finalize()).decode()
    except Exception as e:
        return f"[Error: {str(e)[:50]}]"

def blowfish_encrypt(text: str, key: str) -> str:
    key_bytes = key.encode()[:56] if len(key.encode()) > 56 else key.encode()
    if len(key_bytes) < 4:
        key_bytes = key_bytes.ljust(4, b'\x00')
    
    iv = os.urandom(8)
    cipher = Cipher(algorithms.Blowfish(key_bytes), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(64).padder()
    padded_data = padder.update(text.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()

def blowfish_decrypt(text: str, key: str) -> str:
    try:
        key_bytes = key.encode()[:56] if len(key.encode()) > 56 else key.encode()
        if len(key_bytes) < 4:
            key_bytes = key_bytes.ljust(4, b'\x00')
        
        data = base64.b64decode(text)
        if len(data) < 16:
            return "[Error: Data too short]"
        iv = data[:8]
        ciphertext = data[8:]
        cipher = Cipher(algorithms.Blowfish(key_bytes), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(64).unpadder()
        return (unpadder.update(padded_data) + unpadder.finalize()).decode()
    except Exception as e:
        return f"[Error: {str(e)[:50]}]"

def chacha20_encrypt(text: str, key: str) -> str:
    k = get_key_bytes_simple(key, 32)
    nonce = os.urandom(16)
    algorithm = algorithms.ChaCha20(k, nonce)
    cipher = Cipher(algorithm, mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(text.encode())
    return base64.b64encode(nonce + ciphertext).decode()

def chacha20_decrypt(text: str, key: str) -> str:
    try:
        k = get_key_bytes_simple(key, 32)
        data = base64.b64decode(text)
        if len(data) < 17:
            return "[Error: Data too short]"
        nonce = data[:16]
        ciphertext = data[16:]
        algorithm = algorithms.ChaCha20(k, nonce)
        cipher = Cipher(algorithm, mode=None, backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext).decode()
    except Exception as e:
        return f"[Error: {str(e)[:50]}]"

def camellia_encrypt(text: str, key: str) -> str:
    k = get_key_bytes_simple(key, 32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.Camellia(k), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(text.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()

def camellia_decrypt(text: str, key: str) -> str:
    try:
        k = get_key_bytes_simple(key, 32)
        data = base64.b64decode(text)
        if len(data) < 32:
            return "[Error: Data too short]"
        iv = data[:16]
        ciphertext = data[16:]
        cipher = Cipher(algorithms.Camellia(k), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return (unpadder.update(padded_data) + unpadder.finalize()).decode()
    except Exception as e:
        return f"[Error: {str(e)[:50]}]"

def cast5_encrypt(text: str, key: str) -> str:
    k = get_key_bytes_simple(key, 16)
    iv = os.urandom(8)
    cipher = Cipher(algorithms.CAST5(k), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(64).padder()
    padded_data = padder.update(text.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()

def cast5_decrypt(text: str, key: str) -> str:
    try:
        k = get_key_bytes_simple(key, 16)
        data = base64.b64decode(text)
        if len(data) < 16:
            return "[Error: Data too short]"
        iv = data[:8]
        ciphertext = data[8:]
        cipher = Cipher(algorithms.CAST5(k), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(64).unpadder()
        return (unpadder.update(padded_data) + unpadder.finalize()).decode()
    except Exception as e:
        return f"[Error: {str(e)[:50]}]"

def seed_encrypt(text: str, key: str) -> str:
    k = get_key_bytes_simple(key, 16)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.SEED(k), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(text.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()

def seed_decrypt(text: str, key: str) -> str:
    try:
        k = get_key_bytes_simple(key, 16)
        data = base64.b64decode(text)
        if len(data) < 32:
            return "[Error: Data too short]"
        iv = data[:16]
        ciphertext = data[16:]
        cipher = Cipher(algorithms.SEED(k), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return (unpadder.update(padded_data) + unpadder.finalize()).decode()
    except Exception as e:
        return f"[Error: {str(e)[:50]}]"

# ==================== CIPHER DICTIONARY ====================

CIPHERS = {
    'cesar': {'encrypt': caesar_encrypt, 'decrypt': caesar_decrypt, 'name': 'Caesar Cipher', 'category': 'classical'},
    'rot13': {'encrypt': rot13_encrypt, 'decrypt': rot13_decrypt, 'name': 'ROT13', 'category': 'classical'},
    'atbash': {'encrypt': atbash_encrypt, 'decrypt': atbash_decrypt, 'name': 'Atbash', 'category': 'classical'},
    'vigenere': {'encrypt': vigenere_encrypt, 'decrypt': vigenere_decrypt, 'name': 'Vigenere Cipher', 'category': 'classical'},
    'beaufort': {'encrypt': beaufort_encrypt, 'decrypt': beaufort_decrypt, 'name': 'Beaufort Cipher', 'category': 'classical'},
    'autokey': {'encrypt': autokey_encrypt, 'decrypt': autokey_decrypt, 'name': 'Autokey Cipher', 'category': 'classical'},
    'playfair': {'encrypt': playfair_encrypt, 'decrypt': playfair_decrypt, 'name': 'Playfair Cipher', 'category': 'classical'},
    'columnar': {'encrypt': columnar_encrypt, 'decrypt': columnar_decrypt, 'name': 'Columnar Transposition', 'category': 'classical'},
    'rail_fence': {'encrypt': rail_fence_encrypt, 'decrypt': rail_fence_decrypt, 'name': 'Rail Fence', 'category': 'classical'},
    
    'morse': {'encrypt': morse_encode, 'decrypt': morse_decode, 'name': 'Morse Code', 'category': 'encoding'},
    'base64': {'encrypt': base64_encode, 'decrypt': base64_decode, 'name': 'Base64', 'category': 'encoding'},
    'base32': {'encrypt': base32_encode, 'decrypt': base32_decode, 'name': 'Base32', 'category': 'encoding'},
    'hex': {'encrypt': hex_encode, 'decrypt': hex_decode, 'name': 'Hexadecimal', 'category': 'encoding'},
    'binary': {'encrypt': binary_encode, 'decrypt': binary_decode, 'name': 'Binary', 'category': 'encoding'},
    'reverse': {'encrypt': reverse_text, 'decrypt': reverse_text, 'name': 'Reverse Text', 'category': 'encoding'},
    
    'xor': {'encrypt': xor_encrypt, 'decrypt': xor_decrypt, 'name': 'XOR Cipher', 'category': 'stream'},
    'rc4': {'encrypt': rc4_encrypt, 'decrypt': rc4_decrypt, 'name': 'RC4 Stream', 'category': 'stream'},
    'chacha20': {'encrypt': chacha20_encrypt, 'decrypt': chacha20_decrypt, 'name': 'ChaCha20', 'category': 'stream'},
    
    'fernet': {'encrypt': fernet_encrypt, 'decrypt': fernet_decrypt, 'name': 'Fernet (AES)', 'category': 'block'},
    'aes_gcm': {'encrypt': aes_gcm_encrypt, 'decrypt': aes_gcm_decrypt, 'name': 'AES-GCM (Authenticated)', 'category': 'block'},
    'aes_cbc': {'encrypt': aes_cbc_encrypt, 'decrypt': aes_cbc_decrypt, 'name': 'AES-CBC (256-bit)', 'category': 'block'},
    'aes_ctr': {'encrypt': aes_ctr_encrypt, 'decrypt': aes_ctr_decrypt, 'name': 'AES-CTR (Stream Mode)', 'category': 'block'},
    '3des': {'encrypt': triple_des_encrypt, 'decrypt': triple_des_decrypt, 'name': 'Triple DES', 'category': 'block'},
    'blowfish': {'encrypt': blowfish_encrypt, 'decrypt': blowfish_decrypt, 'name': 'Blowfish', 'category': 'block'},
    'camellia': {'encrypt': camellia_encrypt, 'decrypt': camellia_decrypt, 'name': 'Camellia (256-bit)', 'category': 'block'},
    'cast5': {'encrypt': cast5_encrypt, 'decrypt': cast5_decrypt, 'name': 'CAST5', 'category': 'block'},
    'seed': {'encrypt': seed_encrypt, 'decrypt': seed_decrypt, 'name': 'SEED (Korean Std)', 'category': 'block'},
}

# ==================== VIEWS ====================

def create_decrypt_view(msg_id: str, cipher_name: str, encrypted_text: str, author_name: str):
    """Factory for the Decrypt View"""
    display_text = encrypted_text[:800] + "..." if len(encrypted_text) > 800 else encrypted_text
    
    class DecryptView(discord.ui.LayoutView):
        container1 = discord.ui.Container(
            discord.ui.TextDisplay(
                content=f"```\n@{author_name}: {display_text}\n```"
            ),
            discord.ui.ActionRow(
                discord.ui.Button(
                    style=discord.ButtonStyle.primary,
                    label="Decrypt",
                    custom_id="persistent_decrypt_button",
                    emoji=PartialEmoji.from_str("<:lock:1445513947095498754>"),
                ),
            ),
            accent_colour=discord.Colour(MAIN_COLOR),
        )
        
        def __init__(self):
            super().__init__(timeout=None)
    
    return DecryptView()

def create_container_view(content: str, footer: str = None, color: int = MAIN_COLOR):
    """Crea un container view genérico"""
    class ContainerView(discord.ui.LayoutView):
        pass
    
    if footer:
        ContainerView.container1 = discord.ui.Container(
            discord.ui.TextDisplay(content=content),
            discord.ui.TextDisplay(content=f"-# {footer}"),
            accent_colour=discord.Colour(color),
        )
    else:
        ContainerView.container1 = discord.ui.Container(
            discord.ui.TextDisplay(content=content),
            accent_colour=discord.Colour(color),
        )
    
    return ContainerView()

# ==================== MODALS ====================

class DecryptModal(Modal, title='Decrypt Message'):
    msg_id = None
    
    key_input = TextInput(
        label='Password / Key',
        style=discord.TextStyle.short,
        placeholder='Enter the password to decrypt...',
        required=True,
        max_length=100
    )
    
    async def on_submit(self, interaction: discord.Interaction):
        try:
            if self.msg_id not in encrypted_messages:
                class ErrorView(discord.ui.LayoutView):
                    container1 = discord.ui.Container(
                        discord.ui.TextDisplay(content="**Message expired or not found.**"),
                        accent_colour=discord.Colour(MAIN_COLOR),
                    )
                await interaction.response.send_message(view=ErrorView(), ephemeral=True)
                return
            
            data = encrypted_messages[self.msg_id]
            key = self.key_input.value
            cipher_data = CIPHERS.get(data['cipher'])
            
            if not cipher_data:
                class ErrorView(discord.ui.LayoutView):
                    container1 = discord.ui.Container(
                        discord.ui.TextDisplay(content="**Cipher method not found.**"),
                        accent_colour=discord.Colour(MAIN_COLOR),
                    )
                await interaction.response.send_message(view=ErrorView(), ephemeral=True)
                return

            try:
                decrypted_text = cipher_data['decrypt'](data['encrypted'], key)
                
                if 'key_hash' in data and 'key_salt' in data:
                    is_correct = verify_password(key, data['key_hash'], data['key_salt'])
                elif 'original_key' in data:
                    is_correct = key == data['original_key']
                    key_hash, key_salt = hash_password(key)
                    data['key_hash'] = key_hash
                    data['key_salt'] = key_salt
                    del data['original_key']
                    save_encrypted_messages()
                    logger.info(f"Migrado mensaje {self.msg_id} a formato seguro")
                else:
                    is_correct = False

                if is_correct:
                    class SuccessView(discord.ui.LayoutView):    
                        container1 = discord.ui.Container(
                            discord.ui.TextDisplay(content=f"```{decrypted_text[:1900]}```"),
                            discord.ui.TextDisplay(content="-# <a:yes:1445591348588580967> Correct password"),
                            accent_colour=discord.Colour(MAIN_COLOR),
                        )
                    await interaction.response.send_message(view=SuccessView(), ephemeral=True)
                    logger.info(f"User {interaction.user.id} decrypted message successfully")
                else:
                    class ErrorView(discord.ui.LayoutView):    
                        container1 = discord.ui.Container(
                            discord.ui.TextDisplay(content="<a:no:1445521530707509359>**Wrong password**"),
                            discord.ui.TextDisplay(content="-# Try again"),
                            accent_colour=discord.Colour(MAIN_COLOR),
                        )
                    await interaction.response.send_message(view=ErrorView(), ephemeral=True)
                    logger.info(f"User {interaction.user.id} failed decryption attempt")
                
            except Exception as e:
                error_msg = str(e).lower()
                if "padding" in error_msg or "invalid" in error_msg:
                    class ErrorView(discord.ui.LayoutView):    
                        container1 = discord.ui.Container(
                            discord.ui.TextDisplay(content="<a:no:1445521530707509359>**Wrong password**"),
                            discord.ui.TextDisplay(content="-# Try again"),
                            accent_colour=discord.Colour(MAIN_COLOR),
                        )
                    await interaction.response.send_message(view=ErrorView(), ephemeral=True)
                else:
                    class ErrorView(discord.ui.LayoutView):    
                        container1 = discord.ui.Container(
                            discord.ui.TextDisplay(content=f"**Decryption failed:** {str(e)[:100]}"),
                            accent_colour=discord.Colour(MAIN_COLOR),
                        )
                    await interaction.response.send_message(view=ErrorView(), ephemeral=True)
                    logger.error(f"Decryption error: {e}")
                
        except Exception as e:
            logger.error(f"Modal error: {e}")
            if not interaction.response.is_done():
                class ErrorView(discord.ui.LayoutView):    
                    container1 = discord.ui.Container(
                        discord.ui.TextDisplay(content=f"**System Error:** {str(e)}"),
                        accent_colour=discord.Colour(MAIN_COLOR),
                    )
                await interaction.response.send_message(view=ErrorView(), ephemeral=True)

class HashModal(Modal, title='Generate Hash'):
    text_input = TextInput(
        label='Text to Hash',
        style=discord.TextStyle.paragraph,
        placeholder='Enter text to generate hash...',
        required=True,
        max_length=2000
    )
    
    async def on_submit(self, interaction: discord.Interaction):
        text = self.text_input.value
        
        hashes_text = "**Hash Results**\n\n"
        for hash_id, hash_data in HASH_FUNCTIONS.items():
            hash_value = hash_data['func'](text)
            hashes_text += f"**{hash_data['name']}** ({hash_data['bits']} bits)\n`{hash_value}`\n\n"
        
        class HashView(discord.ui.LayoutView):
            container1 = discord.ui.Container(
                discord.ui.TextDisplay(content=hashes_text[:3900]),
                discord.ui.TextDisplay(content=f"-# Input length: {len(text)} characters"),
                accent_colour=discord.Colour(MAIN_COLOR),
            )
        
        await interaction.response.send_message(view=HashView(), ephemeral=True)

# ==================== COMMANDS ====================

@tree.command(name='encrypt', description='Encrypt text requiring a password')
async def encrypt_command(interaction: discord.Interaction):
    can_use, remaining = check_rate_limit(interaction.user.id)
    if not can_use:
        class RateLimitView(discord.ui.LayoutView):
            container1 = discord.ui.Container(
                discord.ui.TextDisplay(content=f"**Please wait {remaining:.1f} seconds before using this command again.**"),
                accent_colour=discord.Colour(MAIN_COLOR),
            )
        await interaction.response.send_message(view=RateLimitView(), ephemeral=True)
        return
    
    options = [
        {"label": "Caesar Cipher", "value": "cesar", "description": "Shift letters (Key: Number)"},
        {"label": "ROT13", "value": "rot13", "description": "Shift 13 (No key needed)"},
        {"label": "Atbash", "value": "atbash", "description": "Reverse alphabet (No key)"},
        {"label": "Vigenere Cipher", "value": "vigenere", "description": "Key: Word/Phrase"},
        {"label": "Beaufort Cipher", "value": "beaufort", "description": "Variant of Vigenere"},
        {"label": "Autokey Cipher", "value": "autokey", "description": "Self-extending Key"},
        {"label": "Playfair Cipher", "value": "playfair", "description": "Key: Word/Phrase"},
        {"label": "Columnar Transposition", "value": "columnar", "description": "Key: Word"},
        {"label": "Rail Fence", "value": "rail_fence", "description": "Key: Number of rails"},
        {"label": "Morse Code", "value": "morse", "description": "Dots and dashes"},
        {"label": "Base64", "value": "base64", "description": "Standard encoding"},
        {"label": "Base32", "value": "base32", "description": "Uppercase encoding"},
        {"label": "Hexadecimal", "value": "hex", "description": "Hex representation"},
        {"label": "Binary", "value": "binary", "description": "Binary representation"},
        {"label": "XOR Cipher", "value": "xor", "description": "Bitwise XOR"},
        {"label": "RC4 Stream", "value": "rc4", "description": "Fast Stream Cipher"},
        {"label": "ChaCha20", "value": "chacha20", "description": "Modern Stream Cipher"},
        {"label": "Fernet (AES)", "value": "fernet", "description": "Strong Symmetric"},
        {"label": "AES-GCM", "value": "aes_gcm", "description": "Authenticated AES"},
        {"label": "AES-CBC", "value": "aes_cbc", "description": "Classic AES (256-bit)"},
        {"label": "AES-CTR", "value": "aes_ctr", "description": "AES Stream Mode"},
        {"label": "Camellia", "value": "camellia", "description": "Japanese Standard"},
        {"label": "SEED", "value": "seed", "description": "Korean Standard"},
        {"label": "Triple DES", "value": "3des", "description": "Legacy Block Cipher"},
        {"label": "Blowfish", "value": "blowfish", "description": "Fast Block Cipher"},
    ]

    modal_json = {
        "type": 9,
        "data": {
            "custom_id": "encrypt_modal",
            "title": "Encrypt Message",
            "components": [
                {
                    "type": 18,
                    "label": "Encryption Method",
                    "component": {
                        "type": 3,
                        "custom_id": "cipher_select",
                        "placeholder": "Select encryption method...",
                        "min_values": 1,
                        "max_values": 1,
                        "options": options[:25]
                    }
                },
                {
                    "type": 18,
                    "label": "Message",
                    "component": {
                        "type": 4,
                        "custom_id": "text_input",
                        "style": 2,
                        "placeholder": "Type your secret message...",
                        "required": True,
                        "min_length": 1,
                        "max_length": 2000
                    }
                },
                {
                    "type": 18,
                    "label": "Password / Key",
                    "description": "Remember this to decrypt!",
                    "component": {
                        "type": 4,
                        "custom_id": "key_input",
                        "style": 1,
                        "placeholder": "Enter a secure password...",
                        "required": True,
                        "max_length": 100
                    }
                }
            ]
        }
    }
    
    url = f"https://discord.com/api/v10/interactions/{interaction.id}/{interaction.token}/callback"
    
    async with aiohttp.ClientSession() as session:
        await session.post(url, json=modal_json)

@tree.command(name='hash', description='Generate hash of text (MD5, SHA, BLAKE2, etc.)')
async def hash_command(interaction: discord.Interaction):
    await interaction.response.send_modal(HashModal())

@tree.command(name='generate_password', description='Generate a secure random password')
@app_commands.describe(length='Password length (8-64)')
async def generate_password_command(interaction: discord.Interaction, length: int = 16):
    if length < 8:
        length = 8
    elif length > 64:
        length = 64
    
    password = generate_secure_password(length)
    score, strength, crack_time, entropy = calculate_password_strength(password)
    
    content = f"""**Generated Secure Password**

**Password:**
```{password}```

**Length:** {length} characters
**Strength:** {strength} ({score}/100)
**Entropy:** {entropy}
**Time to crack:** {crack_time}"""
    
    class PasswordView(discord.ui.LayoutView):
        container1 = discord.ui.Container(
            discord.ui.TextDisplay(content=content),
            discord.ui.TextDisplay(content="-# Save this password securely!"),
            accent_colour=discord.Colour(MAIN_COLOR),
        )
    
    await interaction.response.send_message(view=PasswordView(), ephemeral=True)

@tree.command(name='check_password', description='Check password strength and crack time')
@app_commands.describe(password='Password to analyze')
async def check_password_command(interaction: discord.Interaction, password: str):
    score, strength, crack_time, entropy = calculate_password_strength(password)
    
    analysis = []
    if len(password) < 8:
        analysis.append("- Too short (min 8 characters)")
    else:
        analysis.append(f"+ Length: {len(password)} characters")
    
    if any(c.islower() for c in password):
        analysis.append("+ Has lowercase letters")
    else:
        analysis.append("- Missing lowercase letters")
    
    if any(c.isupper() for c in password):
        analysis.append("+ Has uppercase letters")
    else:
        analysis.append("- Missing uppercase letters")
    
    if any(c.isdigit() for c in password):
        analysis.append("+ Has numbers")
    else:
        analysis.append("- Missing numbers")
    
    if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        analysis.append("+ Has special characters")
    else:
        analysis.append("- Missing special characters")
    
    content = f"""**Password Analysis**

**Strength:** {strength}
**Score:** {score}/100
**Entropy:** {entropy}

**Time to crack (10B attempts/sec):**
`{crack_time}`

**Analysis:**
```diff
{chr(10).join(analysis)}
```"""
    
    class AnalysisView(discord.ui.LayoutView):
        container1 = discord.ui.Container(
            discord.ui.TextDisplay(content=content),
            accent_colour=discord.Colour(MAIN_COLOR),
        )
    
    await interaction.response.send_message(view=AnalysisView(), ephemeral=True)

@tree.command(name='crypto_info', description='Information about available encryption methods')
async def crypto_info_command(interaction: discord.Interaction):
    categories = {
        'classical': 'Classical Ciphers',
        'encoding': 'Encoding Methods',
        'stream': 'Stream Ciphers',
        'block': 'Block Ciphers'
    }
    
    content = "**Encryption Methods Available**\n\n"
    
    for cat_id, cat_name in categories.items():
        ciphers_in_cat = [f"`{k}`: {v['name']}" for k, v in CIPHERS.items() if v.get('category') == cat_id]
        if ciphers_in_cat:
            content += f"**{cat_name}**\n"
            content += "\n".join(ciphers_in_cat[:10])
            content += "\n\n"
    
    class InfoView(discord.ui.LayoutView):
        container1 = discord.ui.Container(
            discord.ui.TextDisplay(content=content[:3900]),
            discord.ui.TextDisplay(content=f"-# Total: {len(CIPHERS)} encryption methods | Use /encrypt to get started"),
            accent_colour=discord.Colour(MAIN_COLOR),
        )
    
    await interaction.response.send_message(view=InfoView(), ephemeral=True)

@tree.command(name='stats', description='Bot statistics')
async def stats_command(interaction: discord.Interaction):
    content = f"""**Bot Statistics**

**Stored Messages:** {len(encrypted_messages)}
**Available Ciphers:** {len(CIPHERS)}
**Hash Functions:** {len(HASH_FUNCTIONS)}
**Message Expiry:** {MESSAGE_EXPIRY_HOURS} hours
**Max Storage:** {MAX_MESSAGES_STORED}
**Rate Limit:** {RATE_LIMIT_SECONDS}s"""
    
    class StatsView(discord.ui.LayoutView):
        container1 = discord.ui.Container(
            discord.ui.TextDisplay(content=content),
            accent_colour=discord.Colour(MAIN_COLOR),
        )
    
    await interaction.response.send_message(view=StatsView(), ephemeral=True)

@tree.command(name='security_info', description='Information about storage security')
async def security_info_command(interaction: discord.Interaction):
    storage_exists = os.path.exists(STORAGE_FILE)
    has_master_key = MASTER_KEY is not None
    legacy_exists = os.path.exists(STORAGE_FILE_LEGACY)
    
    new_format = sum(1 for m in encrypted_messages.values() if 'key_hash' in m)
    old_format = sum(1 for m in encrypted_messages.values() if 'original_key' in m)
    
    storage_status = "Encrypted (AES-256-GCM)" if storage_exists else "Not created yet"
    key_status = "Configured (Global)" if has_master_key else "NOT CONFIGURED!"
    
    content = f"""**Security Information**

**Storage:** {storage_status}
**Master Key:** {key_status}
**Total Messages:** {len(encrypted_messages)}

**Key Format:**
+ Secure hash (PBKDF2): {new_format}
{'- Plain text (legacy): ' + str(old_format) if old_format > 0 else '+ No legacy format: 0'}"""
    
    if legacy_exists:
        content += "\n\n**Warning:** Legacy JSON file exists. Delete it securely."
    
    if old_format > 0:
        content += "\n\n**Note:** Legacy messages will be migrated when decrypted."
    
    if not has_master_key:
        content += "\n\n**ERROR:** Set BOT_MASTER_KEY environment variable!"
    
    class SecurityView(discord.ui.LayoutView):
        container1 = discord.ui.Container(
            discord.ui.TextDisplay(content=content),
            discord.ui.TextDisplay(content="-# The .enc file is encrypted with AES-256-GCM. Keys are stored as PBKDF2 hashes."),
            accent_colour=discord.Colour(MAIN_COLOR),
        )
    
    await interaction.response.send_message(view=SecurityView(), ephemeral=True)

# ==================== INTERACTION HANDLER ====================

@client.event
async def on_interaction(interaction: discord.Interaction):
    if interaction.type == discord.InteractionType.component:
        custom_id = interaction.data.get("custom_id", "")
        if custom_id == "persistent_decrypt_button":
            msg_id = None
            for stored_msg_id, data in encrypted_messages.items():
                if data.get('message_id') == interaction.message.id:
                    msg_id = stored_msg_id
                    break
            
            if not msg_id or msg_id not in encrypted_messages:
                class ErrorView(discord.ui.LayoutView):
                    container1 = discord.ui.Container(
                        discord.ui.TextDisplay(content="**Message expired or not found.**"),
                        accent_colour=discord.Colour(MAIN_COLOR),
                    )
                await interaction.response.send_message(view=ErrorView(), ephemeral=True)
                return
            
            modal = DecryptModal()
            modal.msg_id = msg_id
            await interaction.response.send_modal(modal)
            return
    
    if interaction.type != discord.InteractionType.modal_submit:
        return
    
    data = interaction.data
    if data.get("custom_id") != "encrypt_modal":
        return
    
    values = {}
    for comp in data.get("components", []):
        c = comp.get("component", comp)
        if "values" in c:
            values[c["custom_id"]] = c["values"]
        elif "value" in c:
            values[c["custom_id"]] = c["value"]
    
    cipher_type = values.get("cipher_select", [None])[0]
    text = values.get("text_input")
    key = values.get("key_input", "")
    
    if not cipher_type or not text:
        return
    
    if cipher_type not in CIPHERS:
        class ErrorView(discord.ui.LayoutView):
            container1 = discord.ui.Container(
                discord.ui.TextDisplay(content="**Invalid cipher type.**"),
                accent_colour=discord.Colour(MAIN_COLOR),
            )
        await interaction.response.send_message(view=ErrorView(), ephemeral=True)
        return
        
    try:
        cipher = CIPHERS[cipher_type]
        encrypted_text = cipher['encrypt'](text, key)
        
        key_hash, key_salt = hash_password(key)
        
        msg_id = f"{interaction.user.id}_{interaction.id}_{int(time.time())}"
        encrypted_messages[msg_id] = {
            'cipher': cipher_type,
            'encrypted': encrypted_text,
            'key_hash': key_hash,
            'key_salt': key_salt,
            'message_id': None,
            'timestamp': time.time(),
            'author_id': interaction.user.id
        }
        
        view = create_decrypt_view(msg_id, cipher['name'], encrypted_text, interaction.user.name)
        
        await interaction.response.send_message(view=view)
        
        try:
            message = await interaction.original_response()
            encrypted_messages[msg_id]['message_id'] = message.id
        except:
            pass
        
        save_encrypted_messages()
        logger.info(f"User {interaction.user.id} encrypted message with {cipher_type}")
        
    except Exception as e:
        logger.error(f"Encryption error: {e}")
        if not interaction.response.is_done():
            class ErrorView(discord.ui.LayoutView):
                container1 = discord.ui.Container(
                    discord.ui.TextDisplay(content=f"**Encryption Failed:** {str(e)}"),
                    accent_colour=discord.Colour(MAIN_COLOR),
                )
            await interaction.response.send_message(view=ErrorView(), ephemeral=True)

# ==================== BACKGROUND TASKS ====================

async def cleanup_task():
    """Tarea en segundo plano para limpiar mensajes expirados"""
    while True:
        await asyncio.sleep(3600)
        global encrypted_messages
        old_count = len(encrypted_messages)
        encrypted_messages = cleanup_expired_messages(encrypted_messages)
        if old_count != len(encrypted_messages):
            save_encrypted_messages()
            logger.info(f"Cleanup: {old_count - len(encrypted_messages)} messages removed")

# ==================== START ====================  

@client.event
async def on_ready():
    await tree.sync()
    logger.info(f'Bot Online: {client.user}')
    logger.info(f'Loaded {len(encrypted_messages)} encrypted messages')
    logger.info(f'Available ciphers: {len(CIPHERS)}')
    logger.info(f'Available hash functions: {len(HASH_FUNCTIONS)}')
    
    if MASTER_KEY:
        storage_status = "encrypted (AES-256-GCM)" if os.path.exists(STORAGE_FILE) else "new"
        logger.info(f'Storage: {storage_status}')
        logger.info('Master key: configured (global)')
    else:
        logger.error('Master key: NOT CONFIGURED!')
        logger.error('Set BOT_MASTER_KEY environment variable!')
    
    new_format = sum(1 for m in encrypted_messages.values() if 'key_hash' in m)
    old_format = sum(1 for m in encrypted_messages.values() if 'original_key' in m)
    if old_format > 0:
        logger.warning(f'{old_format} messages in legacy format (will be migrated automatically)')
    
    if os.path.exists(STORAGE_FILE_LEGACY):
        logger.warning(f'Legacy JSON file exists: {STORAGE_FILE_LEGACY}')
        logger.warning('Consider deleting it securely (contains plain text keys)')
    
    client.loop.create_task(cleanup_task())

# ==================== RUN ====================

if __name__ == "__main__":
    if not MASTER_KEY:
        print("=" * 60)
        print("ERROR: BOT_MASTER_KEY not configured!")
        print("This key is REQUIRED for the bot to work.")
        print("")
        print("Set it with:")
        print("  export BOT_MASTER_KEY='your_secret_key_here'")
        print("")
        print("This key must be the SAME on all servers.")
        print("=" * 60)
    
    if TOKEN:
        client.run(TOKEN)
    else:
        print("")
        print("ERROR: No token found!")
        print("Set the DISCORD_BOT_TOKEN environment variable:")
        print("  export DISCORD_BOT_TOKEN='your_token_here'")
        print("  python bot.py")
