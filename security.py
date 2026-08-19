#!/usr/bin/env python3
"""
=====================================================================
  SENTINEL MFA — Secure Access Console
  Modern Windows Lock Screen & Security Dashboard
=====================================================================

A full-featured MFA lock screen for Windows that runs after login.
It requires a TOTP code (or backup code) before the desktop is usable.
The application features a modern, user-friendly interface with themes,
settings, PIN strength meter, security dashboard, and more.

Dependencies:
    pip install PyQt5 pyotp "qrcode[pil]"

Run:
    python sentinel_mfa.py
"""

import sys
import os
import io
import json
import time
import hashlib
import secrets
import string
import ctypes
import socket
from datetime import datetime, timedelta

import pyotp
import qrcode

from PyQt5.QtCore import Qt, QTimer, QRegExp
from PyQt5.QtGui import QFont, QPixmap, QColor, QRegExpValidator
from PyQt5.QtWidgets import (
    QApplication, QWidget, QStackedWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QFrame, QGraphicsDropShadowEffect,
    QMessageBox, QProgressBar, QTextEdit, QScrollArea, QCheckBox,
    QGridLayout, QSpinBox, QComboBox, QGroupBox, QFormLayout
)

# =====================================================================
# CONFIGURATION / CONSTANTS
# =====================================================================

CONFIG_FILE = "mfa_config.json"
DEVICE_TOKEN_FILE = "device_token.txt"
APP_LABEL = "MyLaptopMFA"
ISSUER = "PythonSec"

DEFAULT_SESSION_TIMEOUT = 300
DEFAULT_TOTP_INTERVAL = 30
DEFAULT_LOCK_BEHAVIOR = "full_screen"
DEFAULT_THEME = "dark"

# ── Lockout & attempt limits ─────────────────────────────
MAX_PIN_ATTEMPTS = 3
PIN_LOCKOUT_DURATIONS = [30, 60, 300]      # 30s, 1m, 5m escalating

MAX_TOTP_ATTEMPTS = 5
TOTP_LOCKOUT_DURATION = 30

MAX_BACKUP_ATTEMPTS = 3
BACKUP_LOCKOUT_DURATIONS = [30, 60, 300]

# ── Backup codes ─────────────────────────────────────────
NB_BACKUP_CODES = 10
BACKUP_CODE_LENGTH = 8
BACKUP_CODE_CHARS = string.ascii_uppercase + string.digits

# ── PIN complexity ───────────────────────────────────────
PIN_MIN_LENGTH = 4
PIN_ALLOW_NUMERIC_ONLY = True
PIN_NO_REPEATED_DIGITS = False
PIN_DISALLOW_SEQUENTIAL = True

# ── Device token ─────────────────────────────────────────
DEVICE_TOKEN_VALIDITY_DAYS = 30
DEVICE_TOKEN_LENGTH = 32

# ── PBKDF2 ───────────────────────────────────────────────
PBKDF2_ITERATIONS = 200_000
PBKDF2_ALGORITHM = 'sha256'
SALT_LENGTH = 16

# ── Themes ───────────────────────────────────────────────
THEMES = {
    "dark": {
        "ACCENT": "#00e5c9",
        "ACCENT_DIM": "#0a3f3a",
        "DANGER": "#ff5470",
        "SUCCESS": "#3ddc97",
        "BG_ROOT": "#0a0e14",
        "BG_CARD": "#111826",
        "BG_FIELD": "#0d1420",
        "BORDER": "#1e2a3d",
        "TEXT_MAIN": "#e8eef5",
        "TEXT_DIM": "#7d8ba1",
    },
    "light": {
        "ACCENT": "#007aff",
        "ACCENT_DIM": "#cce5ff",
        "DANGER": "#ff3b30",
        "SUCCESS": "#34c759",
        "BG_ROOT": "#f0f2f5",
        "BG_CARD": "#ffffff",
        "BG_FIELD": "#f8f9fa",
        "BORDER": "#d1d1d6",
        "TEXT_MAIN": "#1c1c1e",
        "TEXT_DIM": "#6c6c70",
    }
}

# ── Default settings ─────────────────────────────────────
DEFAULT_SETTINGS = {
    "session_timeout": DEFAULT_SESSION_TIMEOUT,
    "totp_interval": DEFAULT_TOTP_INTERVAL,
    "lock_behavior": DEFAULT_LOCK_BEHAVIOR,
    "theme": DEFAULT_THEME,
    "language": "English",
    "notifications": "enabled",
    "pin_policy": "standard",
    "device_duration": DEVICE_TOKEN_VALIDITY_DAYS,
    "device_naming": "auto",
    "auto_revoke": "enabled",
    "failed_attempt_policy": "progressive",
    "security_logging": "enabled",
    "clipboard_clearing": "30",
    "auto_lock": "disabled",
    "backup_code_count": NB_BACKUP_CODES,
    "backup_code_length": BACKUP_CODE_LENGTH,
    "recovery_policy": "standard"
}

# =====================================================================
# WINDOWS SYSTEM LOCKDOWN
# =====================================================================

MOD_ALT = 0x0001
MOD_CONTROL = 0x0002
MOD_SHIFT = 0x0004
MOD_WIN = 0x0008

HOTKEYS = [
    (1, MOD_ALT, 0x09),                # Alt+Tab
    (2, MOD_ALT, 0x73),                # Alt+F4
    (3, MOD_WIN, 0x44),                # Win+D
    (4, MOD_WIN, 0x45),                # Win+E
    (5, MOD_WIN, 0x52),                # Win+R
    (6, MOD_WIN, 0x4C),                # Win+L
    (7, MOD_CONTROL | MOD_SHIFT, 0x1B),# Ctrl+Shift+Esc
    (8, MOD_CONTROL | MOD_ALT, 0x2E),  # Ctrl+Alt+Del (attempt)
]

def block_system_keys():
    user32 = ctypes.windll.user32
    for hotkey_id, modifiers, vk in HOTKEYS:
        user32.RegisterHotKey(None, hotkey_id, modifiers, vk)

def unblock_system_keys():
    user32 = ctypes.windll.user32
    for hotkey_id, _, _ in HOTKEYS:
        user32.UnregisterHotKey(None, hotkey_id)

def hide_taskbar():
    hwnd = ctypes.windll.user32.FindWindowW("Shell_TrayWnd", None)
    if hwnd:
        ctypes.windll.user32.ShowWindow(hwnd, 0)

def show_taskbar():
    hwnd = ctypes.windll.user32.FindWindowW("Shell_TrayWnd", None)
    if hwnd:
        ctypes.windll.user32.ShowWindow(hwnd, 1)

def hide_desktop_icons():
    progman = ctypes.windll.user32.FindWindowW("Progman", None)
    if progman:
        ctypes.windll.user32.ShowWindow(progman, 0)

def show_desktop_icons():
    progman = ctypes.windll.user32.FindWindowW("Progman", None)
    if progman:
        ctypes.windll.user32.ShowWindow(progman, 1)

# =====================================================================
# CORE MFA LOGIC
# =====================================================================

def hash_pin_legacy(pin: str) -> str:
    return hashlib.sha256(pin.encode()).hexdigest()

def generate_pin_salt() -> str:
    return secrets.token_hex(SALT_LENGTH)

def hash_pin_pbkdf2(pin: str, salt_hex: str) -> str:
    salt_bytes = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac(
        PBKDF2_ALGORITHM,
        pin.encode('utf-8'),
        salt_bytes,
        PBKDF2_ITERATIONS
    )
    return dk.hex()

def verify_pin(pin: str, stored_hash: str, salt_hex: str | None) -> bool:
    if salt_hex:
        return hash_pin_pbkdf2(pin, salt_hex) == stored_hash
    else:
        return hash_pin_legacy(pin) == stored_hash

def generate_backup_codes(n=NB_BACKUP_CODES, length=BACKUP_CODE_LENGTH):
    codes = []
    for _ in range(n):
        code = ''.join(secrets.choice(BACKUP_CODE_CHARS) for _ in range(length))
        codes.append(code)
    return codes

def hash_backup_code(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()

def load_config():
    if not os.path.exists(CONFIG_FILE):
        return None
    with open(CONFIG_FILE, "r") as f:
        data = json.load(f)
    # Ensure all fields exist
    defaults = {
        "last_totp_step": None,
        "backup_codes": [],
        "device_token_hash": None,
        "device_token_expiry": None,
        "device_label": None,
        "last_login": None,
        "settings": {},
        "last_failed_pin_time": None,
        "last_failed_totp_time": None,
        "last_failed_backup_time": None,
        "failed_attempts_today": 0,
        "failed_attempts_date": None,
        "backup_codes_generated_at": None,
        "pin_salt": None,
    }
    for key, val in defaults.items():
        if key not in data:
            data[key] = val
    # Ensure all default settings exist
    if not isinstance(data["settings"], dict):
        data["settings"] = {}
    for key, val in DEFAULT_SETTINGS.items():
        if key not in data["settings"]:
            data["settings"][key] = val
    return data

def save_config(pin_hash, totp_secret, last_totp_step=None, backup_codes=None,
                device_token_hash=None, device_token_expiry=None, device_label=None,
                last_login=None, settings=None,
                last_failed_pin_time=None, last_failed_totp_time=None,
                last_failed_backup_time=None, failed_attempts_today=None,
                failed_attempts_date=None, backup_codes_generated_at=None,
                pin_salt=None):
    existing = load_config() or {}
    if settings is None:
        settings = existing.get("settings", DEFAULT_SETTINGS.copy())
    # Merge with defaults
    for key, val in DEFAULT_SETTINGS.items():
        if key not in settings:
            settings[key] = val

    def get_preserved(key, arg, default=None):
        return arg if arg is not None else existing.get(key, default)

    config = {
        "pin_hash": pin_hash,
        "pin_salt": get_preserved("pin_salt", pin_salt),
        "totp_secret": totp_secret,
        "last_totp_step": last_totp_step,
        "backup_codes": backup_codes or [],
        "device_token_hash": device_token_hash,
        "device_token_expiry": device_token_expiry,
        "device_label": device_label,
        "last_login": last_login,
        "settings": settings,
        "last_failed_pin_time": get_preserved("last_failed_pin_time", last_failed_pin_time),
        "last_failed_totp_time": get_preserved("last_failed_totp_time", last_failed_totp_time),
        "last_failed_backup_time": get_preserved("last_failed_backup_time", last_failed_backup_time),
        "failed_attempts_today": get_preserved("failed_attempts_today", failed_attempts_today, 0),
        "failed_attempts_date": get_preserved("failed_attempts_date", failed_attempts_date),
        "backup_codes_generated_at": get_preserved("backup_codes_generated_at", backup_codes_generated_at)
    }
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)

def make_qr_pixmap(uri: str) -> QPixmap:
    img = qrcode.make(uri, box_size=8, border=2)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    pix = QPixmap()
    pix.loadFromData(buf.getvalue())
    return pix

# ---------------------------------------------------------------------
# PIN validation and strength
# ---------------------------------------------------------------------
def is_sequential(pin: str) -> bool:
    if len(pin) < 3:
        return False
    for i in range(len(pin) - 2):
        a, b, c = int(pin[i]), int(pin[i+1]), int(pin[i+2])
        if (a + 1 == b and b + 1 == c) or (a - 1 == b and b - 1 == c):
            return True
    return False

COMMON_PATTERNS = {
    "0000", "1111", "2222", "3333", "4444", "5555", "6666", "7777", "8888", "9999",
    "1234", "2345", "3456", "4567", "5678", "6789", "7890",
    "4321", "5432", "6543", "7654", "8765", "9876", "0987",
    "1357", "2468", "3579", "1470", "2580", "3690", "1590",
    "1122", "1212", "123123", "111222", "222333", "444555"
}

def is_common_pattern(pin: str) -> bool:
    return pin in COMMON_PATTERNS

def has_repeated_digits(pin: str) -> bool:
    if len(pin) < 3:
        return False
    for i in range(len(pin) - 2):
        if pin[i] == pin[i+1] == pin[i+2]:
            return True
    return False

def is_keyboard_pattern(pin: str) -> bool:
    keypad_neighbors = {
        '0': ['1', '2', '3', '4', '5', '6', '7', '8', '9'],
        '1': ['2', '4', '5'],
        '2': ['1', '3', '4', '5', '6'],
        '3': ['2', '5', '6'],
        '4': ['1', '2', '5', '7', '8'],
        '5': ['1', '2', '3', '4', '6', '7', '8', '9'],
        '6': ['2', '3', '5', '8', '9'],
        '7': ['4', '5', '8'],
        '8': ['4', '5', '6', '7', '9'],
        '9': ['5', '6', '8']
    }
    for i in range(len(pin)-1):
        if pin[i+1] not in keypad_neighbors.get(pin[i], []):
            return False
    return True

def is_date_pattern(pin: str) -> bool:
    if len(pin) != 4:
        return False
    try:
        month = int(pin[:2]); day = int(pin[2:])
        if 1 <= month <= 12 and 1 <= day <= 31:
            return True
        month = int(pin[2:]); day = int(pin[:2])
        if 1 <= month <= 12 and 1 <= day <= 31:
            return True
    except ValueError:
        pass
    return False

def validate_pin(pin: str) -> tuple[bool, str]:
    if len(pin) < PIN_MIN_LENGTH:
        return False, f"PIN must be at least {PIN_MIN_LENGTH} characters."
    if PIN_ALLOW_NUMERIC_ONLY and not pin.isdigit():
        return False, "PIN must contain only digits (0-9)."
    if is_sequential(pin):
        return False, "PIN cannot contain consecutive sequences (e.g., 123, 234, 765)."
    if has_repeated_digits(pin):
        return False, "PIN cannot contain three or more identical consecutive digits."
    if is_common_pattern(pin):
        return False, "PIN is too common and easily guessable."
    if is_keyboard_pattern(pin):
        return False, "PIN follows a keyboard pattern and is too weak."
    if is_date_pattern(pin):
        return False, "PIN resembles a date and is too weak."
    return True, ""

def compute_pin_strength(pin: str) -> tuple[int, str]:
    if not pin:
        return 0, ""
    length = len(pin)
    score = 0
    feedback = []

    if length >= 12: score += 30
    elif length >= 8: score += 25
    elif length >= 6: score += 15
    else: score += 5

    unique = len(set(pin))
    if unique >= 5: score += 20
    elif unique >= 4: score += 15
    elif unique >= 3: score += 10
    else: score += 5

    if is_sequential(pin): score -= 15; feedback.append("Sequential digits")
    if has_repeated_digits(pin): score -= 15; feedback.append("Repeated digits")
    if is_common_pattern(pin): score -= 20; feedback.append("Common pattern")
    if is_keyboard_pattern(pin): score -= 15; feedback.append("Keyboard pattern")
    if is_date_pattern(pin): score -= 10; feedback.append("Date pattern")

    score = max(0, min(100, score))
    if score >= 80: strength = "Strong"
    elif score >= 60: strength = "Good"
    elif score >= 40: strength = "Weak"
    else: strength = "Very weak"

    if feedback:
        return score, f"{strength} ({', '.join(feedback)})"
    return score, strength

# ---------------------------------------------------------------------
# Device token
# ---------------------------------------------------------------------
def generate_device_token(label=None):
    token = secrets.token_hex(DEVICE_TOKEN_LENGTH)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expiry = int(time.time()) + DEVICE_TOKEN_VALIDITY_DAYS * 24 * 3600
    if label is None:
        label = socket.gethostname()
    return token, token_hash, expiry, label

def save_device_token(token, expiry, label):
    with open(DEVICE_TOKEN_FILE, "w") as f:
        f.write(token)
    config = load_config()
    if config is None:
        return
    save_config(
        config["pin_hash"],
        config["totp_secret"],
        config["last_totp_step"],
        config["backup_codes"],
        hashlib.sha256(token.encode()).hexdigest(),
        expiry,
        label,
        config.get("last_login"),
        config.get("settings"),
        pin_salt=config.get("pin_salt")
    )

def clear_device_token():
    if os.path.exists(DEVICE_TOKEN_FILE):
        try:
            os.remove(DEVICE_TOKEN_FILE)
        except OSError:
            pass
    config = load_config()
    if config:
        save_config(
            config["pin_hash"],
            config["totp_secret"],
            config["last_totp_step"],
            config["backup_codes"],
            None,
            None,
            None,
            config.get("last_login"),
            config.get("settings"),
            pin_salt=config.get("pin_salt")
        )

def validate_device_token() -> bool:
    if not os.path.exists(DEVICE_TOKEN_FILE):
        return False
    config = load_config()
    if config is None:
        return False
    stored_hash = config.get("device_token_hash")
    expiry = config.get("device_token_expiry")
    if stored_hash is None or expiry is None:
        return False
    try:
        with open(DEVICE_TOKEN_FILE, "r") as f:
            token = f.read().strip()
    except OSError:
        return False
    if hashlib.sha256(token.encode()).hexdigest() != stored_hash:
        return False
    if int(time.time()) > expiry:
        return False
    return True

# =====================================================================
# REUSABLE UI COMPONENTS
# =====================================================================

_current_theme = "dark"

def get_theme_colors(theme_name=None):
    if theme_name is None:
        theme_name = _current_theme
    return THEMES.get(theme_name, THEMES["dark"])

class PasswordField(QWidget):
    def __init__(self, placeholder="", numeric=False, max_len=None, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self.edit = QLineEdit()
        self.edit.setPlaceholderText(placeholder)
        self.edit.setEchoMode(QLineEdit.Password)
        self.edit.setObjectName("inputField")
        self.edit.setMinimumHeight(48)
        if max_len:
            self.edit.setMaxLength(max_len)
        if numeric:
            self.edit.setValidator(QRegExpValidator(QRegExp(r"^\d*$")))
        self.toggle_btn = QPushButton("SHOW")
        self.toggle_btn.setObjectName("toggleBtn")
        self.toggle_btn.setCursor(Qt.PointingHandCursor)
        self.toggle_btn.setFixedWidth(60)
        self.toggle_btn.setFixedHeight(48)
        self.toggle_btn.clicked.connect(self._toggle)
        layout.addWidget(self.edit)
        layout.addWidget(self.toggle_btn)
        self._apply_style()

    def _apply_style(self):
        colors = get_theme_colors()
        self.setStyleSheet(f"""
            #inputField {{
                background: {colors["BG_FIELD"]};
                border: 1px solid {colors["BORDER"]};
                border-top-left-radius: 12px;
                border-bottom-left-radius: 12px;
                border-right: none;
                padding: 0 16px;
                color: {colors["TEXT_MAIN"]};
                font-size: 15px;
                letter-spacing: 2px;
            }}
            #inputField:focus {{
                border: 1px solid {colors["ACCENT"]};
                border-right: none;
            }}
            #toggleBtn {{
                background: {colors["BG_FIELD"]};
                border: 1px solid {colors["BORDER"]};
                border-left: none;
                border-top-right-radius: 12px;
                border-bottom-right-radius: 12px;
                color: {colors["TEXT_DIM"]};
                font-size: 10px;
                font-weight: 600;
                letter-spacing: 1px;
            }}
            #toggleBtn:hover {{
                color: {colors["TEXT_DIM"]};
            }}
        """)

    def _toggle(self):
        if self.edit.echoMode() == QLineEdit.Password:
            self.edit.setEchoMode(QLineEdit.Normal)
            self.toggle_btn.setText("HIDE")
        else:
            self.edit.setEchoMode(QLineEdit.Password)
            self.toggle_btn.setText("SHOW")

    def text(self):
        return self.edit.text()

    def clear(self):
        self.edit.clear()

    def set_error(self, is_error: bool):
        colors = get_theme_colors()
        border = colors["DANGER"] if is_error else colors["BORDER"]
        self.edit.setStyleSheet(f"border: 1px solid {border}; border-right: none;")

    def set_enabled(self, enabled: bool):
        self.edit.setEnabled(enabled)
        self.toggle_btn.setEnabled(enabled)

class PinStrengthMeter(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        colors = get_theme_colors()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(8)
        self.progress.setStyleSheet(f"""
            QProgressBar {{
                background: {colors['BG_FIELD']};
                border: 1px solid {colors['BORDER']};
                border-radius: 4px;
            }}
            QProgressBar::chunk {{
                background: {colors['ACCENT']};
                border-radius: 3px;
            }}
        """)
        layout.addWidget(self.progress)
        self.label = QLabel("")
        self.label.setStyleSheet(f"color: {colors['TEXT_DIM']}; font-size: 11px;")
        layout.addWidget(self.label)

    def update_strength(self, pin):
        score, feedback = compute_pin_strength(pin)
        self.progress.setValue(score)
        self.label.setText(feedback)
        colors = get_theme_colors()
        if score >= 80:
            color = colors["SUCCESS"]
        elif score >= 60:
            color = colors["ACCENT"]
        elif score >= 40:
            color = "#ffaa00"
        else:
            color = colors["DANGER"]
        self.progress.setStyleSheet(f"""
            QProgressBar {{
                background: {colors['BG_FIELD']};
                border: 1px solid {colors['BORDER']};
                border-radius: 4px;
            }}
            QProgressBar::chunk {{
                background: {color};
                border-radius: 3px;
            }}
        """)

def make_button(text, primary=True):
    btn = QPushButton(text)
    btn.setCursor(Qt.PointingHandCursor)
    btn.setMinimumHeight(46)
    colors = get_theme_colors()
    if primary:
        btn.setStyleSheet(f"""
            QPushButton {{
                background: {colors["ACCENT"]};
                color: #06110f;
                border: none;
                border-radius: 12px;
                font-size: 14px;
                font-weight: 700;
                letter-spacing: 0.5px;
            }}
            QPushButton:hover {{
                background: {colors["ACCENT"]};
                color: #06110f;
            }}
            QPushButton:pressed {{
                background: {colors["ACCENT"]};
                color: #06110f;
            }}
        """)
    else:
        btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                color: {colors["TEXT_DIM"]};
                border: 1px solid {colors["BORDER"]};
                border-radius: 12px;
                font-size: 13px;
                font-weight: 600;
            }}
            QPushButton:hover {{
                color: {colors["TEXT_DIM"]};
                border-color: {colors["BORDER"]};
            }}
            QPushButton:pressed {{
                color: {colors["TEXT_DIM"]};
                border-color: {colors["BORDER"]};
            }}
        """)
    return btn

def make_link_button(text):
    btn = QPushButton(text)
    btn.setCursor(Qt.PointingHandCursor)
    btn.setFlat(True)
    colors = get_theme_colors()
    btn.setStyleSheet(f"""
        QPushButton {{
            background: transparent;
            border: none;
            color: {colors["ACCENT"]};
            font-size: 13px;
            font-weight: 600;
            text-decoration: underline;
        }}
    """)
    return btn

class Card(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        self.setFixedWidth(480)
        colors = get_theme_colors()
        self.setStyleSheet(f"""
            #card {{
                background: {colors["BG_CARD"]};
                border: 1px solid {colors["BORDER"]};
                border-radius: 20px;
            }}
        """)
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(60)
        shadow.setOffset(0, 20)
        shadow.setColor(QColor(0, 0, 0, 160))
        self.setGraphicsEffect(shadow)
        self.layout_ = QVBoxLayout(self)
        self.layout_.setContentsMargins(40, 40, 40, 40)
        self.layout_.setSpacing(16)

    def add(self, widget, spacing_after=0):
        self.layout_.addWidget(widget)
        if spacing_after:
            self.layout_.addSpacing(spacing_after)

def title_label(text):
    colors = get_theme_colors()
    lbl = QLabel(text)
    lbl.setStyleSheet(f"color: {colors['TEXT_MAIN']}; font-size: 24px; font-weight: 800;")
    lbl.setAlignment(Qt.AlignCenter)
    lbl.setWordWrap(True)
    return lbl

def subtitle_label(text):
    colors = get_theme_colors()
    lbl = QLabel(text)
    lbl.setStyleSheet(f"color: {colors['TEXT_DIM']}; font-size: 13px;")
    lbl.setAlignment(Qt.AlignCenter)
    lbl.setWordWrap(True)
    return lbl

def error_label():
    colors = get_theme_colors()
    lbl = QLabel("")
    lbl.setStyleSheet(f"color: {colors['DANGER']}; font-size: 12px; font-weight: 600;")
    lbl.setAlignment(Qt.AlignCenter)
    lbl.setWordWrap(True)
    lbl.setFixedHeight(20)
    return lbl

def kicker_badge(text, color=None):
    colors = get_theme_colors()
    if color is None:
        color = colors["ACCENT"]
    lbl = QLabel(text)
    lbl.setAlignment(Qt.AlignCenter)
    lbl.setStyleSheet(f"""
        color: {color};
        font-size: 11px;
        font-weight: 800;
        letter-spacing: 3px;
        background: transparent;
    """)
    return lbl

# =====================================================================
# PAGES
# =====================================================================

class BasePage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addStretch(1)
        row = QHBoxLayout()
        row.addStretch(1)
        self.card = Card()
        row.addWidget(self.card)
        row.addStretch(1)
        outer.addLayout(row)
        outer.addStretch(1)

class WelcomePage(BasePage):
    def __init__(self, on_setup, parent=None):
        super().__init__(parent)
        c = self.card
        c.add(kicker_badge("SENTINEL MFA"))
        c.add(title_label("🔐 Secure Access Console"), 4)
        c.add(subtitle_label(
            "No credentials found on this device yet.\n"
            "Let's set up your PIN and Authenticator app."
        ), 24)
        btn = make_button("Set Up MFA")
        btn.clicked.connect(on_setup)
        c.add(btn)

class SetupPinPage(BasePage):
    def __init__(self, on_continue, parent=None):
        super().__init__(parent)
        c = self.card
        c.add(kicker_badge("STEP 1 OF 3"))
        c.add(title_label("Create Your PIN"), 2)
        c.add(subtitle_label(
            f"Minimum {PIN_MIN_LENGTH} digits, numbers only.\n"
            "Avoid sequences, repeated digits, and common patterns."
        ), 16)
        self.pin_field = PasswordField(placeholder="New PIN", numeric=True)
        self.confirm_field = PasswordField(placeholder="Confirm PIN", numeric=True)
        c.add(self.pin_field, 10)
        self.strength_meter = PinStrengthMeter()
        c.add(self.strength_meter, 12)
        c.add(self.confirm_field, 6)
        self.err = error_label()
        c.add(self.err, 10)
        self.pin_field.edit.textChanged.connect(self._update_strength)
        btn = make_button("Continue")
        btn.clicked.connect(lambda: on_continue(self.pin_field.text(), self.confirm_field.text()))
        c.add(btn)
        self.confirm_field.edit.returnPressed.connect(btn.click)

    def _update_strength(self, text):
        self.strength_meter.update_strength(text)

    def show_error(self, msg):
        self.err.setText(msg)
        self.pin_field.set_error(True)
        self.confirm_field.set_error(True)

    def clear_error(self):
        self.err.setText("")
        self.pin_field.set_error(False)
        self.confirm_field.set_error(False)

class SetupQRPage(BasePage):
    def __init__(self, on_verify, parent=None):
        super().__init__(parent)
        c = self.card
        c.add(kicker_badge("STEP 2 OF 3"))
        c.add(title_label("Scan With Authenticator"), 2)
        c.add(subtitle_label("Open Google Authenticator (or any TOTP app) and scan this code."), 14)
        self.qr_label = QLabel()
        self.qr_label.setAlignment(Qt.AlignCenter)
        self.qr_label.setStyleSheet(f"background: white; border-radius: 12px; padding: 12px;")
        c.add(self.qr_label, 14)
        c.add(subtitle_label("Can't scan? Enter this key manually:"), 4)
        secret_row = QHBoxLayout()
        self.secret_box = QLabel("")
        self.secret_box.setAlignment(Qt.AlignCenter)
        colors = get_theme_colors()
        self.secret_box.setStyleSheet(f"""
            background: {colors['BG_FIELD']}; border: 1px solid {colors['BORDER']}; border-radius: 10px;
            color: {colors['ACCENT']}; font-size: 13px; font-family: Consolas, monospace;
            padding: 10px; letter-spacing: 1px;
        """)
        self.copy_btn = make_button("Copy to Clipboard", primary=False)
        self.copy_btn.setFixedWidth(140)
        self.copy_btn.clicked.connect(self._copy_secret)
        secret_row.addWidget(self.secret_box)
        secret_row.addWidget(self.copy_btn)
        c.layout_.addLayout(secret_row)
        c.layout_.addSpacing(18)
        c.add(subtitle_label("Enter the 6-digit code to verify setup:"), 8)
        self.code_field = PasswordField(placeholder="000000", numeric=True, max_len=6)
        self.code_field.edit.setEchoMode(QLineEdit.Normal)
        self.code_field.toggle_btn.hide()
        self.code_field.edit.setAlignment(Qt.AlignCenter)
        self.code_field.edit.setStyleSheet(self.code_field.edit.styleSheet() + f"""
            font-size: 22px; font-weight: 700; letter-spacing: 6px;
            border-top-right-radius: 10px; border-bottom-right-radius: 10px; border-right: 1px solid {colors['BORDER']};
        """)
        c.add(self.code_field, 10)
        self.err = error_label()
        c.add(self.err, 6)
        self.verify_btn = make_button("Verify Setup")
        self.verify_btn.clicked.connect(self._on_verify_clicked)
        c.add(self.verify_btn, 4)
        self.code_field.edit.returnPressed.connect(self.verify_btn.click)
        self._copy_timer = QTimer(self)
        self._copy_timer.setSingleShot(True)
        self._copy_timer.timeout.connect(self._reset_copy_button)
        self._on_verify = on_verify

    def set_data(self, uri, secret):
        self.qr_label.setPixmap(make_qr_pixmap(uri).scaled(
            220, 220, Qt.KeepAspectRatio, Qt.SmoothTransformation
        ))
        self.secret_box.setText(secret)
        self._secret = secret

    def _copy_secret(self):
        QApplication.clipboard().setText(self._secret)
        self.copy_btn.setText("Copied!")
        self._copy_timer.start(2000)

    def _reset_copy_button(self):
        self.copy_btn.setText("Copy to Clipboard")

    def _on_verify_clicked(self):
        code = self.code_field.text().strip()
        if len(code) != 6:
            self.show_error("Please enter the 6-digit code.")
            return
        self._on_verify(code)

    def show_error(self, msg):
        self.err.setText(msg)
        self.code_field.set_error(True)

    def clear_error(self):
        self.err.setText("")
        self.code_field.set_error(False)

    def reset(self):
        self.code_field.clear()
        self.clear_error()

class LockPage(BasePage):
    def __init__(self, on_unlock, on_forgot, on_remembered_device, parent=None):
        super().__init__(parent)
        c = self.card
        c.add(kicker_badge("SENTINEL MFA"))
        c.add(title_label("🔒 Enter PIN to Unlock"), 2)
        c.add(subtitle_label("Step 1 of 2 — PIN verification"), 16)
        self.pin_field = PasswordField(placeholder="PIN", numeric=True)
        c.add(self.pin_field, 10)
        self.err = error_label()
        c.add(self.err, 8)
        self.unlock_btn = make_button("Unlock")
        self.unlock_btn.clicked.connect(lambda: on_unlock(self.pin_field.text()))
        c.add(self.unlock_btn, 14)
        self.pin_field.edit.returnPressed.connect(self.unlock_btn.click)
        forgot_row = QHBoxLayout()
        forgot_row.addStretch(1)
        self.forgot_btn = make_link_button("Forgot your PIN?")
        self.forgot_btn.clicked.connect(on_forgot)
        forgot_row.addWidget(self.forgot_btn)
        forgot_row.addStretch(1)
        c.layout_.addLayout(forgot_row)
        device_row = QHBoxLayout()
        device_row.addStretch(1)
        self.device_btn = make_link_button("Use remembered device")
        self.device_btn.clicked.connect(on_remembered_device)
        device_row.addWidget(self.device_btn)
        device_row.addStretch(1)
        c.layout_.addLayout(device_row)
        self._lockout_timer = QTimer(self)
        self._lockout_timer.timeout.connect(self._update_lockout)
        self._lockout_end = 0

    def show_error(self, msg):
        self.err.setText(msg)
        self.pin_field.set_error(True)

    def reset(self):
        self.pin_field.clear()
        self.err.setText("")
        self.pin_field.set_error(False)
        self._clear_lockout()

    def start_lockout(self, duration_seconds):
        self._lockout_end = time.time() + duration_seconds
        self.pin_field.set_enabled(False)
        self.unlock_btn.setEnabled(False)
        self.err.setText(f"Too many attempts. Locked out for {duration_seconds} seconds.")
        self._lockout_timer.start(1000)

    def _update_lockout(self):
        remaining = int(self._lockout_end - time.time())
        if remaining <= 0:
            self._clear_lockout()
            self.err.setText("Lockout expired. Try again.")
        else:
            self.err.setText(f"Locked out. Try again in {remaining} seconds.")

    def _clear_lockout(self):
        self._lockout_timer.stop()
        self.pin_field.set_enabled(True)
        self.unlock_btn.setEnabled(True)
        self.err.setText("")
        self.pin_field.set_error(False)

    def is_locked_out(self):
        return self._lockout_timer.isActive()

    def set_device_btn_visible(self, visible):
        self.device_btn.setVisible(visible)

class TotpPage(BasePage):
    def __init__(self, on_verify, on_back, on_backup, show_back=True, totp_interval=30, parent=None):
        super().__init__(parent)
        self.interval = totp_interval
        c = self.card
        self.kicker = kicker_badge("STEP 2 OF 2")
        c.add(self.kicker)
        self.clock_label = QLabel("")
        self.clock_label.setAlignment(Qt.AlignCenter)
        colors = get_theme_colors()
        self.clock_label.setStyleSheet(f"""
            color: {colors['TEXT_MAIN']};
            font-size: 32px;
            font-weight: 800;
            font-family: 'Segoe UI', 'Consolas', monospace;
            letter-spacing: 1px;
        """)
        c.add(self.clock_label, 2)
        self.date_label = QLabel("")
        self.date_label.setAlignment(Qt.AlignCenter)
        self.date_label.setStyleSheet(f"""
            color: {colors['TEXT_DIM']};
            font-size: 13px;
            font-weight: 500;
            letter-spacing: 1px;
        """)
        c.add(self.date_label, 12)
        self.title = title_label("Enter Authenticator Code")
        c.add(self.title, 2)
        self.subtitle = subtitle_label("Enter the 6-digit code from your Authenticator app.")
        c.add(self.subtitle, 16)
        self.totp_field = PasswordField(placeholder="000000", numeric=True, max_len=6)
        self.totp_field.edit.setEchoMode(QLineEdit.Normal)
        self.totp_field.toggle_btn.hide()
        self.totp_field.edit.setAlignment(Qt.AlignCenter)
        self.totp_field.edit.setStyleSheet(self.totp_field.edit.styleSheet() + f"""
            font-size: 28px; font-weight: 800; letter-spacing: 10px;
            border-top-right-radius: 10px; border-bottom-right-radius: 10px; border-right: 1px solid {colors['BORDER']};
        """)
        c.add(self.totp_field, 10)
        timer_row = QHBoxLayout()
        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(6)
        self.progress.setStyleSheet(f"""
            QProgressBar {{ background: {colors['BG_FIELD']}; border-radius: 3px; }}
            QProgressBar::chunk {{ background: {colors['ACCENT']}; border-radius: 3px; }}
        """)
        timer_row.addWidget(self.progress)
        c.layout_.addLayout(timer_row)
        self.timer_lbl = subtitle_label(f"Refreshes in {self.interval}s")
        self.timer_lbl.setStyleSheet(f"color: {colors['TEXT_DIM']}; font-size: 11px;")
        c.add(self.timer_lbl, 12)
        self.err = error_label()
        c.add(self.err, 8)
        self.verify_btn = make_button("Verify")
        self.verify_btn.clicked.connect(lambda: on_verify(self.totp_field.text()))
        c.add(self.verify_btn, 8)
        self.totp_field.edit.returnPressed.connect(self.verify_btn.click)
        backup_row = QHBoxLayout()
        backup_row.addStretch(1)
        self.backup_btn = make_link_button("Use a backup code")
        self.backup_btn.clicked.connect(on_backup)
        backup_row.addWidget(self.backup_btn)
        backup_row.addStretch(1)
        c.layout_.addLayout(backup_row)
        if show_back:
            back_btn = make_button("← Back", primary=False)
            back_btn.clicked.connect(on_back)
            c.add(back_btn)
        self._qtimer = QTimer(self)
        self._qtimer.timeout.connect(self._tick)
        self._qtimer.start(1000)
        self._tick()
        self._totp_lockout_timer = QTimer(self)
        self._totp_lockout_timer.timeout.connect(self._update_totp_lockout)
        self._totp_lockout_end = 0

    def set_mode(self, kicker, title, subtitle):
        self.kicker.setText(kicker)
        self.title.setText(title)
        self.subtitle.setText(subtitle)

    def update_interval(self, new_interval):
        self.interval = new_interval
        self._tick()

    def _tick(self):
        remaining = self.interval - (int(time.time()) % self.interval)
        self.progress.setMaximum(self.interval)
        self.progress.setValue(remaining)
        self.timer_lbl.setText(f"Refreshes in {remaining}s")
        now = datetime.now()
        self.clock_label.setText(now.strftime("%H:%M:%S"))
        self.date_label.setText(now.strftime("%A, %d %B %Y"))

    def show_error(self, msg):
        self.err.setText(msg)
        self.totp_field.set_error(True)

    def reset(self):
        self.totp_field.clear()
        self.err.setText("")
        self.totp_field.set_error(False)
        self._clear_totp_lockout()

    def start_totp_lockout(self, duration_seconds):
        self._totp_lockout_end = time.time() + duration_seconds
        self.totp_field.set_enabled(False)
        self.verify_btn.setEnabled(False)
        self.err.setText(f"Too many TOTP attempts. Locked out for {duration_seconds} seconds.")
        self._totp_lockout_timer.start(1000)

    def _update_totp_lockout(self):
        remaining = int(self._totp_lockout_end - time.time())
        if remaining <= 0:
            self._clear_totp_lockout()
            self.err.setText("TOTP lockout expired. Try again.")
        else:
            self.err.setText(f"TOTP locked out. Try again in {remaining} seconds.")

    def _clear_totp_lockout(self):
        self._totp_lockout_timer.stop()
        self.totp_field.set_enabled(True)
        self.verify_btn.setEnabled(True)
        self.err.setText("")
        self.totp_field.set_error(False)

    def is_totp_locked_out(self):
        return self._totp_lockout_timer.isActive()

class BackupCodeEntryPage(BasePage):
    def __init__(self, on_verify, on_back, parent=None):
        super().__init__(parent)
        c = self.card
        c.add(kicker_badge("BACKUP RECOVERY"))
        c.add(title_label("Enter Backup Code"), 2)
        c.add(subtitle_label("Enter one of your emergency backup codes."), 16)
        self.code_field = PasswordField(placeholder="ABC123XY", max_len=BACKUP_CODE_LENGTH)
        self.code_field.edit.setEchoMode(QLineEdit.Normal)
        self.code_field.toggle_btn.hide()
        c.add(self.code_field, 10)
        self.err = error_label()
        c.add(self.err, 8)
        self.verify_btn = make_button("Verify")
        self.verify_btn.clicked.connect(lambda: on_verify(self.code_field.text()))
        c.add(self.verify_btn, 8)
        self.code_field.edit.returnPressed.connect(self.verify_btn.click)
        back_btn = make_button("← Back", primary=False)
        back_btn.clicked.connect(on_back)
        c.add(back_btn)
        self._lockout_timer = QTimer(self)
        self._lockout_timer.timeout.connect(self._update_lockout)
        self._lockout_end = 0

    def show_error(self, msg):
        self.err.setText(msg)
        self.code_field.set_error(True)

    def reset(self):
        self.code_field.clear()
        self.err.setText("")
        self.code_field.set_error(False)
        self._clear_lockout()

    def start_lockout(self, duration_seconds):
        self._lockout_end = time.time() + duration_seconds
        self.code_field.set_enabled(False)
        self.verify_btn.setEnabled(False)
        self.err.setText(f"Too many backup code attempts. Locked out for {duration_seconds} seconds.")
        self._lockout_timer.start(1000)

    def _update_lockout(self):
        remaining = int(self._lockout_end - time.time())
        if remaining <= 0:
            self._clear_lockout()
            self.err.setText("Backup code lockout expired. Try again.")
        else:
            self.err.setText(f"Backup code locked out. Try again in {remaining} seconds.")

    def _clear_lockout(self):
        self._lockout_timer.stop()
        self.code_field.set_enabled(True)
        self.verify_btn.setEnabled(True)
        self.err.setText("")
        self.code_field.set_error(False)

    def is_locked_out(self):
        return self._lockout_timer.isActive()

class ManageBackupCodesPage(BasePage):
    def __init__(self, on_generate, on_back, parent=None):
        super().__init__(parent)
        c = self.card
        c.add(kicker_badge("MANAGE CODES"))
        c.add(title_label("Backup Recovery Codes"), 2)
        c.add(subtitle_label(
            "These codes can be used once each to unlock your account.\n"
            "Keep them in a safe place."
        ), 12)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        colors = get_theme_colors()
        scroll.setStyleSheet(f"""
            QScrollArea {{
                border: 1px solid {colors['BORDER']};
                border-radius: 10px;
                background: {colors['BG_FIELD']};
            }}
        """)
        self.list_widget = QWidget()
        self.list_layout = QVBoxLayout(self.list_widget)
        self.list_layout.setContentsMargins(10, 10, 10, 10)
        self.list_layout.setSpacing(6)
        scroll.setWidget(self.list_widget)
        c.add(scroll, 10)
        self.err = error_label()
        c.add(self.err, 8)
        gen_btn = make_button("Generate New Codes")
        gen_btn.clicked.connect(on_generate)
        c.add(gen_btn, 8)
        back_btn = make_button("← Back", primary=False)
        back_btn.clicked.connect(on_back)
        c.add(back_btn)

    def set_codes(self, codes):
        while self.list_layout.count():
            item = self.list_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        colors = get_theme_colors()
        for i, code_data in enumerate(codes):
            status = "✅ Used" if code_data.get("used", False) else "⬜ Available"
            color = colors['TEXT_DIM'] if code_data.get("used", False) else colors['ACCENT']
            label = QLabel(f"Code {i+1}: {status}")
            label.setStyleSheet(f"color: {color}; font-size: 13px; font-family: monospace;")
            self.list_layout.addWidget(label)
        note = QLabel("(Plaintext codes are not stored for security.)")
        note.setStyleSheet(f"color: {colors['TEXT_DIM']}; font-size: 11px;")
        self.list_layout.addWidget(note)
        self.list_layout.addStretch(1)

    def show_error(self, msg):
        self.err.setText(msg)

class ChangePinPage(BasePage):
    def __init__(self, on_save, on_back, parent=None):
        super().__init__(parent)
        c = self.card
        c.add(kicker_badge("CHANGE PIN"))
        c.add(title_label("Change Your PIN"), 2)
        c.add(subtitle_label(
            f"Minimum {PIN_MIN_LENGTH} digits.\n"
            "Avoid sequences, repeated digits, and common patterns."
        ), 16)
        self.current_pin_field = PasswordField(placeholder="Current PIN", numeric=True)
        self.new_pin_field = PasswordField(placeholder="New PIN", numeric=True)
        self.confirm_field = PasswordField(placeholder="Confirm New PIN", numeric=True)
        c.add(self.current_pin_field, 10)
        c.add(self.new_pin_field, 10)
        self.strength_meter = PinStrengthMeter()
        c.add(self.strength_meter, 10)
        c.add(self.confirm_field, 6)
        self.err = error_label()
        c.add(self.err, 10)
        self.new_pin_field.edit.textChanged.connect(self._update_strength)
        save_btn = make_button("Save New PIN")
        save_btn.clicked.connect(lambda: on_save(
            self.current_pin_field.text(),
            self.new_pin_field.text(),
            self.confirm_field.text()
        ))
        c.add(save_btn, 8)
        self.confirm_field.edit.returnPressed.connect(save_btn.click)
        back_btn = make_button("← Cancel", primary=False)
        back_btn.clicked.connect(on_back)
        c.add(back_btn)

    def _update_strength(self, text):
        self.strength_meter.update_strength(text)

    def show_error(self, msg):
        self.err.setText(msg)
        self.current_pin_field.set_error(True)
        self.new_pin_field.set_error(True)
        self.confirm_field.set_error(True)

    def clear_error(self):
        self.err.setText("")
        self.current_pin_field.set_error(False)
        self.new_pin_field.set_error(False)
        self.confirm_field.set_error(False)

    def reset(self):
        self.current_pin_field.clear()
        self.new_pin_field.clear()
        self.confirm_field.clear()
        self.clear_error()
        self.strength_meter.update_strength("")

class ResetPinPage(BasePage):
    def __init__(self, on_save, parent=None):
        super().__init__(parent)
        c = self.card
        c.add(kicker_badge("BACKUP VERIFIED"))
        c.add(title_label("Set A New PIN"), 2)
        c.add(subtitle_label(
            f"Minimum {PIN_MIN_LENGTH} digits.\n"
            "Avoid sequences, repeated digits, and common patterns."
        ), 16)
        self.pin_field = PasswordField(placeholder="New PIN", numeric=True)
        self.confirm_field = PasswordField(placeholder="Confirm New PIN", numeric=True)
        c.add(self.pin_field, 10)
        self.strength_meter = PinStrengthMeter()
        c.add(self.strength_meter, 10)
        c.add(self.confirm_field, 6)
        self.err = error_label()
        c.add(self.err, 10)
        self.pin_field.edit.textChanged.connect(self._update_strength)
        btn = make_button("Save New PIN & Continue")
        btn.clicked.connect(lambda: on_save(self.pin_field.text(), self.confirm_field.text()))
        c.add(btn)
        self.confirm_field.edit.returnPressed.connect(btn.click)

    def _update_strength(self, text):
        self.strength_meter.update_strength(text)

    def show_error(self, msg):
        self.err.setText(msg)
        self.pin_field.set_error(True)
        self.confirm_field.set_error(True)

    def clear_error(self):
        self.err.setText("")
        self.pin_field.set_error(False)
        self.confirm_field.set_error(False)

class ResetTotpPage(BasePage):
    def __init__(self, on_done, parent=None):
        super().__init__(parent)
        c = self.card
        c.add(kicker_badge("RESET TOTP"))
        c.add(title_label("Scan New Authenticator Code"), 2)
        c.add(subtitle_label("Your TOTP secret has been reset. Scan the new QR code with your Authenticator app."), 14)
        self.qr_label = QLabel()
        self.qr_label.setAlignment(Qt.AlignCenter)
        self.qr_label.setStyleSheet(f"background: white; border-radius: 12px; padding: 12px;")
        c.add(self.qr_label, 14)
        c.add(subtitle_label("Can't scan? Enter this key manually:"), 4)
        secret_row = QHBoxLayout()
        self.secret_box = QLabel("")
        self.secret_box.setAlignment(Qt.AlignCenter)
        colors = get_theme_colors()
        self.secret_box.setStyleSheet(f"""
            background: {colors['BG_FIELD']}; border: 1px solid {colors['BORDER']}; border-radius: 10px;
            color: {colors['ACCENT']}; font-size: 13px; font-family: Consolas, monospace;
            padding: 10px; letter-spacing: 1px;
        """)
        self.copy_btn = make_button("Copy to Clipboard", primary=False)
        self.copy_btn.setFixedWidth(140)
        self.copy_btn.clicked.connect(self._copy_secret)
        secret_row.addWidget(self.secret_box)
        secret_row.addWidget(self.copy_btn)
        c.layout_.addLayout(secret_row)
        c.layout_.addSpacing(18)
        c.add(subtitle_label("Enter the 6-digit code to verify:"), 8)
        self.code_field = PasswordField(placeholder="000000", numeric=True, max_len=6)
        self.code_field.edit.setEchoMode(QLineEdit.Normal)
        self.code_field.toggle_btn.hide()
        self.code_field.edit.setAlignment(Qt.AlignCenter)
        self.code_field.edit.setStyleSheet(self.code_field.edit.styleSheet() + f"""
            font-size: 22px; font-weight: 700; letter-spacing: 6px;
            border-top-right-radius: 10px; border-bottom-right-radius: 10px; border-right: 1px solid {colors['BORDER']};
        """)
        c.add(self.code_field, 10)
        self.err = error_label()
        c.add(self.err, 6)
        btn = make_button("Verify & Continue")
        btn.clicked.connect(self._on_verify_clicked)
        c.add(btn, 4)
        self.code_field.edit.returnPressed.connect(btn.click)
        self._copy_timer = QTimer(self)
        self._copy_timer.setSingleShot(True)
        self._copy_timer.timeout.connect(self._reset_copy_button)
        self._on_verify = on_done

    def set_data(self, uri, secret):
        self.qr_label.setPixmap(make_qr_pixmap(uri).scaled(
            220, 220, Qt.KeepAspectRatio, Qt.SmoothTransformation
        ))
        self.secret_box.setText(secret)
        self._secret = secret

    def _copy_secret(self):
        QApplication.clipboard().setText(self._secret)
        self.copy_btn.setText("Copied!")
        self._copy_timer.start(2000)

    def _reset_copy_button(self):
        self.copy_btn.setText("Copy to Clipboard")

    def _on_verify_clicked(self):
        code = self.code_field.text().strip()
        if len(code) != 6:
            self.show_error("Please enter the 6-digit code.")
            return
        self._on_verify(code)

    def show_error(self, msg):
        self.err.setText(msg)
        self.code_field.set_error(True)

    def clear_error(self):
        self.err.setText("")
        self.code_field.set_error(False)

    def reset(self):
        self.code_field.clear()
        self.clear_error()

class RememberDevicePage(BasePage):
    def __init__(self, on_continue, parent=None):
        super().__init__(parent)
        c = self.card
        c.add(kicker_badge("REMEMBER THIS DEVICE"))
        c.add(title_label("Remember Device?"), 2)
        c.add(subtitle_label(
            "Do you want to skip authentication on this device for the next "
            f"{DEVICE_TOKEN_VALIDITY_DAYS} days?"
        ), 16)
        label_row = QHBoxLayout()
        label_row.addWidget(QLabel("Device Label:"))
        self.label_edit = QLineEdit()
        self.label_edit.setText(socket.gethostname())
        colors = get_theme_colors()
        self.label_edit.setStyleSheet(f"""
            background: {colors['BG_FIELD']};
            border: 1px solid {colors['BORDER']};
            border-radius: 10px;
            padding: 6px 10px;
            color: {colors['TEXT_MAIN']};
            font-size: 13px;
        """)
        label_row.addWidget(self.label_edit)
        c.layout_.addLayout(label_row)
        expiry_date = datetime.now() + timedelta(days=DEVICE_TOKEN_VALIDITY_DAYS)
        expiry_str = expiry_date.strftime("%Y-%m-%d %H:%M")
        self.expiry_label = QLabel(f"Token will expire on: {expiry_str}")
        self.expiry_label.setStyleSheet(f"color: {colors['TEXT_DIM']}; font-size: 12px;")
        self.expiry_label.setAlignment(Qt.AlignCenter)
        c.add(self.expiry_label, 8)
        self.checkbox = QCheckBox("Remember this device")
        self.checkbox.setStyleSheet(f"""
            QCheckBox {{
                color: {colors['TEXT_MAIN']};
                font-size: 14px;
                spacing: 8px;
            }}
            QCheckBox::indicator {{
                width: 18px;
                height: 18px;
            }}
        """)
        self.checkbox.setCursor(Qt.PointingHandCursor)
        c.add(self.checkbox, 10)
        self.err = error_label()
        c.add(self.err, 8)
        continue_btn = make_button("Continue")
        continue_btn.clicked.connect(lambda: on_continue(
            self.checkbox.isChecked(),
            self.label_edit.text().strip() or socket.gethostname()
        ))
        c.add(continue_btn)

class InfoCard(QFrame):
    def __init__(self, title, parent=None):
        super().__init__(parent)
        self.setObjectName("infoCard")
        colors = get_theme_colors()
        self.setStyleSheet(f"""
            #infoCard {{
                background: {colors['BG_CARD']};
                border: 1px solid {colors['BORDER']};
                border-radius: 16px;
            }}
        """)
        self.layout_ = QVBoxLayout(self)
        self.layout_.setContentsMargins(20, 18, 20, 18)
        self.layout_.setSpacing(10)
        title_lbl = QLabel(title)
        title_lbl.setStyleSheet(f"color: {colors['ACCENT']}; font-size: 14px; font-weight: 700; letter-spacing: 1px;")
        self.layout_.addWidget(title_lbl)
        self.grid = QGridLayout()
        self.grid.setVerticalSpacing(6)
        self.grid.setHorizontalSpacing(20)
        self.layout_.addLayout(self.grid)

    def add_row(self, row, label, value_label):
        colors = get_theme_colors()
        key = QLabel(label)
        key.setStyleSheet(f"color: {colors['TEXT_DIM']}; font-size: 13px; font-weight: 500;")
        value_label.setStyleSheet(f"color: {colors['TEXT_MAIN']}; font-size: 13px; font-weight: 600;")
        self.grid.addWidget(key, row, 0)
        self.grid.addWidget(value_label, row, 1)

    def add_widget(self, widget):
        self.layout_.insertWidget(1, widget)

class BackupHealthWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        colors = get_theme_colors()
        self.layout_ = QVBoxLayout(self)
        self.layout_.setContentsMargins(0, 0, 0, 0)
        self.layout_.setSpacing(4)
        title = QLabel("BACKUP CODES")
        title.setStyleSheet(f"color: {colors['TEXT_DIM']}; font-size: 11px; font-weight: 700; letter-spacing: 2px;")
        self.layout_.addWidget(title)
        progress_row = QHBoxLayout()
        self.progress = QProgressBar()
        self.progress.setRange(0, NB_BACKUP_CODES)
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(20)
        self.progress.setStyleSheet(f"""
            QProgressBar {{
                background: {colors['BG_FIELD']};
                border: 1px solid {colors['BORDER']};
                border-radius: 4px;
            }}
            QProgressBar::chunk {{
                background: {colors['ACCENT']};
                border-radius: 3px;
            }}
        """)
        progress_row.addWidget(self.progress, stretch=1)
        self.count_label = QLabel("0/0")
        self.count_label.setStyleSheet(f"color: {colors['TEXT_MAIN']}; font-size: 13px; font-weight: 600;")
        progress_row.addWidget(self.count_label)
        self.layout_.addLayout(progress_row)
        self.status_label = QLabel("")
        self.status_label.setStyleSheet(f"color: {colors['SUCCESS']}; font-size: 13px; font-weight: 600;")
        self.layout_.addWidget(self.status_label)

    def update_health(self, unused, total):
        self.progress.setMaximum(total)
        self.progress.setValue(unused)
        self.count_label.setText(f"{unused}/{total}")
        colors = get_theme_colors()
        if unused == total:
            self.status_label.setText("Excellent")
            self.status_label.setStyleSheet(f"color: {colors['SUCCESS']}; font-size: 13px; font-weight: 600;")
        elif unused >= total * 0.4:
            self.status_label.setText("Good")
            self.status_label.setStyleSheet(f"color: {colors['SUCCESS']}; font-size: 13px; font-weight: 600;")
        elif unused > 1:
            self.status_label.setText("Running low")
            self.status_label.setStyleSheet(f"color: {colors['DANGER']}; font-size: 13px; font-weight: 600;")
        else:
            self.status_label.setText("Critical — regenerate codes")
            self.status_label.setStyleSheet(f"color: {colors['DANGER']}; font-size: 13px; font-weight: 600;")

class DashboardPage(QWidget):
    def __init__(self, on_lock, on_manage_backup, on_change_pin, on_reset_totp, on_reset_mfa,
                 on_forget_device, on_settings, parent=None):
        super().__init__(parent)
        colors = get_theme_colors()
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("background: transparent; border: none;")
        content = QWidget()
        content.setStyleSheet("background: transparent;")
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(24, 24, 24, 24)
        content_layout.setSpacing(16)
        scroll.setWidget(content)
        outer.addWidget(scroll)
        header = QLabel("🔐 Security Dashboard")
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet(f"color: {colors['TEXT_MAIN']}; font-size: 26px; font-weight: 800;")
        content_layout.addWidget(header)

        # Security Status
        self.status_card = InfoCard("Security Status")
        self.status_values = {}
        self.status_card.add_row(0, "MFA Status", self._make_value_label(self.status_values, "status"))
        self.status_card.add_row(1, "Last Authentication", self._make_value_label(self.status_values, "last_auth"))
        self.status_card.add_row(2, "Session Duration", self._make_value_label(self.status_values, "session_duration"))
        self.status_card.add_row(3, "Authenticator", self._make_value_label(self.status_values, "auth"))
        content_layout.addWidget(self.status_card)

        # Device
        self.device_card = InfoCard("Device")
        self.device_values = {}
        self.device_card.add_row(0, "Device Name", self._make_value_label(self.device_values, "device"))
        self.device_card.add_row(1, "Remembered", self._make_value_label(self.device_values, "remembered"))
        self.device_card.add_row(2, "Token Expiry", self._make_value_label(self.device_values, "token_expiry"))
        self.device_card.add_row(3, "Token Age", self._make_value_label(self.device_values, "token_age"))
        self.device_card.add_row(4, "Last Auth", self._make_value_label(self.device_values, "device_last_auth"))
        content_layout.addWidget(self.device_card)

        # Recovery
        self.recovery_card = InfoCard("Recovery")
        self.backup_health = BackupHealthWidget()
        self.recovery_card.add_widget(self.backup_health)
        self.recovery_values = {}
        self.recovery_card.add_row(0, "Last Regeneration", self._make_value_label(self.recovery_values, "backup_generated"))
        content_layout.addWidget(self.recovery_card)

        # Security Events
        self.events_card = InfoCard("Security Events")
        self.events_values = {}
        self.events_card.add_row(0, "Last Failed PIN", self._make_value_label(self.events_values, "last_failed_pin"))
        self.events_card.add_row(1, "Last Failed TOTP", self._make_value_label(self.events_values, "last_failed_totp"))
        self.events_card.add_row(2, "Last Failed Backup", self._make_value_label(self.events_values, "last_failed_backup"))
        self.events_card.add_row(3, "Failed Today", self._make_value_label(self.events_values, "failed_today"))
        self.events_card.add_row(4, "Last Success", self._make_value_label(self.events_values, "last_success"))
        content_layout.addWidget(self.events_card)

        # Actions
        actions_card = QFrame()
        actions_card.setObjectName("actionsCard")
        actions_card.setStyleSheet(f"""
            #actionsCard {{
                background: {colors['BG_CARD']};
                border: 1px solid {colors['BORDER']};
                border-radius: 16px;
            }}
        """)
        actions_layout = QVBoxLayout(actions_card)
        actions_layout.setContentsMargins(20, 18, 20, 18)
        actions_layout.setSpacing(8)
        lock_btn = make_button("Lock Now")
        lock_btn.clicked.connect(on_lock)
        actions_layout.addWidget(lock_btn)
        row1 = QHBoxLayout(); row1.setSpacing(6)
        manage_btn = make_button("Manage Codes", primary=False); manage_btn.setFixedHeight(36); manage_btn.clicked.connect(on_manage_backup)
        change_pin_btn = make_button("Change PIN", primary=False); change_pin_btn.setFixedHeight(36); change_pin_btn.clicked.connect(on_change_pin)
        row1.addWidget(manage_btn); row1.addWidget(change_pin_btn)
        actions_layout.addLayout(row1)
        row2 = QHBoxLayout(); row2.setSpacing(6)
        reset_totp_btn = make_button("Reset TOTP", primary=False); reset_totp_btn.setFixedHeight(36); reset_totp_btn.clicked.connect(on_reset_totp)
        reset_mfa_btn = make_button("Reset MFA", primary=False); reset_mfa_btn.setFixedHeight(36); reset_mfa_btn.clicked.connect(on_reset_mfa)
        row2.addWidget(reset_totp_btn); row2.addWidget(reset_mfa_btn)
        actions_layout.addLayout(row2)
        row3 = QHBoxLayout(); row3.setSpacing(6)
        forget_device_btn = make_button("Forget Device", primary=False); forget_device_btn.setFixedHeight(36); forget_device_btn.clicked.connect(on_forget_device)
        settings_btn = make_button("Settings", primary=False); settings_btn.setFixedHeight(36); settings_btn.clicked.connect(on_settings)
        row3.addWidget(forget_device_btn); row3.addWidget(settings_btn)
        actions_layout.addLayout(row3)
        content_layout.addWidget(actions_card)
        content_layout.addStretch(1)

    def _make_value_label(self, storage, key):
        lbl = QLabel("--")
        storage[key] = lbl
        return lbl

    def update_data(self, sentinel=None):
        config = load_config()
        if config is None:
            return
        colors = get_theme_colors()
        self.status_values["status"].setText("ENABLED")
        self.status_values["status"].setStyleSheet(f"color: {colors['SUCCESS']}; font-weight: 600;")
        last_login_ts = config.get("last_login")
        self.status_values["last_auth"].setText(
            datetime.fromtimestamp(last_login_ts).strftime("%Y-%m-%d %H:%M") if last_login_ts else "Never"
        )
        if sentinel and getattr(sentinel, '_last_auth_time', None):
            duration = int(time.time() - sentinel._last_auth_time)
            self.status_values["session_duration"].setText(f"{duration} seconds")
        else:
            self.status_values["session_duration"].setText("N/A")
        self.status_values["auth"].setText("Google Authenticator")

        device_label = config.get("device_label") or "Not set"
        self.device_values["device"].setText(device_label)
        remembered = config.get("device_token_hash") is not None and config.get("device_token_expiry") is not None
        if remembered:
            expiry = config.get("device_token_expiry")
            if int(time.time()) < expiry:
                self.device_values["remembered"].setText("Yes")
                self.device_values["remembered"].setStyleSheet(f"color: {colors['SUCCESS']};")
                self.device_values["token_expiry"].setText(datetime.fromtimestamp(expiry).strftime("%Y-%m-%d %H:%M"))
                issued = expiry - DEVICE_TOKEN_VALIDITY_DAYS * 24 * 3600
                age_days = (time.time() - issued) / (24 * 3600)
                self.device_values["token_age"].setText(f"{age_days:.1f} days")
            else:
                self.device_values["remembered"].setText("Expired")
                self.device_values["remembered"].setStyleSheet(f"color: {colors['DANGER']};")
                self.device_values["token_expiry"].setText(datetime.fromtimestamp(expiry).strftime("%Y-%m-%d %H:%M"))
                self.device_values["token_age"].setText("Expired")
        else:
            self.device_values["remembered"].setText("No")
            self.device_values["remembered"].setStyleSheet(f"color: {colors['TEXT_DIM']};")
            self.device_values["token_expiry"].setText("N/A")
            self.device_values["token_age"].setText("N/A")
        self.device_values["device_last_auth"].setText(self.status_values["last_auth"].text())

        backup_codes = config.get("backup_codes", [])
        unused = sum(1 for bc in backup_codes if not bc.get("used", False))
        total = len(backup_codes)
        self.backup_health.update_health(unused, total if total > 0 else NB_BACKUP_CODES)
        gen_ts = config.get("backup_codes_generated_at")
        self.recovery_values["backup_generated"].setText(
            datetime.fromtimestamp(gen_ts).strftime("%Y-%m-%d %H:%M") if gen_ts else "Never"
        )

        self.events_values["last_failed_pin"].setText(self._format_ts(config.get("last_failed_pin_time")))
        self.events_values["last_failed_totp"].setText(self._format_ts(config.get("last_failed_totp_time")))
        self.events_values["last_failed_backup"].setText(self._format_ts(config.get("last_failed_backup_time")))
        self.events_values["failed_today"].setText(str(config.get("failed_attempts_today", 0)))
        self.events_values["last_success"].setText(self._format_ts(config.get("last_login")))

    def _format_ts(self, ts):
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M") if ts else "None"

class SettingsPage(QWidget):
    def __init__(self, on_save, on_back, current_settings, parent=None):
        super().__init__(parent)
        colors = get_theme_colors()
        self._on_save = on_save
        self._on_back = on_back
        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(16)
        title = QLabel("⚙️ Settings")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet(f"color: {colors['TEXT_MAIN']}; font-size: 24px; font-weight: 800;")
        outer.addWidget(title)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("background: transparent; border: none;")
        content = QWidget()
        content.setStyleSheet("background: transparent;")
        scroll.setWidget(content)
        outer.addWidget(scroll, 1)
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(12)

        # General
        general_group = QGroupBox("GENERAL")
        general_layout = QFormLayout(general_group)
        self.theme_combo = QComboBox(); self.theme_combo.addItems(["dark", "light"])
        self.theme_combo.setCurrentText(current_settings.get("theme", DEFAULT_THEME))
        self.language_combo = QComboBox(); self.language_combo.addItems(["English", "Spanish", "French", "German"])
        self.language_combo.setCurrentText(current_settings.get("language", "English"))
        self.notifications_combo = QComboBox(); self.notifications_combo.addItems(["enabled", "disabled"])
        self.notifications_combo.setCurrentText(current_settings.get("notifications", "enabled"))
        general_layout.addRow("Theme:", self.theme_combo)
        general_layout.addRow("Language:", self.language_combo)
        general_layout.addRow("Notifications:", self.notifications_combo)
        content_layout.addWidget(general_group)

        # Authentication
        auth_group = QGroupBox("AUTHENTICATION")
        auth_layout = QFormLayout(auth_group)
        self.timeout_spin = QSpinBox(); self.timeout_spin.setRange(30, 3600); self.timeout_spin.setSingleStep(30)
        self.timeout_spin.setValue(current_settings.get("session_timeout", DEFAULT_SESSION_TIMEOUT))
        self.interval_spin = QSpinBox(); self.interval_spin.setRange(15, 120); self.interval_spin.setSingleStep(5)
        self.interval_spin.setValue(current_settings.get("totp_interval", DEFAULT_TOTP_INTERVAL))
        self.pin_policy_combo = QComboBox(); self.pin_policy_combo.addItems(["standard", "strict", "relaxed"])
        self.pin_policy_combo.setCurrentText(current_settings.get("pin_policy", "standard"))
        self.lock_combo = QComboBox(); self.lock_combo.addItems(["full_screen", "windowed", "standard"])
        self.lock_combo.setCurrentText(current_settings.get("lock_behavior", DEFAULT_LOCK_BEHAVIOR))
        auth_layout.addRow("Session Timeout (sec):", self.timeout_spin)
        auth_layout.addRow("TOTP Interval (sec):", self.interval_spin)
        auth_layout.addRow("PIN Policy:", self.pin_policy_combo)
        auth_layout.addRow("Lock Behavior:", self.lock_combo)
        content_layout.addWidget(auth_group)

        # Devices
        device_group = QGroupBox("DEVICES")
        device_layout = QFormLayout(device_group)
        self.device_duration_spin = QSpinBox(); self.device_duration_spin.setRange(1, 365)
        self.device_duration_spin.setValue(int(current_settings.get("device_duration", DEVICE_TOKEN_VALIDITY_DAYS)))
        self.device_naming_combo = QComboBox(); self.device_naming_combo.addItems(["auto", "custom"])
        self.device_naming_combo.setCurrentText(current_settings.get("device_naming", "auto"))
        self.auto_revoke_combo = QComboBox(); self.auto_revoke_combo.addItems(["enabled", "disabled"])
        self.auto_revoke_combo.setCurrentText(current_settings.get("auto_revoke", "enabled"))
        device_layout.addRow("Remembered Duration (days):", self.device_duration_spin)
        device_layout.addRow("Device Naming:", self.device_naming_combo)
        device_layout.addRow("Automatic Revocation:", self.auto_revoke_combo)
        content_layout.addWidget(device_group)

        # Security
        security_group = QGroupBox("SECURITY")
        security_layout = QFormLayout(security_group)
        self.failed_attempt_combo = QComboBox(); self.failed_attempt_combo.addItems(["progressive", "fixed", "strict"])
        self.failed_attempt_combo.setCurrentText(current_settings.get("failed_attempt_policy", "progressive"))
        self.security_logging_combo = QComboBox(); self.security_logging_combo.addItems(["enabled", "disabled"])
        self.security_logging_combo.setCurrentText(current_settings.get("security_logging", "enabled"))
        self.clipboard_spin = QSpinBox(); self.clipboard_spin.setRange(0, 300)
        self.clipboard_spin.setValue(int(current_settings.get("clipboard_clearing", 30)))
        self.auto_lock_combo = QComboBox(); self.auto_lock_combo.addItems(["disabled", "5min", "10min", "15min", "30min"])
        self.auto_lock_combo.setCurrentText(current_settings.get("auto_lock", "disabled"))
        security_layout.addRow("Failed-Attempt Policy:", self.failed_attempt_combo)
        security_layout.addRow("Security Logging:", self.security_logging_combo)
        security_layout.addRow("Clipboard Clearing (sec):", self.clipboard_spin)
        security_layout.addRow("Auto-Lock:", self.auto_lock_combo)
        content_layout.addWidget(security_group)

        # Recovery
        recovery_group = QGroupBox("RECOVERY")
        recovery_layout = QFormLayout(recovery_group)
        self.backup_count_spin = QSpinBox(); self.backup_count_spin.setRange(1, 20)
        self.backup_count_spin.setValue(int(current_settings.get("backup_code_count", NB_BACKUP_CODES)))
        self.backup_length_spin = QSpinBox(); self.backup_length_spin.setRange(6, 12)
        self.backup_length_spin.setValue(int(current_settings.get("backup_code_length", BACKUP_CODE_LENGTH)))
        self.recovery_policy_combo = QComboBox(); self.recovery_policy_combo.addItems(["standard", "strict", "offline"])
        self.recovery_policy_combo.setCurrentText(current_settings.get("recovery_policy", "standard"))
        recovery_layout.addRow("Backup Code Count:", self.backup_count_spin)
        recovery_layout.addRow("Backup Code Length:", self.backup_length_spin)
        recovery_layout.addRow("Recovery Policy:", self.recovery_policy_combo)
        content_layout.addWidget(recovery_group)

        self.err = error_label()
        content_layout.addWidget(self.err)
        btn_row = QHBoxLayout()
        save_btn = make_button("Save Settings"); save_btn.clicked.connect(self._collect_and_save)
        back_btn = make_button("← Back", primary=False); back_btn.clicked.connect(self._on_back)
        btn_row.addWidget(back_btn); btn_row.addWidget(save_btn)
        content_layout.addLayout(btn_row)

    def _collect_and_save(self):
        settings = {
            "theme": self.theme_combo.currentText(),
            "language": self.language_combo.currentText(),
            "notifications": self.notifications_combo.currentText(),
            "session_timeout": self.timeout_spin.value(),
            "totp_interval": self.interval_spin.value(),
            "pin_policy": self.pin_policy_combo.currentText(),
            "lock_behavior": self.lock_combo.currentText(),
            "device_duration": self.device_duration_spin.value(),
            "device_naming": self.device_naming_combo.currentText(),
            "auto_revoke": self.auto_revoke_combo.currentText(),
            "failed_attempt_policy": self.failed_attempt_combo.currentText(),
            "security_logging": self.security_logging_combo.currentText(),
            "clipboard_clearing": str(self.clipboard_spin.value()),
            "auto_lock": self.auto_lock_combo.currentText(),
            "backup_code_count": self.backup_count_spin.value(),
            "backup_code_length": self.backup_length_spin.value(),
            "recovery_policy": self.recovery_policy_combo.currentText()
        }
        self._on_save(settings)

    def show_error(self, msg):
        self.err.setText(msg)

# =====================================================================
# MAIN APPLICATION WINDOW
# =====================================================================

class SentinelMFA(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Sentinel MFA — Secure Access")
        self.resize(640, 800)
        self.setMinimumSize(480, 640)
        self._authenticated = False
        self._is_locked = False
        self._last_auth_time = None
        self.setWindowFlags(
            Qt.Window | Qt.WindowTitleHint | Qt.WindowCloseButtonHint |
            Qt.WindowMinimizeButtonHint | Qt.WindowMaximizeButtonHint
        )
        self._pending_secret = None
        self._pending_pin_hash = None
        self._pending_pin_salt = None
        self._forgot_flow = False
        self._pin_attempts = 0
        self._lockout_count = 0
        self._totp_attempts = 0
        self._backup_attempts = 0
        self._backup_lockout_count = 0

        config = load_config()
        if config is None:
            self.settings = DEFAULT_SETTINGS.copy()
        else:
            self.settings = config.get("settings", DEFAULT_SETTINGS.copy())
            for key, val in DEFAULT_SETTINGS.items():
                if key not in self.settings:
                    self.settings[key] = val

        self.session_timeout = self.settings.get("session_timeout", DEFAULT_SESSION_TIMEOUT)
        self.totp_interval = self.settings.get("totp_interval", DEFAULT_TOTP_INTERVAL)
        self.lock_behavior = self.settings.get("lock_behavior", DEFAULT_LOCK_BEHAVIOR)
        self.theme = self.settings.get("theme", DEFAULT_THEME)

        global _current_theme
        _current_theme = self.theme
        self._apply_theme()

        self._session_timer = QTimer(self)
        self._session_timer.setSingleShot(True)
        self._session_timer.timeout.connect(self._on_session_timeout)

        self.stack = QStackedWidget()
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(self.stack)

        # Pages
        self.welcome_page = WelcomePage(self.go_setup_pin)
        self.setup_pin_page = SetupPinPage(self.handle_setup_pin)
        self.setup_qr_page = SetupQRPage(self.handle_setup_verify)
        self.lock_page = LockPage(
            self.handle_unlock_pin, self.handle_forgot_pin, self.handle_remembered_device
        )
        self.totp_page = TotpPage(
            self.handle_totp_verify, self.handle_totp_back, self.handle_use_backup_code,
            show_back=False, totp_interval=self.totp_interval
        )
        self.backup_entry_page = BackupCodeEntryPage(self.handle_backup_verify, self.handle_totp_back)
        self.reset_pin_page = ResetPinPage(self.handle_reset_pin)
        self.remember_device_page = RememberDevicePage(self.handle_remember_device_choice)
        self.dashboard_page = DashboardPage(
            self.handle_lock_session, self.handle_manage_backup_codes,
            self.handle_change_pin, self.handle_reset_totp, self.handle_reset_mfa,
            self.handle_forget_device, self.handle_settings
        )
        self.manage_backup_page = ManageBackupCodesPage(
            self.handle_generate_backup_codes, self.handle_back_to_dashboard
        )
        self.change_pin_page = ChangePinPage(self.handle_change_pin_save, self.handle_back_to_dashboard)
        self.reset_totp_page = ResetTotpPage(self.handle_reset_totp_verify)
        self.settings_page = SettingsPage(
            self.handle_settings_save, self.handle_back_to_dashboard, self.settings
        )

        for p in [self.welcome_page, self.setup_pin_page, self.setup_qr_page,
                  self.lock_page, self.totp_page, self.backup_entry_page,
                  self.reset_pin_page, self.remember_device_page, self.dashboard_page,
                  self.manage_backup_page, self.change_pin_page, self.reset_totp_page,
                  self.settings_page]:
            self.stack.addWidget(p)

        self.start()

    def _apply_theme(self):
        global _current_theme
        _current_theme = self.theme
        colors = get_theme_colors()
        self.setStyleSheet(f"background: {colors['BG_ROOT']};")
        QApplication.instance().setStyleSheet("")

    def _enter_lock_mode(self):
        self._is_locked = True
        self._authenticated = False
        if self.lock_behavior == "full_screen":
            hide_taskbar(); hide_desktop_icons(); block_system_keys()
            self.setWindowFlags(Qt.Window | Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
            self.showFullScreen()
        elif self.lock_behavior == "windowed":
            hide_taskbar(); hide_desktop_icons(); block_system_keys()
            self.setWindowFlags(Qt.Window | Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
            self.showMaximized()
        else:
            self.setWindowFlags(
                Qt.Window | Qt.WindowTitleHint | Qt.WindowCloseButtonHint |
                Qt.WindowMinimizeButtonHint | Qt.WindowMaximizeButtonHint
            )
            self.showNormal()

        config = load_config()
        if config:
            self._active_secret = config["totp_secret"]
            self._active_config = config
            self.totp_page.set_mode(
                "AUTHENTICATE", "Enter Authenticator Code",
                "Enter the 6‑digit code from your Authenticator app."
            )
            self.totp_page.reset()
            self._goto(self.totp_page)
        else:
            self._goto(self.welcome_page)

    def _exit_lock_mode(self):
        self._is_locked = False
        self._authenticated = True
        self._last_auth_time = int(time.time())
        if self.lock_behavior in ("full_screen", "windowed"):
            show_taskbar(); show_desktop_icons(); unblock_system_keys()
        self.setWindowFlags(
            Qt.Window | Qt.WindowTitleHint | Qt.WindowCloseButtonHint |
            Qt.WindowMinimizeButtonHint | Qt.WindowMaximizeButtonHint
        )
        self.showNormal()

    def _goto(self, widget):
        self.stack.setCurrentWidget(widget)
        if widget in (self.dashboard_page, self.manage_backup_page,
                      self.change_pin_page, self.reset_totp_page, self.settings_page):
            self._start_session_timer()
        else:
            self._stop_session_timer()
        if widget == self.dashboard_page:
            self.dashboard_page.update_data(self)

    def _start_session_timer(self):
        self._session_timer.start(self.session_timeout * 1000)

    def _stop_session_timer(self):
        self._session_timer.stop()

    def _reset_session_timer(self):
        if self._session_timer.isActive():
            self._session_timer.start(self.session_timeout * 1000)

    def _on_session_timeout(self):
        current = self.stack.currentWidget()
        if current in (self.lock_page, self.welcome_page):
            return
        self.handle_lock_session()
        QMessageBox.information(self, "Session Expired", "Your session has timed out due to inactivity.")

    def mousePressEvent(self, event): self._reset_session_timer(); super().mousePressEvent(event)
    def mouseReleaseEvent(self, event): self._reset_session_timer(); super().mouseReleaseEvent(event)
    def mouseMoveEvent(self, event): self._reset_session_timer(); super().mouseMoveEvent(event)
    def keyPressEvent(self, event): self._reset_session_timer(); super().keyPressEvent(event)
    def keyReleaseEvent(self, event): self._reset_session_timer(); super().keyReleaseEvent(event)

    def closeEvent(self, event):
        if self._authenticated:
            event.accept()
        else:
            event.ignore()

    def _record_failed_attempt(self, kind):
        config = load_config()
        if not config:
            return
        now = int(time.time())
        today = datetime.now().strftime("%Y-%m-%d")
        if config.get("failed_attempts_date") != today:
            config["failed_attempts_today"] = 1
            config["failed_attempts_date"] = today
        else:
            config["failed_attempts_today"] = config.get("failed_attempts_today", 0) + 1
        if kind == "pin": config["last_failed_pin_time"] = now
        elif kind == "totp": config["last_failed_totp_time"] = now
        elif kind == "backup": config["last_failed_backup_time"] = now
        save_config(
            config["pin_hash"], config["totp_secret"], config["last_totp_step"],
            config.get("backup_codes", []),
            device_token_hash=config.get("device_token_hash"),
            device_token_expiry=config.get("device_token_expiry"),
            device_label=config.get("device_label"),
            last_login=config.get("last_login"),
            settings=config.get("settings"),
            last_failed_pin_time=config.get("last_failed_pin_time"),
            last_failed_totp_time=config.get("last_failed_totp_time"),
            last_failed_backup_time=config.get("last_failed_backup_time"),
            failed_attempts_today=config.get("failed_attempts_today"),
            failed_attempts_date=config.get("failed_attempts_date"),
            backup_codes_generated_at=config.get("backup_codes_generated_at"),
            pin_salt=config.get("pin_salt")
        )

    def _check_device_token_and_authenticate(self):
        if validate_device_token():
            config = load_config()
            if config:
                self._active_config = config
                self._active_secret = config["totp_secret"]
                self._exit_lock_mode()
                self._goto(self.dashboard_page)
                return True
        return False

    def start(self):
        self._enter_lock_mode()

    def go_setup_pin(self):
        self._goto(self.setup_pin_page)

    def handle_setup_pin(self, pin, confirm):
        self.setup_pin_page.clear_error()
        valid, msg = validate_pin(pin)
        if not valid:
            self.setup_pin_page.show_error(msg)
            return
        if pin != confirm:
            self.setup_pin_page.show_error("PINs do not match.")
            return
        salt = generate_pin_salt()
        pin_hash = hash_pin_pbkdf2(pin, salt)
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name=APP_LABEL, issuer_name=ISSUER)
        self._pending_pin_hash = pin_hash
        self._pending_pin_salt = salt
        self._pending_secret = secret
        save_config(
            self._pending_pin_hash, self._pending_secret, None, [],
            settings=self.settings, pin_salt=self._pending_pin_salt
        )
        self.setup_qr_page.set_data(uri, secret)
        self.setup_qr_page.reset()
        self.setup_pin_page.pin_field.clear()
        self.setup_pin_page.confirm_field.clear()
        self._goto(self.setup_qr_page)

    def handle_setup_verify(self, code):
        if not self._pending_secret:
            self.setup_qr_page.show_error("No secret found. Please start over.")
            return
        totp = pyotp.TOTP(self._pending_secret)
        if totp.verify(code):
            self.setup_qr_page.reset()
            self._authenticated = False
            self._enter_lock_mode()
        else:
            self.setup_qr_page.show_error("Invalid code. Please try again.")

    def handle_unlock_pin(self, pin):
        if self.lock_page.is_locked_out():
            return
        config = load_config()
        if config is None:
            QMessageBox.warning(self, "No Setup Found", "No MFA configuration found.")
            self._goto(self.welcome_page)
            return
        if not pin:
            self.lock_page.show_error("Please enter your PIN.")
            return
        if verify_pin(pin, config["pin_hash"], config.get("pin_salt")):
            self._forgot_flow = False
            self._active_secret = config["totp_secret"]
            self._active_config = config
            self.lock_page.reset()
            self._pin_attempts = 0
            self._lockout_count = 0
            self.totp_page.set_mode(
                "STEP 2 OF 2", "Enter Authenticator Code",
                "PIN correct. Now enter the 6-digit code."
            )
            self.totp_page.reset()
            self._totp_attempts = 0
            self._goto(self.totp_page)
        else:
            self._record_failed_attempt("pin")
            self._pin_attempts += 1
            if self._pin_attempts >= MAX_PIN_ATTEMPTS:
                self._lockout_count += 1
                idx = min(self._lockout_count - 1, len(PIN_LOCKOUT_DURATIONS) - 1)
                duration = PIN_LOCKOUT_DURATIONS[idx]
                self.lock_page.start_lockout(duration)
                self.lock_page.show_error(f"Too many failed attempts. Locked out for {duration} seconds.")
                self._pin_attempts = 0
            else:
                self.lock_page.show_error(
                    f"Incorrect PIN. Attempt {self._pin_attempts}/{MAX_PIN_ATTEMPTS}."
                )

    def handle_forgot_pin(self):
        pass

    def handle_totp_back(self):
        self._enter_lock_mode()

    def handle_use_backup_code(self):
        self.backup_entry_page.reset()
        self._backup_attempts = 0
        self._backup_lockout_count = 0
        self._goto(self.backup_entry_page)

    def handle_backup_verify(self, code):
        if self.backup_entry_page.is_locked_out():
            return
        if not code or len(code) != BACKUP_CODE_LENGTH:
            self.backup_entry_page.show_error(f"Enter a {BACKUP_CODE_LENGTH}-character code.")
            return
        config = load_config()
        if config is None:
            QMessageBox.warning(self, "No Setup Found", "No MFA configuration found.")
            self._goto(self.welcome_page)
            return
        backup_codes = config.get("backup_codes", [])
        input_hash = hash_backup_code(code)
        for bc in backup_codes:
            if bc["hash"] == input_hash and not bc["used"]:
                bc["used"] = True
                save_config(
                    config["pin_hash"], config["totp_secret"], config["last_totp_step"],
                    backup_codes, last_login=int(time.time()),
                    settings=self.settings, pin_salt=config.get("pin_salt")
                )
                self._active_config = load_config()
                self._pin_attempts = 0; self._lockout_count = 0
                self._totp_attempts = 0; self._backup_attempts = 0
                self._backup_lockout_count = 0; self._forgot_flow = False
                self._exit_lock_mode()
                self._goto(self.remember_device_page)
                return
        self._record_failed_attempt("backup")
        self._backup_attempts += 1
        if self._backup_attempts >= MAX_BACKUP_ATTEMPTS:
            self._backup_lockout_count += 1
            idx = min(self._backup_lockout_count - 1, len(BACKUP_LOCKOUT_DURATIONS) - 1)
            duration = BACKUP_LOCKOUT_DURATIONS[idx]
            self.backup_entry_page.start_lockout(duration)
            self.backup_entry_page.show_error(
                f"Too many failed backup code attempts. Locked out for {duration} seconds."
            )
            self._backup_attempts = 0
        else:
            self.backup_entry_page.show_error(
                f"Invalid or already used backup code. Attempt {self._backup_attempts}/{MAX_BACKUP_ATTEMPTS}."
            )

    def handle_totp_verify(self, code):
        if self.totp_page.is_totp_locked_out():
            return
        if not code or len(code) != 6:
            self.totp_page.show_error("Enter the 6-digit code.")
            return
        totp = pyotp.TOTP(self._active_secret, interval=self.totp_interval)
        if not totp.verify(code):
            self._record_failed_attempt("totp")
            self._totp_attempts += 1
            if self._totp_attempts >= MAX_TOTP_ATTEMPTS:
                self.totp_page.start_totp_lockout(TOTP_LOCKOUT_DURATION)
                self.totp_page.show_error(
                    f"Too many failed TOTP attempts. Locked out for {TOTP_LOCKOUT_DURATION} seconds."
                )
                self._totp_attempts = 0
            else:
                self.totp_page.show_error(
                    f"Incorrect TOTP code. Attempt {self._totp_attempts}/{MAX_TOTP_ATTEMPTS}."
                )
            return
        current_step = int(time.time()) // self.totp_interval
        last_step = self._active_config.get("last_totp_step")
        if last_step is not None and current_step <= last_step:
            self.totp_page.show_error("This code has already been used. Please wait for a new one.")
            return
        save_config(
            self._active_config["pin_hash"], self._active_config["totp_secret"],
            current_step, self._active_config.get("backup_codes", []),
            last_login=int(time.time()), settings=self.settings,
            pin_salt=self._active_config.get("pin_salt")
        )
        self._active_config["last_totp_step"] = current_step
        self._totp_attempts = 0
        self._exit_lock_mode()
        self._goto(self.remember_device_page)

    def handle_remember_device_choice(self, remember: bool, label: str):
        if remember:
            token, _, expiry, label = generate_device_token(label)
            save_device_token(token, expiry, label)
            self._active_config = load_config()
        self._goto(self.dashboard_page)

    def handle_reset_pin(self, pin, confirm):
        self.reset_pin_page.clear_error()
        valid, msg = validate_pin(pin)
        if not valid:
            self.reset_pin_page.show_error(msg)
            return
        if pin != confirm:
            self.reset_pin_page.show_error("PINs do not match.")
            return
        salt = generate_pin_salt()
        pin_hash = hash_pin_pbkdf2(pin, salt)
        save_config(
            pin_hash, self._active_secret, self._active_config["last_totp_step"],
            self._active_config.get("backup_codes", []),
            settings=self.settings, pin_salt=salt
        )
        self.reset_pin_page.pin_field.clear()
        self.reset_pin_page.confirm_field.clear()
        QMessageBox.information(self, "PIN Updated", "Your PIN was updated successfully.")
        self._goto(self.remember_device_page)

    def handle_lock_session(self):
        self._stop_session_timer()
        self._pin_attempts = 0; self._lockout_count = 0
        self._totp_attempts = 0; self._backup_attempts = 0
        self._backup_lockout_count = 0
        self._enter_lock_mode()

    def handle_remembered_device(self):
        if self._check_device_token_and_authenticate():
            return
        self.lock_page.set_device_btn_visible(False)
        self.lock_page.show_error("Remembered device token is invalid or expired.")

    def handle_forget_device(self):
        clear_device_token()
        self._active_config = load_config()
        QMessageBox.information(self, "Device Forgotten", "This device will no longer be remembered.")
        self.dashboard_page.update_data(self)

    def handle_manage_backup_codes(self):
        config = load_config()
        if config is None:
            QMessageBox.warning(self, "No Setup Found", "No MFA configuration found.")
            return
        self.manage_backup_page.set_codes(config.get("backup_codes", []))
        self._goto(self.manage_backup_page)

    def handle_generate_backup_codes(self):
        config = load_config()
        if config is None:
            QMessageBox.warning(self, "No Setup Found", "No MFA configuration found.")
            return
        plain_codes = generate_backup_codes(
            n=int(self.settings.get("backup_code_count", NB_BACKUP_CODES)),
            length=int(self.settings.get("backup_code_length", BACKUP_CODE_LENGTH))
        )
        hashed_codes = [{"hash": hash_backup_code(c), "used": False} for c in plain_codes]
        save_config(
            config["pin_hash"], config["totp_secret"], config["last_totp_step"],
            hashed_codes, last_login=config.get("last_login"),
            settings=self.settings, backup_codes_generated_at=int(time.time()),
            pin_salt=config.get("pin_salt")
        )
        self._active_config = load_config()
        code_list = "\n".join(f"{i+1}. {c}" for i, c in enumerate(plain_codes))
        QMessageBox.information(
            self, "New Backup Codes",
            f"Your new backup codes are:\n\n{code_list}\n\n"
            "Write them down and keep them safe. These are the only times you will see them."
        )
        self.manage_backup_page.set_codes(hashed_codes)
        self.manage_backup_page.show_error("")
        self.dashboard_page.update_data(self)

    def handle_back_to_dashboard(self):
        self._goto(self.dashboard_page)

    def handle_change_pin(self):
        self.change_pin_page.reset()
        self._goto(self.change_pin_page)

    def handle_change_pin_save(self, current_pin, new_pin, confirm):
        self.change_pin_page.clear_error()
        config = load_config()
        if config is None:
            QMessageBox.warning(self, "No Setup Found", "No MFA configuration found.")
            self._goto(self.welcome_page)
            return
        if not verify_pin(current_pin, config["pin_hash"], config.get("pin_salt")):
            self.change_pin_page.show_error("Current PIN is incorrect.")
            return
        valid, msg = validate_pin(new_pin)
        if not valid:
            self.change_pin_page.show_error(msg)
            return
        if new_pin != confirm:
            self.change_pin_page.show_error("New PINs do not match.")
            return
        salt = generate_pin_salt()
        pin_hash = hash_pin_pbkdf2(new_pin, salt)
        save_config(
            pin_hash, config["totp_secret"], config["last_totp_step"],
            config.get("backup_codes", []), last_login=config.get("last_login"),
            settings=self.settings, pin_salt=salt
        )
        self._active_config = load_config()
        self.change_pin_page.reset()
        QMessageBox.information(self, "PIN Changed", "Your PIN has been changed successfully.")
        self._goto(self.dashboard_page)

    def handle_reset_totp(self):
        config = load_config()
        if config is None:
            QMessageBox.warning(self, "No Setup Found", "No MFA configuration found.")
            self._goto(self.welcome_page)
            return
        new_secret = pyotp.random_base32()
        totp = pyotp.TOTP(new_secret, interval=self.totp_interval)
        uri = totp.provisioning_uri(name=APP_LABEL, issuer_name=ISSUER)
        save_config(
            config["pin_hash"], new_secret, None, config.get("backup_codes", []),
            last_login=config.get("last_login"), settings=self.settings,
            pin_salt=config.get("pin_salt")
        )
        self._active_config = load_config()
        self._active_secret = new_secret
        self.reset_totp_page.set_data(uri, new_secret)
        self.reset_totp_page.reset()
        self._goto(self.reset_totp_page)

    def handle_reset_totp_verify(self, code):
        if not self._active_secret:
            self.reset_totp_page.show_error("No secret found.")
            return
        totp = pyotp.TOTP(self._active_secret, interval=self.totp_interval)
        if totp.verify(code):
            self.reset_totp_page.reset()
            QMessageBox.information(self, "TOTP Reset", "Your authenticator has been reset and verified.")
            self._goto(self.dashboard_page)
        else:
            self.reset_totp_page.show_error("Invalid code. Please try again.")

    def handle_settings(self):
        self.settings_page.theme_combo.setCurrentText(self.settings.get("theme", DEFAULT_THEME))
        self.settings_page.language_combo.setCurrentText(self.settings.get("language", "English"))
        self.settings_page.notifications_combo.setCurrentText(self.settings.get("notifications", "enabled"))
        self.settings_page.timeout_spin.setValue(self.settings.get("session_timeout", DEFAULT_SESSION_TIMEOUT))
        self.settings_page.interval_spin.setValue(self.settings.get("totp_interval", DEFAULT_TOTP_INTERVAL))
        self.settings_page.pin_policy_combo.setCurrentText(self.settings.get("pin_policy", "standard"))
        self.settings_page.lock_combo.setCurrentText(self.settings.get("lock_behavior", DEFAULT_LOCK_BEHAVIOR))
        self.settings_page.device_duration_spin.setValue(int(self.settings.get("device_duration", DEVICE_TOKEN_VALIDITY_DAYS)))
        self.settings_page.device_naming_combo.setCurrentText(self.settings.get("device_naming", "auto"))
        self.settings_page.auto_revoke_combo.setCurrentText(self.settings.get("auto_revoke", "enabled"))
        self.settings_page.failed_attempt_combo.setCurrentText(self.settings.get("failed_attempt_policy", "progressive"))
        self.settings_page.security_logging_combo.setCurrentText(self.settings.get("security_logging", "enabled"))
        self.settings_page.clipboard_spin.setValue(int(self.settings.get("clipboard_clearing", 30)))
        self.settings_page.auto_lock_combo.setCurrentText(self.settings.get("auto_lock", "disabled"))
        self.settings_page.backup_count_spin.setValue(int(self.settings.get("backup_code_count", NB_BACKUP_CODES)))
        self.settings_page.backup_length_spin.setValue(int(self.settings.get("backup_code_length", BACKUP_CODE_LENGTH)))
        self.settings_page.recovery_policy_combo.setCurrentText(self.settings.get("recovery_policy", "standard"))
        self.settings_page.show_error("")
        self._goto(self.settings_page)

    def handle_settings_save(self, new_settings):
        self.settings = new_settings
        self.session_timeout = new_settings["session_timeout"]
        self.totp_interval = new_settings["totp_interval"]
        self.lock_behavior = new_settings["lock_behavior"]
        self.theme = new_settings["theme"]
        config = load_config()
        if config is None:
            QMessageBox.warning(self, "No Config", "No MFA configuration found.")
            return
        save_config(
            config["pin_hash"], config["totp_secret"], config["last_totp_step"],
            config["backup_codes"], config.get("device_token_hash"),
            config.get("device_token_expiry"), config.get("device_label"),
            config.get("last_login"), settings=self.settings,
            pin_salt=config.get("pin_salt")
        )
        self.totp_page.update_interval(self.totp_interval)
        if self._session_timer.isActive():
            self._start_session_timer()
        if self.theme != _current_theme:
            self._apply_theme()
            reply = QMessageBox.question(
                self, "Theme Changed",
                "Theme changes require an application restart to take full effect. Restart now?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                QApplication.quit()
                os.execl(sys.executable, sys.executable, *sys.argv)
        QMessageBox.information(self, "Settings Saved", "Settings have been saved successfully.")
        self._goto(self.dashboard_page)

    def handle_reset_mfa(self):
        reply = QMessageBox.question(
            self, "Reset MFA?",
            "This will permanently delete all your MFA credentials and cannot be undone.\n\n"
            "Are you sure you want to continue?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply != QMessageBox.Yes:
            return
        if os.path.exists(CONFIG_FILE):
            try:
                os.remove(CONFIG_FILE)
            except OSError:
                save_config("", "", None, [])
        clear_device_token()
        self._pending_secret = None
        self._pending_pin_hash = None
        self._pending_pin_salt = None
        self._forgot_flow = False
        self._pin_attempts = 0; self._lockout_count = 0
        self._totp_attempts = 0; self._backup_attempts = 0
        self._backup_lockout_count = 0
        self._active_config = None
        self._active_secret = None
        self._last_auth_time = None
        self._stop_session_timer()
        QMessageBox.information(self, "MFA Reset", "All credentials have been erased.")
        self._goto(self.welcome_page)

# =====================================================================
# ENTRY POINT
# =====================================================================

def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setFont(QFont("Segoe UI", 10))
    window = SentinelMFA()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()