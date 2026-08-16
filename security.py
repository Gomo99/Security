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
from ctypes import wintypes
from datetime import datetime, timedelta

import pyotp
import qrcode

from PyQt5.QtCore import (
    Qt, QTimer, QRegExp
)
from PyQt5.QtGui import (
    QFont, QPixmap, QColor, QRegExpValidator
)
from PyQt5.QtWidgets import (
    QApplication, QWidget, QStackedWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QFrame, QGraphicsDropShadowEffect,
    QMessageBox, QProgressBar, QTextEdit, QScrollArea, QCheckBox,
    QGridLayout, QSpinBox, QComboBox
)

# =====================================================================
# CONFIGURATION / CONSTANTS
# =====================================================================

CONFIG_FILE = "mfa_config.json"
DEVICE_TOKEN_FILE = "device_token.txt"
APP_LABEL = "MyLaptopMFA"
ISSUER = "PythonSec"

# Default settings (overridden by config)
DEFAULT_SESSION_TIMEOUT = 300
DEFAULT_TOTP_INTERVAL = 30
DEFAULT_LOCK_BEHAVIOR = "full_screen"
DEFAULT_THEME = "dark"

# Color palettes for themes
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

# PIN lockout settings (hardcoded, not configurable via UI)
MAX_PIN_ATTEMPTS = 3
PIN_LOCKOUT_DURATIONS = [30, 60, 300]

# TOTP lockout settings
MAX_TOTP_ATTEMPTS = 5
TOTP_LOCKOUT_DURATION = 30

# Backup code lockout settings
MAX_BACKUP_ATTEMPTS = 3
BACKUP_LOCKOUT_DURATIONS = [30, 60, 300]

# Backup codes settings
NB_BACKUP_CODES = 10
BACKUP_CODE_LENGTH = 8
BACKUP_CODE_CHARS = string.ascii_uppercase + string.digits

# PIN complexity rules
PIN_MIN_LENGTH = 4
PIN_ALLOW_NUMERIC_ONLY = True
PIN_NO_REPEATED_DIGITS = False
PIN_DISALLOW_SEQUENTIAL = True

# Device token settings
DEVICE_TOKEN_VALIDITY_DAYS = 30
DEVICE_TOKEN_LENGTH = 32


# =====================================================================
# WINDOWS SYSTEM LOCKDOWN
# =====================================================================

MOD_ALT = 0x0001
MOD_CONTROL = 0x0002
MOD_SHIFT = 0x0004
MOD_WIN = 0x0008

HOTKEYS = [
    (1, MOD_ALT, 0x09),
    (2, MOD_ALT, 0x73),
    (3, MOD_WIN, 0x44),
    (4, MOD_WIN, 0x45),
    (5, MOD_WIN, 0x52),
    (6, MOD_WIN, 0x4C),
    (7, MOD_CONTROL | MOD_SHIFT, 0x1B),
    (8, MOD_CONTROL | MOD_ALT, 0x2E),
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

def hash_pin(pin: str) -> str:
    return hashlib.sha256(pin.encode()).hexdigest()

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
    if "last_totp_step" not in data:
        data["last_totp_step"] = None
    if "backup_codes" not in data:
        data["backup_codes"] = []
    if "device_token_hash" not in data:
        data["device_token_hash"] = None
    if "device_token_expiry" not in data:
        data["device_token_expiry"] = None
    if "device_label" not in data:
        data["device_label"] = None
    if "last_login" not in data:
        data["last_login"] = None
    if "settings" not in data:
        data["settings"] = {}
    if "session_timeout" not in data["settings"]:
        data["settings"]["session_timeout"] = DEFAULT_SESSION_TIMEOUT
    if "totp_interval" not in data["settings"]:
        data["settings"]["totp_interval"] = DEFAULT_TOTP_INTERVAL
    if "lock_behavior" not in data["settings"]:
        data["settings"]["lock_behavior"] = DEFAULT_LOCK_BEHAVIOR
    if "theme" not in data["settings"]:
        data["settings"]["theme"] = DEFAULT_THEME
    return data

def save_config(pin_hash: str, totp_secret: str, last_totp_step=None, backup_codes=None,
                device_token_hash=None, device_token_expiry=None, device_label=None,
                last_login=None, settings=None):
    if settings is None:
        # Load existing settings to avoid losing them
        existing = load_config()
        if existing and existing.get("settings"):
            settings = existing["settings"]
        else:
            settings = {
                "session_timeout": DEFAULT_SESSION_TIMEOUT,
                "totp_interval": DEFAULT_TOTP_INTERVAL,
                "lock_behavior": DEFAULT_LOCK_BEHAVIOR,
                "theme": DEFAULT_THEME
            }
    config = {
        "pin_hash": pin_hash,
        "totp_secret": totp_secret,
        "last_totp_step": last_totp_step,
        "backup_codes": backup_codes or [],
        "device_token_hash": device_token_hash,
        "device_token_expiry": device_token_expiry,
        "device_label": device_label,
        "last_login": last_login,
        "settings": settings
    }
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f)

def make_qr_pixmap(uri: str) -> QPixmap:
    img = qrcode.make(uri, box_size=8, border=2)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    pix = QPixmap()
    pix.loadFromData(buf.getvalue())
    return pix

# ---------------------------------------------------------------------
# PIN validation
# ---------------------------------------------------------------------
def is_sequential(pin: str) -> bool:
    if len(pin) < 3:
        return False
    for i in range(len(pin) - 2):
        a, b, c = int(pin[i]), int(pin[i+1]), int(pin[i+2])
        if (a + 1 == b and b + 1 == c) or (a - 1 == b and b - 1 == c):
            return True
    return False

def validate_pin(pin: str) -> tuple[bool, str]:
    if len(pin) < PIN_MIN_LENGTH:
        return False, f"PIN must be at least {PIN_MIN_LENGTH} characters."
    if PIN_ALLOW_NUMERIC_ONLY and not pin.isdigit():
        return False, "PIN must contain only digits (0-9)."
    if PIN_DISALLOW_SEQUENTIAL and is_sequential(pin):
        return False, "PIN cannot contain consecutive sequences (e.g., 123, 234, 765)."
    return True, ""

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
        config.get("settings")
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
            config.get("settings")
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

# Global theme access
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
        self.edit.setMinimumHeight(46)
        if max_len:
            self.edit.setMaxLength(max_len)
        if numeric:
            self.edit.setValidator(QRegExpValidator(QRegExp(r"^\d*$")))
        self.toggle_btn = QPushButton("SHOW")
        self.toggle_btn.setObjectName("toggleBtn")
        self.toggle_btn.setCursor(Qt.PointingHandCursor)
        self.toggle_btn.setFixedWidth(58)
        self.toggle_btn.setFixedHeight(46)
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
                border-top-left-radius: 10px;
                border-bottom-left-radius: 10px;
                border-right: none;
                padding: 0 14px;
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
                border-top-right-radius: 10px;
                border-bottom-right-radius: 10px;
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
                border-radius: 10px;
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
                border-radius: 10px;
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
        QPushButton:hover {{
            color: {colors["ACCENT"]};
        }}
        QPushButton:pressed {{
            color: {colors["ACCENT"]};
        }}
    """)
    return btn


class Card(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        self.setFixedWidth(460)
        colors = get_theme_colors()
        self.setStyleSheet(f"""
            #card {{
                background: {colors["BG_CARD"]};
                border: 1px solid {colors["BORDER"]};
                border-radius: 18px;
            }}
        """)
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(60)
        shadow.setOffset(0, 20)
        shadow.setColor(QColor(0, 0, 0, 160))
        self.setGraphicsEffect(shadow)
        self.layout_ = QVBoxLayout(self)
        self.layout_.setContentsMargins(38, 40, 38, 40)
        self.layout_.setSpacing(14)

    def add(self, widget, spacing_after=0):
        self.layout_.addWidget(widget)
        if spacing_after:
            self.layout_.addSpacing(spacing_after)


def title_label(text):
    colors = get_theme_colors()
    lbl = QLabel(text)
    lbl.setStyleSheet(f"color: {colors['TEXT_MAIN']}; font-size: 22px; font-weight: 800;")
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
    lbl.setFixedHeight(18)
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
        ), 20)
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
            f"Minimum {PIN_MIN_LENGTH} digits, numbers only, no repeated digits."
        ), 16)
        self.pin_field = PasswordField(placeholder="New PIN", numeric=True)
        self.confirm_field = PasswordField(placeholder="Confirm PIN", numeric=True)
        c.add(self.pin_field, 10)
        c.add(self.confirm_field, 6)
        self.err = error_label()
        c.add(self.err, 10)
        btn = make_button("Continue")
        btn.clicked.connect(lambda: on_continue(self.pin_field.text(), self.confirm_field.text()))
        c.add(btn)
        self.confirm_field.edit.returnPressed.connect(btn.click)

    def show_error(self, msg):
        self.err.setText(msg)
        self.pin_field.set_error(True)
        self.confirm_field.set_error(True)

    def clear_error(self):
        self.err.setText("")
        self.pin_field.set_error(False)
        self.confirm_field.set_error(False)


class SetupQRPage(BasePage):
    def __init__(self, on_done, parent=None):
        super().__init__(parent)
        c = self.card
        c.add(kicker_badge("STEP 2 OF 3"))
        c.add(title_label("Scan With Authenticator"), 2)
        c.add(subtitle_label("Open Google Authenticator (or any TOTP app) and scan this code."), 14)
        self.qr_label = QLabel()
        self.qr_label.setAlignment(Qt.AlignCenter)
        self.qr_label.setStyleSheet(f"background: white; border-radius: 10px; padding: 12px;")
        c.add(self.qr_label, 14)
        c.add(subtitle_label("Can't scan? Enter this key manually:"), 4)
        secret_row = QHBoxLayout()
        self.secret_box = QLabel("")
        self.secret_box.setAlignment(Qt.AlignCenter)
        colors = get_theme_colors()
        self.secret_box.setStyleSheet(f"""
            background: {colors['BG_FIELD']}; border: 1px solid {colors['BORDER']}; border-radius: 8px;
            color: {colors['ACCENT']}; font-size: 13px; font-family: Consolas, monospace;
            padding: 10px; letter-spacing: 1px;
        """)
        self.copy_btn = make_button("Copy", primary=False)
        self.copy_btn.setFixedWidth(70)
        self.copy_btn.clicked.connect(self._copy_secret)
        secret_row.addWidget(self.secret_box)
        secret_row.addWidget(self.copy_btn)
        c.layout_.addLayout(secret_row)
        c.layout_.addSpacing(18)
        btn = make_button("I've Saved It — Continue")
        btn.clicked.connect(on_done)
        c.add(btn)

    def set_data(self, uri, secret):
        self.qr_label.setPixmap(make_qr_pixmap(uri).scaled(
            220, 220, Qt.KeepAspectRatio, Qt.SmoothTransformation
        ))
        self.secret_box.setText(secret)
        self._secret = secret

    def _copy_secret(self):
        QApplication.clipboard().setText(self._secret)


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
            font-size: 28px;
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
            font-size: 26px; font-weight: 800; letter-spacing: 10px;
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
                border-radius: 8px;
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
        self._codes = []

    def set_codes(self, codes):
        self._codes = codes
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
            f"New PIN must be at least {PIN_MIN_LENGTH} digits, numbers only, no repeated digits."
        ), 16)
        self.current_pin_field = PasswordField(placeholder="Current PIN", numeric=True)
        self.new_pin_field = PasswordField(placeholder="New PIN", numeric=True)
        self.confirm_field = PasswordField(placeholder="Confirm New PIN", numeric=True)
        c.add(self.current_pin_field, 10)
        c.add(self.new_pin_field, 6)
        c.add(self.confirm_field, 6)
        self.err = error_label()
        c.add(self.err, 10)
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


class ResetPinPage(BasePage):
    def __init__(self, on_save, parent=None):
        super().__init__(parent)
        c = self.card
        c.add(kicker_badge("BACKUP VERIFIED"))
        c.add(title_label("Set A New PIN"), 2)
        c.add(subtitle_label(
            f"Minimum {PIN_MIN_LENGTH} digits, numbers only, no repeated digits."
        ), 16)
        self.pin_field = PasswordField(placeholder="New PIN", numeric=True)
        self.confirm_field = PasswordField(placeholder="Confirm New PIN", numeric=True)
        c.add(self.pin_field, 10)
        c.add(self.confirm_field, 6)
        self.err = error_label()
        c.add(self.err, 10)
        btn = make_button("Save New PIN & Continue")
        btn.clicked.connect(lambda: on_save(self.pin_field.text(), self.confirm_field.text()))
        c.add(btn)
        self.confirm_field.edit.returnPressed.connect(btn.click)

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
        self.qr_label.setStyleSheet(f"background: white; border-radius: 10px; padding: 12px;")
        c.add(self.qr_label, 14)
        c.add(subtitle_label("Can't scan? Enter this key manually:"), 4)
        secret_row = QHBoxLayout()
        self.secret_box = QLabel("")
        self.secret_box.setAlignment(Qt.AlignCenter)
        colors = get_theme_colors()
        self.secret_box.setStyleSheet(f"""
            background: {colors['BG_FIELD']}; border: 1px solid {colors['BORDER']}; border-radius: 8px;
            color: {colors['ACCENT']}; font-size: 13px; font-family: Consolas, monospace;
            padding: 10px; letter-spacing: 1px;
        """)
        self.copy_btn = make_button("Copy", primary=False)
        self.copy_btn.setFixedWidth(70)
        self.copy_btn.clicked.connect(self._copy_secret)
        secret_row.addWidget(self.secret_box)
        secret_row.addWidget(self.copy_btn)
        c.layout_.addLayout(secret_row)
        c.layout_.addSpacing(18)
        btn = make_button("Done — Continue")
        btn.clicked.connect(on_done)
        c.add(btn)

    def set_data(self, uri, secret):
        self.qr_label.setPixmap(make_qr_pixmap(uri).scaled(
            220, 220, Qt.KeepAspectRatio, Qt.SmoothTransformation
        ))
        self.secret_box.setText(secret)
        self._secret = secret

    def _copy_secret(self):
        QApplication.clipboard().setText(self._secret)


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
            border-radius: 8px;
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


class DashboardPage(BasePage):
    def __init__(self, on_lock, on_manage_backup, on_change_pin, on_reset_totp, on_reset_mfa,
                 on_forget_device, on_settings, parent=None):
        super().__init__(parent)
        c = self.card
        c.add(kicker_badge("SENTINEL MFA"))
        status_frame = QFrame()
        status_frame.setStyleSheet("background: transparent; border: none;")
        status_layout = QHBoxLayout(status_frame)
        status_layout.setContentsMargins(0, 0, 0, 0)
        status_layout.setSpacing(8)
        colors = get_theme_colors()
        dot = QLabel("●")
        dot.setStyleSheet(f"color: {colors['SUCCESS']}; font-size: 24px; font-weight: bold;")
        dot.setAlignment(Qt.AlignCenter)
        status_layout.addWidget(dot)
        status_text = QLabel("PROTECTED")
        status_text.setStyleSheet(f"color: {colors['TEXT_MAIN']}; font-size: 20px; font-weight: 800;")
        status_text.setAlignment(Qt.AlignCenter)
        status_layout.addWidget(status_text)
        c.add(status_frame, 4)
        grid = QGridLayout()
        grid.setVerticalSpacing(8)
        grid.setHorizontalSpacing(20)
        self.labels = {}
        grid.addWidget(QLabel("MFA Status"), 0, 0)
        self.labels["status"] = QLabel("ENABLED")
        self.labels["status"].setStyleSheet(f"color: {colors['SUCCESS']}; font-weight: 600;")
        grid.addWidget(self.labels["status"], 0, 1)
        grid.addWidget(QLabel("Authenticator"), 1, 0)
        self.labels["auth"] = QLabel("Google Authenticator")
        self.labels["auth"].setStyleSheet(f"color: {colors['TEXT_MAIN']};")
        grid.addWidget(self.labels["auth"], 1, 1)
        grid.addWidget(QLabel("Backup Codes"), 2, 0)
        self.labels["backup"] = QLabel("10 remaining")
        self.labels["backup"].setStyleSheet(f"color: {colors['TEXT_MAIN']};")
        grid.addWidget(self.labels["backup"], 2, 1)
        grid.addWidget(QLabel("Last Login"), 3, 0)
        self.labels["last_login"] = QLabel("Never")
        self.labels["last_login"].setStyleSheet(f"color: {colors['TEXT_MAIN']};")
        grid.addWidget(self.labels["last_login"], 3, 1)
        grid.addWidget(QLabel("Device"), 4, 0)
        self.labels["device"] = QLabel(socket.gethostname().upper())
        self.labels["device"].setStyleSheet(f"color: {colors['TEXT_MAIN']};")
        grid.addWidget(self.labels["device"], 4, 1)
        grid.addWidget(QLabel("Device Expiry"), 5, 0)
        self.labels["device_expiry"] = QLabel("Not set")
        self.labels["device_expiry"].setStyleSheet(f"color: {colors['TEXT_MAIN']};")
        grid.addWidget(self.labels["device_expiry"], 5, 1)
        for i in range(6):
            lbl = grid.itemAtPosition(i, 0).widget()
            lbl.setStyleSheet(f"color: {colors['TEXT_DIM']}; font-size: 13px; font-weight: 500;")
            grid.itemAtPosition(i, 1).widget().setStyleSheet(f"color: {colors['TEXT_MAIN']}; font-size: 13px;")
        c.layout_.addLayout(grid)
        c.layout_.addSpacing(10)
        self.lock_btn = make_button("Lock Now")
        self.lock_btn.clicked.connect(on_lock)
        c.add(self.lock_btn, 8)
        actions_layout = QHBoxLayout()
        actions_layout.setSpacing(6)
        manage_btn = make_button("Manage Codes", primary=False)
        manage_btn.setFixedHeight(36)
        manage_btn.clicked.connect(on_manage_backup)
        actions_layout.addWidget(manage_btn)
        change_pin_btn = make_button("Change PIN", primary=False)
        change_pin_btn.setFixedHeight(36)
        change_pin_btn.clicked.connect(on_change_pin)
        actions_layout.addWidget(change_pin_btn)
        reset_totp_btn = make_button("Reset TOTP", primary=False)
        reset_totp_btn.setFixedHeight(36)
        reset_totp_btn.clicked.connect(on_reset_totp)
        actions_layout.addWidget(reset_totp_btn)
        reset_mfa_btn = make_button("Reset MFA", primary=False)
        reset_mfa_btn.setFixedHeight(36)
        reset_mfa_btn.clicked.connect(on_reset_mfa)
        actions_layout.addWidget(reset_mfa_btn)
        forget_device_btn = make_button("Forget Device", primary=False)
        forget_device_btn.setFixedHeight(36)
        forget_device_btn.clicked.connect(on_forget_device)
        actions_layout.addWidget(forget_device_btn)
        settings_btn = make_button("Settings", primary=False)
        settings_btn.setFixedHeight(36)
        settings_btn.clicked.connect(on_settings)
        actions_layout.addWidget(settings_btn)
        c.layout_.addLayout(actions_layout)

    def update_data(self):
        config = load_config()
        if config is None:
            return
        colors = get_theme_colors()
        backup_codes = config.get("backup_codes", [])
        unused = sum(1 for bc in backup_codes if not bc.get("used", False))
        self.labels["backup"].setText(f"{unused} remaining")
        last_login_ts = config.get("last_login")
        if last_login_ts:
            dt = datetime.fromtimestamp(last_login_ts)
            self.labels["last_login"].setText(dt.strftime("%Y-%m-%d %H:%M"))
        else:
            self.labels["last_login"].setText("Never")
        device_label = config.get("device_label")
        device_expiry = config.get("device_token_expiry")
        if device_label:
            self.labels["device"].setText(device_label)
        else:
            self.labels["device"].setText("Not set")
        if device_expiry:
            dt = datetime.fromtimestamp(device_expiry)
            self.labels["device_expiry"].setText(dt.strftime("%Y-%m-%d %H:%M"))
        else:
            self.labels["device_expiry"].setText("Not set")


class SettingsPage(BasePage):
    def __init__(self, on_save, on_back, current_settings, parent=None):
        super().__init__(parent)
        c = self.card
        c.add(kicker_badge("SETTINGS"))
        c.add(title_label("Application Settings"), 2)

        # Session Timeout
        timeout_row = QHBoxLayout()
        timeout_row.addWidget(QLabel("Session Timeout (seconds):"))
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(30, 3600)
        self.timeout_spin.setSingleStep(30)
        self.timeout_spin.setValue(current_settings.get("session_timeout", DEFAULT_SESSION_TIMEOUT))
        self.timeout_spin.setStyleSheet(f"""
            background: {get_theme_colors()['BG_FIELD']};
            color: {get_theme_colors()['TEXT_MAIN']};
            border: 1px solid {get_theme_colors()['BORDER']};
            border-radius: 6px;
            padding: 4px;
        """)
        timeout_row.addWidget(self.timeout_spin)
        c.layout_.addLayout(timeout_row)

        # TOTP Interval
        interval_row = QHBoxLayout()
        interval_row.addWidget(QLabel("TOTP Interval (seconds):"))
        self.interval_spin = QSpinBox()
        self.interval_spin.setRange(15, 120)
        self.interval_spin.setSingleStep(5)
        self.interval_spin.setValue(current_settings.get("totp_interval", DEFAULT_TOTP_INTERVAL))
        self.interval_spin.setStyleSheet(f"""
            background: {get_theme_colors()['BG_FIELD']};
            color: {get_theme_colors()['TEXT_MAIN']};
            border: 1px solid {get_theme_colors()['BORDER']};
            border-radius: 6px;
            padding: 4px;
        """)
        interval_row.addWidget(self.interval_spin)
        c.layout_.addLayout(interval_row)

        # Lock Behavior
        lock_row = QHBoxLayout()
        lock_row.addWidget(QLabel("Lock Behavior:"))
        self.lock_combo = QComboBox()
        self.lock_combo.addItems(["full_screen", "windowed", "standard"])
        self.lock_combo.setCurrentText(current_settings.get("lock_behavior", DEFAULT_LOCK_BEHAVIOR))
        self.lock_combo.setStyleSheet(f"""
            background: {get_theme_colors()['BG_FIELD']};
            color: {get_theme_colors()['TEXT_MAIN']};
            border: 1px solid {get_theme_colors()['BORDER']};
            border-radius: 6px;
            padding: 4px;
        """)
        lock_row.addWidget(self.lock_combo)
        c.layout_.addLayout(lock_row)

        # Theme
        theme_row = QHBoxLayout()
        theme_row.addWidget(QLabel("Theme:"))
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["dark", "light"])
        self.theme_combo.setCurrentText(current_settings.get("theme", DEFAULT_THEME))
        self.theme_combo.setStyleSheet(f"""
            background: {get_theme_colors()['BG_FIELD']};
            color: {get_theme_colors()['TEXT_MAIN']};
            border: 1px solid {get_theme_colors()['BORDER']};
            border-radius: 6px;
            padding: 4px;
        """)
        theme_row.addWidget(self.theme_combo)
        c.layout_.addLayout(theme_row)

        c.layout_.addSpacing(10)
        self.err = error_label()
        c.add(self.err, 8)

        save_btn = make_button("Save Settings")
        save_btn.clicked.connect(lambda: on_save(
            self.timeout_spin.value(),
            self.interval_spin.value(),
            self.lock_combo.currentText(),
            self.theme_combo.currentText()
        ))
        c.add(save_btn, 8)

        back_btn = make_button("← Back", primary=False)
        back_btn.clicked.connect(on_back)
        c.add(back_btn)


# =====================================================================
# MAIN APPLICATION WINDOW
# =====================================================================

class SentinelMFA(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Sentinel MFA — Secure Access")
        self.resize(560, 720)
        self.setMinimumSize(480, 640)
        self._authenticated = False
        self._is_locked = False
        self.setWindowFlags(
            Qt.Window |
            Qt.FramelessWindowHint |
            Qt.WindowStaysOnTopHint
        )
        self._pending_secret = None
        self._pending_pin_hash = None
        self._forgot_flow = False
        self._pin_attempts = 0
        self._lockout_count = 0
        self._totp_attempts = 0
        self._backup_attempts = 0
        self._backup_lockout_count = 0

        # Load config and settings
        config = load_config()
        if config is None:
            self.settings = {
                "session_timeout": DEFAULT_SESSION_TIMEOUT,
                "totp_interval": DEFAULT_TOTP_INTERVAL,
                "lock_behavior": DEFAULT_LOCK_BEHAVIOR,
                "theme": DEFAULT_THEME
            }
        else:
            self.settings = config.get("settings", {
                "session_timeout": DEFAULT_SESSION_TIMEOUT,
                "totp_interval": DEFAULT_TOTP_INTERVAL,
                "lock_behavior": DEFAULT_LOCK_BEHAVIOR,
                "theme": DEFAULT_THEME
            })

        self.session_timeout = self.settings.get("session_timeout", DEFAULT_SESSION_TIMEOUT)
        self.totp_interval = self.settings.get("totp_interval", DEFAULT_TOTP_INTERVAL)
        self.lock_behavior = self.settings.get("lock_behavior", DEFAULT_LOCK_BEHAVIOR)
        self.theme = self.settings.get("theme", DEFAULT_THEME)

        # Apply theme globally
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

        # --- build pages ---
        self.welcome_page = WelcomePage(self.go_setup_pin)
        self.setup_pin_page = SetupPinPage(self.handle_setup_pin)
        self.setup_qr_page = SetupQRPage(self.handle_setup_done)
        self.lock_page = LockPage(
            self.handle_unlock_pin,
            self.handle_forgot_pin,
            self.handle_remembered_device
        )
        self.totp_page = TotpPage(
            self.handle_totp_verify,
            self.handle_totp_back,
            self.handle_use_backup_code,
            show_back=False,
            totp_interval=self.totp_interval
        )
        self.backup_entry_page = BackupCodeEntryPage(
            self.handle_backup_verify,
            self.handle_totp_back
        )
        self.reset_pin_page = ResetPinPage(self.handle_reset_pin)
        self.remember_device_page = RememberDevicePage(self.handle_remember_device_choice)
        self.dashboard_page = DashboardPage(
            self.handle_lock_session,
            self.handle_manage_backup_codes,
            self.handle_change_pin,
            self.handle_reset_totp,
            self.handle_reset_mfa,
            self.handle_forget_device,
            self.handle_settings
        )
        self.manage_backup_page = ManageBackupCodesPage(
            self.handle_generate_backup_codes,
            self.handle_back_to_dashboard
        )
        self.change_pin_page = ChangePinPage(
            self.handle_change_pin_save,
            self.handle_back_to_dashboard
        )
        self.reset_totp_page = ResetTotpPage(
            self.handle_reset_totp_done
        )
        self.settings_page = SettingsPage(
            self.handle_settings_save,
            self.handle_back_to_dashboard,
            self.settings
        )

        for p in [self.welcome_page, self.setup_pin_page, self.setup_qr_page,
                  self.lock_page, self.totp_page, self.backup_entry_page,
                  self.reset_pin_page, self.remember_device_page, self.dashboard_page,
                  self.manage_backup_page, self.change_pin_page, self.reset_totp_page,
                  self.settings_page]:
            self.stack.addWidget(p)

        self.start()

    # ---------- Theme handling ----------
    def _apply_theme(self):
        global _current_theme
        _current_theme = self.theme
        colors = get_theme_colors()
        self.setStyleSheet(f"background: {colors['BG_ROOT']};")
        # Force a repaint of all widgets
        QApplication.instance().setStyleSheet("")

    # ---------- Lock mode management ----------
    def _enter_lock_mode(self):
        self._is_locked = True
        self._authenticated = False

        if self.lock_behavior == "full_screen":
            hide_taskbar()
            hide_desktop_icons()
            block_system_keys()
            self.setWindowFlags(
                Qt.Window |
                Qt.FramelessWindowHint |
                Qt.WindowStaysOnTopHint
            )
            self.showFullScreen()
        elif self.lock_behavior == "windowed":
            hide_taskbar()
            hide_desktop_icons()
            block_system_keys()
            self.setWindowFlags(
                Qt.Window |
                Qt.FramelessWindowHint |
                Qt.WindowStaysOnTopHint
            )
            self.showMaximized()
        else:  # standard
            # No blocking, just show normal window
            self.setWindowFlags(
                Qt.Window |
                Qt.WindowTitleHint |
                Qt.WindowCloseButtonHint
            )
            self.showNormal()

        config = load_config()
        if config:
            self._active_secret = config["totp_secret"]
            self._active_config = config
            self.totp_page.set_mode(
                "AUTHENTICATE",
                "Enter Authenticator Code",
                "Enter the 6‑digit code from your Authenticator app."
            )
            self.totp_page.reset()
            self._goto(self.totp_page)
        else:
            self._goto(self.welcome_page)

    def _exit_lock_mode(self):
        self._is_locked = False
        self._authenticated = True

        if self.lock_behavior in ("full_screen", "windowed"):
            show_taskbar()
            show_desktop_icons()
            unblock_system_keys()

        self.setWindowFlags(
            Qt.Window |
            Qt.WindowTitleHint |
            Qt.WindowCloseButtonHint
        )
        self.showNormal()

    # ---------- Navigation ----------
    def _goto(self, widget):
        self.stack.setCurrentWidget(widget)
        if widget == self.dashboard_page or widget == self.manage_backup_page or \
           widget == self.change_pin_page or widget == self.reset_totp_page or \
           widget == self.settings_page:
            self._start_session_timer()
        else:
            self._stop_session_timer()
        if widget == self.dashboard_page:
            self.dashboard_page.update_data()

    # ---------- Session timeout ----------
    def _start_session_timer(self):
        self._session_timer.start(self.session_timeout * 1000)

    def _stop_session_timer(self):
        self._session_timer.stop()

    def _reset_session_timer(self):
        if self._session_timer.isActive():
            self._session_timer.start(self.session_timeout * 1000)

    def _on_session_timeout(self):
        current = self.stack.currentWidget()
        if current == self.lock_page or current == self.welcome_page:
            return
        self.handle_lock_session()
        QMessageBox.information(self, "Session Expired", "Your session has timed out due to inactivity.")

    # ---------- Event overrides ----------
    def mousePressEvent(self, event):
        self._reset_session_timer()
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        self._reset_session_timer()
        super().mouseReleaseEvent(event)

    def mouseMoveEvent(self, event):
        self._reset_session_timer()
        super().mouseMoveEvent(event)

    def keyPressEvent(self, event):
        self._reset_session_timer()
        super().keyPressEvent(event)

    def keyReleaseEvent(self, event):
        self._reset_session_timer()
        super().keyReleaseEvent(event)

    def closeEvent(self, event):
        if self._authenticated:
            event.accept()
        else:
            event.ignore()

    # ---------- Device token ----------
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

    # ---------- Start ----------
    def start(self):
        self._enter_lock_mode()

    # ---------- Setup handlers ----------
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
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name=APP_LABEL, issuer_name=ISSUER)
        self._pending_pin_hash = hash_pin(pin)
        self._pending_secret = secret
        save_config(self._pending_pin_hash, self._pending_secret, None, [], settings=self.settings)
        self.setup_qr_page.set_data(uri, secret)
        self.setup_pin_page.pin_field.clear()
        self.setup_pin_page.confirm_field.clear()
        self._goto(self.setup_qr_page)

    def handle_setup_done(self):
        self._authenticated = False
        self._enter_lock_mode()

    # ---------- PIN unlock ----------
    def handle_unlock_pin(self, pin):
        if self.lock_page.is_locked_out():
            return
        config = load_config()
        if config is None:
            QMessageBox.warning(self, "No Setup Found", "No MFA configuration found. Please set up first.")
            self._goto(self.welcome_page)
            return
        if not pin:
            self.lock_page.show_error("Please enter your PIN.")
            return
        if hash_pin(pin) == config["pin_hash"]:
            self._forgot_flow = False
            self._active_secret = config["totp_secret"]
            self._active_config = config
            self.lock_page.reset()
            self._pin_attempts = 0
            self._lockout_count = 0
            self.totp_page.set_mode(
                "STEP 2 OF 2",
                "Enter Authenticator Code",
                "PIN correct. Now enter the 6-digit code from your Authenticator app."
            )
            self.totp_page.reset()
            self._totp_attempts = 0
            self._goto(self.totp_page)
        else:
            self._pin_attempts += 1
            msg = f"Incorrect PIN. Attempt {self._pin_attempts}/{MAX_PIN_ATTEMPTS}."
            if self._pin_attempts >= MAX_PIN_ATTEMPTS:
                self._lockout_count += 1
                idx = min(self._lockout_count - 1, len(PIN_LOCKOUT_DURATIONS) - 1)
                duration = PIN_LOCKOUT_DURATIONS[idx]
                self.lock_page.start_lockout(duration)
                self.lock_page.show_error(f"Too many failed attempts. Locked out for {duration} seconds.")
                self._pin_attempts = 0
            else:
                self.lock_page.show_error(msg)

    def handle_forgot_pin(self):
        pass

    def handle_totp_back(self):
        self._enter_lock_mode()

    # ---------- Backup code flow ----------
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
            QMessageBox.warning(self, "No Setup Found", "No MFA configuration found. Please set up first.")
            self._goto(self.welcome_page)
            return
        backup_codes = config.get("backup_codes", [])
        input_hash = hash_backup_code(code)
        for bc in backup_codes:
            if bc["hash"] == input_hash and not bc["used"]:
                bc["used"] = True
                save_config(
                    config["pin_hash"],
                    config["totp_secret"],
                    config["last_totp_step"],
                    backup_codes,
                    last_login=int(time.time()),
                    settings=self.settings
                )
                self._active_config = load_config()
                self._pin_attempts = 0
                self._lockout_count = 0
                self._totp_attempts = 0
                self._backup_attempts = 0
                self._backup_lockout_count = 0
                self._forgot_flow = False
                self._exit_lock_mode()
                self._goto(self.remember_device_page)
                return
        self._backup_attempts += 1
        msg = f"Invalid or already used backup code. Attempt {self._backup_attempts}/{MAX_BACKUP_ATTEMPTS}."
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
            self.backup_entry_page.show_error(msg)

    # ---------- TOTP verification ----------
    def handle_totp_verify(self, code):
        if self.totp_page.is_totp_locked_out():
            return
        if not code or len(code) != 6:
            self.totp_page.show_error("Enter the 6-digit code.")
            return
        totp = pyotp.TOTP(self._active_secret)
        if not totp.verify(code):
            self._totp_attempts += 1
            msg = f"Incorrect TOTP code. Attempt {self._totp_attempts}/{MAX_TOTP_ATTEMPTS}."
            if self._totp_attempts >= MAX_TOTP_ATTEMPTS:
                self.totp_page.start_totp_lockout(TOTP_LOCKOUT_DURATION)
                self.totp_page.show_error(f"Too many failed TOTP attempts. Locked out for {TOTP_LOCKOUT_DURATION} seconds.")
                self._totp_attempts = 0
            else:
                self.totp_page.show_error(msg)
            return
        current_step = int(time.time()) // self.totp_interval
        last_step = self._active_config.get("last_totp_step")
        if last_step is not None and current_step <= last_step:
            self.totp_page.show_error("This code has already been used. Please wait for a new one.")
            return
        save_config(
            self._active_config["pin_hash"],
            self._active_config["totp_secret"],
            current_step,
            self._active_config.get("backup_codes", []),
            last_login=int(time.time()),
            settings=self.settings
        )
        self._active_config["last_totp_step"] = current_step
        self._totp_attempts = 0
        self._exit_lock_mode()
        self._goto(self.remember_device_page)

    # ---------- Remember device ----------
    def handle_remember_device_choice(self, remember: bool, label: str):
        if remember:
            token, _, expiry, label = generate_device_token(label)
            save_device_token(token, expiry, label)
            self._active_config = load_config()
        self._goto(self.dashboard_page)

    # ---------- Reset PIN (from backup flow) ----------
    def handle_reset_pin(self, pin, confirm):
        self.reset_pin_page.clear_error()
        valid, msg = validate_pin(pin)
        if not valid:
            self.reset_pin_page.show_error(msg)
            return
        if pin != confirm:
            self.reset_pin_page.show_error("PINs do not match.")
            return
        save_config(
            hash_pin(pin),
            self._active_secret,
            self._active_config["last_totp_step"],
            self._active_config.get("backup_codes", []),
            settings=self.settings
        )
        self.reset_pin_page.pin_field.clear()
        self.reset_pin_page.confirm_field.clear()
        QMessageBox.information(self, "PIN Updated", "Your PIN was updated successfully.")
        self._goto(self.remember_device_page)

    # ---------- Lock session ----------
    def handle_lock_session(self):
        self._stop_session_timer()
        self._pin_attempts = 0
        self._lockout_count = 0
        self._totp_attempts = 0
        self._backup_attempts = 0
        self._backup_lockout_count = 0
        self._enter_lock_mode()

    # ---------- Remembered device ----------
    def handle_remembered_device(self):
        if self._check_device_token_and_authenticate():
            return
        self.lock_page.set_device_btn_visible(False)
        self.lock_page.show_error("Remembered device token is invalid or expired.")

    # ---------- Forget device ----------
    def handle_forget_device(self):
        clear_device_token()
        self._active_config = load_config()
        QMessageBox.information(self, "Device Forgotten", "This device will no longer be remembered.")
        self.dashboard_page.update_data()

    # ---------- Manage backup codes ----------
    def handle_manage_backup_codes(self):
        config = load_config()
        if config is None:
            QMessageBox.warning(self, "No Setup Found", "No MFA configuration found.")
            return
        backup_codes = config.get("backup_codes", [])
        self.manage_backup_page.set_codes(backup_codes)
        self._goto(self.manage_backup_page)

    def handle_generate_backup_codes(self):
        config = load_config()
        if config is None:
            QMessageBox.warning(self, "No Setup Found", "No MFA configuration found.")
            return
        plain_codes = generate_backup_codes()
        hashed_codes = [{"hash": hash_backup_code(c), "used": False} for c in plain_codes]
        save_config(
            config["pin_hash"],
            config["totp_secret"],
            config["last_totp_step"],
            hashed_codes,
            last_login=config.get("last_login"),
            settings=self.settings
        )
        self._active_config = load_config()
        code_list = "\n".join(f"{i+1}. {c}" for i, c in enumerate(plain_codes))
        QMessageBox.information(
            self,
            "New Backup Codes",
            f"Your new backup codes are:\n\n{code_list}\n\n"
            "Write them down and keep them safe. "
            "These are the only times you will see them."
        )
        self.manage_backup_page.set_codes(hashed_codes)
        self.manage_backup_page.show_error("")
        self.dashboard_page.update_data()

    def handle_back_to_dashboard(self):
        self._goto(self.dashboard_page)

    # ---------- Change PIN ----------
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
        if hash_pin(current_pin) != config["pin_hash"]:
            self.change_pin_page.show_error("Current PIN is incorrect.")
            return
        valid, msg = validate_pin(new_pin)
        if not valid:
            self.change_pin_page.show_error(msg)
            return
        if new_pin != confirm:
            self.change_pin_page.show_error("New PINs do not match.")
            return
        save_config(
            hash_pin(new_pin),
            config["totp_secret"],
            config["last_totp_step"],
            config.get("backup_codes", []),
            last_login=config.get("last_login"),
            settings=self.settings
        )
        self._active_config = load_config()
        self.change_pin_page.reset()
        QMessageBox.information(self, "PIN Changed", "Your PIN has been changed successfully.")
        self._goto(self.dashboard_page)

    # ---------- Reset TOTP ----------
    def handle_reset_totp(self):
        config = load_config()
        if config is None:
            QMessageBox.warning(self, "No Setup Found", "No MFA configuration found.")
            self._goto(self.welcome_page)
            return
        new_secret = pyotp.random_base32()
        totp = pyotp.TOTP(new_secret)
        uri = totp.provisioning_uri(name=APP_LABEL, issuer_name=ISSUER)
        save_config(
            config["pin_hash"],
            new_secret,
            None,
            config.get("backup_codes", []),
            last_login=config.get("last_login"),
            settings=self.settings
        )
        self._active_config = load_config()
        self._active_secret = new_secret
        self.reset_totp_page.set_data(uri, new_secret)
        self._goto(self.reset_totp_page)

    def handle_reset_totp_done(self):
        self._goto(self.dashboard_page)

    # ---------- Settings ----------
    def handle_settings(self):
        self.settings_page.timeout_spin.setValue(self.session_timeout)
        self.settings_page.interval_spin.setValue(self.totp_interval)
        self.settings_page.lock_combo.setCurrentText(self.lock_behavior)
        self.settings_page.theme_combo.setCurrentText(self.theme)
        self.settings_page.err.setText("")
        self._goto(self.settings_page)

    def handle_settings_save(self, timeout, interval, lock_behavior, theme):
        # Update settings
        self.session_timeout = timeout
        self.totp_interval = interval
        self.lock_behavior = lock_behavior
        self.theme = theme

        # Save to config
        config = load_config()
        if config is None:
            QMessageBox.warning(self, "No Config", "No MFA configuration found. Cannot save settings.")
            return

        self.settings = {
            "session_timeout": timeout,
            "totp_interval": interval,
            "lock_behavior": lock_behavior,
            "theme": theme
        }

        save_config(
            config["pin_hash"],
            config["totp_secret"],
            config["last_totp_step"],
            config["backup_codes"],
            config.get("device_token_hash"),
            config.get("device_token_expiry"),
            config.get("device_label"),
            config.get("last_login"),
            settings=self.settings
        )

        # Apply live changes
        self.totp_page.update_interval(interval)
        if self._session_timer.isActive():
            self._start_session_timer()

        # Apply theme (requires restart for full effect)
        if self.theme != _current_theme:
            reply = QMessageBox.question(
                self,
                "Theme Changed",
                "Theme changes require an application restart to take full effect. Restart now?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                # Restart the application
                QApplication.quit()
                os.execl(sys.executable, sys.executable, *sys.argv)

        QMessageBox.information(self, "Settings Saved", "Settings have been saved successfully.")
        self._goto(self.dashboard_page)

    # ---------- Complete MFA Reset ----------
    def handle_reset_mfa(self):
        reply = QMessageBox.question(
            self, "Reset MFA?",
            "This will permanently delete all your MFA credentials (PIN, TOTP secret, backup codes) and cannot be undone.\n\n"
            "You will need to set up your MFA again from scratch.\n\n"
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
        self._forgot_flow = False
        self._pin_attempts = 0
        self._lockout_count = 0
        self._totp_attempts = 0
        self._backup_attempts = 0
        self._backup_lockout_count = 0
        self._active_config = None
        self._active_secret = None
        self._stop_session_timer()
        QMessageBox.information(self, "MFA Reset", "All credentials have been erased. You will now be redirected to the setup page.")
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