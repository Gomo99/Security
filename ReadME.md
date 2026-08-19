Sentinel MFA — Secure Access Console
A modern, full-featured multi-factor authentication (MFA) lock screen for Windows.
It runs after Windows login and requires a TOTP code (from Google Authenticator or similar) or a backup code before the desktop becomes usable.

Table of Contents
Overview

Features

Requirements

Installation

Usage

First-time Setup

Unlocking the Desktop

Security Dashboard

Settings

Configuration File

Security Notes

Troubleshooting

Customization

License

Overview
Sentinel MFA is designed to add an extra layer of protection to your Windows workstation. After you log in with your Windows credentials, this application takes over the screen, hides the taskbar and desktop icons, and blocks common system shortcuts. You must enter a valid 6‑digit TOTP code from your authenticator app (or a backup recovery code) to unlock the desktop.

The application also provides a security dashboard for managing backup codes, changing your PIN, resetting TOTP, remembering devices, and adjusting settings.

Features
Full‑screen lock screen – hides taskbar and desktop icons, blocks Alt+Tab, Win+D, Win+E, Win+R, and more.

TOTP authentication – uses time‑based one‑time passwords (30‑second intervals by default).

Backup recovery codes – 10 one‑time use codes (configurable).

PIN protection – optional PIN used as first factor (can be skipped if you only want TOTP).

Escalating lockout – after repeated failed attempts for PIN, TOTP, or backup codes.

Device remembering – skip authentication on a trusted device for a configurable number of days.

Security dashboard – shows session info, device trust status, backup code health, and recent security events.

Settings page – customize session timeout, TOTP interval, lock behavior, theme, backup code settings, and more.

Modern UI – dark/light themes, rounded cards, shadows, PIN strength meter, live clock.

PBKDF2 PIN hashing – strong key derivation for PIN storage (with legacy SHA‑256 fallback for old configs).

Requirements
Windows 10 or 11 (recommended)
(The lockdown features are Windows‑specific and require ctypes access to user32.dll.)

Python 3.8 or later

PyQt5

pyotp

qrcode[pil]

Installation
Clone or download this repository.

Install the required packages:

bash
pip install PyQt5 pyotp "qrcode[pil]"
Ensure you have Python in your PATH.

Usage
First-time Setup
Run the application:

bash
python sentinel_mfa.py
If no configuration is found, you'll see the Welcome screen. Click "Set Up MFA".

Create a PIN (if you want to use PIN as first factor).

The strength meter will give real‑time feedback.

Avoid common patterns, sequences, repeated digits, and keyboard patterns.

If you prefer to skip the PIN and rely solely on TOTP, you can still proceed — the PIN will not be required during unlock if you modify the flow (see Customization).

Scan the QR code with Google Authenticator, Microsoft Authenticator, Authy, or any TOTP app.

The secret key is also displayed for manual entry.

Enter the 6‑digit code shown in your authenticator app to verify setup.

After successful verification, the lock screen will appear again. Now enter the PIN (if configured) and then the TOTP code to unlock.

Unlocking the Desktop
The application starts in lock mode (full‑screen by default).

If a PIN was configured, you must first enter it.

Then enter the 6‑digit TOTP code from your authenticator app.

You can also use a backup code by clicking the link on the TOTP page.

On successful authentication, you will see the Remember Device page.

You can choose to remember this device for future logins (skips MFA for the configured number of days).

After that, the main Security Dashboard appears, and the desktop is fully usable.

Security Dashboard
The dashboard provides:

Security Status – MFA enabled, last authentication, current session duration.

Device Information – name, remembered status, token expiry, token age.

Recovery – backup code health (used/unused) and last regeneration time.

Security Events – timestamps of last failed PIN/TOTP/backup attempts, failed attempts today, last successful login.

Actions – lock now, manage backup codes, change PIN, reset TOTP, reset MFA, forget device, open settings.

Settings
From the dashboard, click Settings to adjust:

General – theme (dark/light), language, notifications.

Authentication – session timeout, TOTP interval, PIN policy, lock behavior.

Devices – remembered device duration, device naming, automatic revocation.

Security – failed‑attempt policy, security logging, clipboard clearing, auto‑lock.

Recovery – backup code count, backup code length, recovery policy.

Configuration File
The application stores its configuration in mfa_config.json (created automatically). It contains:

pin_hash – PBKDF2‑hashed PIN (or legacy SHA‑256).

pin_salt – salt used for PBKDF2 (if present).

totp_secret – base32 secret for TOTP.

backup_codes – list of hashed backup codes with used flags.

device_token_hash and device_token_expiry – for trusted device.

last_totp_step – anti‑replay protection.

last_login, failed_attempts_* – security event data.

settings – all user‑customizable settings.

The device token itself is stored in device_token.txt (plaintext). The hash is kept in the config.

Important: The configuration file and device token are stored in the same directory as the script. For better security, consider moving them to a restricted location (e.g., %APPDATA% with proper permissions).

Security Notes
This is not a Windows Credential Provider. It runs after Windows logon and can be bypassed by restarting into Safe Mode or using a live USB. For true pre‑login MFA, a dedicated credential provider is required.

The hotkey blocking is implemented via RegisterHotKey. Some system shortcuts (e.g., Ctrl+Alt+Del, Win+L) cannot be fully blocked without Group Policy or registry changes.

The PIN is hashed using PBKDF2‑HMAC‑SHA256 with 200,000 iterations and a random salt. Legacy SHA‑256 is only used for backward compatibility when no salt exists.

The TOTP secret is stored in plaintext inside mfa_config.json. An attacker with file access could read it and generate codes. For stronger protection, consider encrypting the config or using Windows DPAPI.

The device token is also stored in plaintext. Combine with the config hash to impersonate a trusted device. Consider encrypting both.

Do not rely solely on this application to protect highly sensitive data. It is an additional layer, not a replacement for full‑disk encryption or a secure Windows login.

Troubleshooting
Application doesn't start full‑screen
Make sure you are running it with normal user privileges (admin rights may be needed to hide taskbar/desktop icons). Check the lock_behavior setting in the config.

Alt+Tab still works
The hotkey registration may fail if another application has already registered the same hotkey. Try closing other applications that use global hotkeys (e.g., screenshot tools, launchers).

Desktop icons are still visible
Hiding Progman may not work on all Windows versions. You may need to use a different method, such as toggling the “Show desktop icons” registry setting.

TOTP codes are rejected
Ensure your system clock is accurate. TOTP is time‑sensitive. Also check that the totp_interval setting matches your authenticator app (default is 30 seconds).

Backup codes not working
Make sure you are entering the code exactly as shown, including uppercase letters. Codes are one‑time use.

Application crashes on startup
Check that all dependencies are installed (pip install PyQt5 pyotp "qrcode[pil]"). If a NameError or ImportError appears, ensure you are using the correct Python version.

Customization
You can change default settings by editing DEFAULT_SETTINGS in the code, or use the Settings page after unlocking.

To skip the PIN step entirely and require only TOTP, modify the start() method in the SentinelMFA class to call _enter_lock_mode() and then directly navigate to self.totp_page instead of self.lock_page. You may also remove or ignore the PIN fields.

Themes are defined in the THEMES dictionary. You can add new themes by adding entries with the same color keys.

License
This project is provided for educational and personal use. You may modify and distribute it freely.

Enjoy your enhanced Windows security!