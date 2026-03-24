# CipherLink Setup Guide

## Android APK Installation

### 1. Download
- Download the latest APK from [GitHub Releases](https://github.com/BEKO2210/cipherlink/releases/latest)
- Or visit [beko2210.github.io/cipherlink](https://beko2210.github.io/cipherlink/) and click **Download APK**

### 2. Install on your device
1. Transfer the `.apk` file to your Android device (USB, email, cloud storage)
2. Open the file on your device
3. If prompted, enable **"Install from unknown sources"** for your file manager:
   - Go to **Settings > Apps > Special app access > Install unknown apps**
   - Select the app you're using to open the APK (e.g. Files, Chrome)
   - Toggle **"Allow from this source"**
4. Tap **Install**

### 3. First launch
1. Open CipherLink
2. The app generates your encryption identity automatically (takes a few seconds)
3. You're ready to chat!

## Server Setup (Required for messaging)

CipherLink needs a relay server to exchange encrypted messages. The server is **zero-knowledge** — it never sees your plaintext or keys.

### Option A: Use the built-in server (local/LAN)
```bash
# Clone the repository
git clone https://github.com/BEKO2210/cipherlink.git
cd cipherlink

# Install dependencies
pnpm install

# Start the relay server
pnpm dev:server
```
The server starts on `ws://localhost:4200`. For LAN access, use your computer's IP address (e.g. `ws://192.168.1.100:4200`).

### Option B: Deploy your own server (recommended for production)
```bash
cd apps/server
pnpm install
pnpm build
NODE_ENV=production node dist/index.js
```
Use a reverse proxy (nginx, Caddy) with TLS for `wss://` connections.

## App Configuration

### Connect to your server
1. Open CipherLink > **Settings** tab (gear icon)
2. Enter your server URL:
   - Local: `ws://192.168.1.100:4200`
   - Production: `wss://your-server.example.com`
3. Tap **Save**

### Start a chat
1. Go to **Messages** tab
2. Tap **New Chat** (+)
3. Enter your contact's **Display Name** and **Public Key**
4. Your contact's public key is shown in their **Settings** screen — they can copy it to share with you

### Verify encryption
1. Open a chat
2. Tap the encryption badge at the top
3. Compare the **60-digit safety number** with your contact (in person or via a trusted channel)
4. Matching numbers = verified end-to-end encryption

### Create a backup
1. Go to **Settings** > **Backup**
2. Choose a strong passphrase (12+ characters recommended)
3. Save the backup data and recovery codes in a safe place
4. You'll need the passphrase OR 2-of-3 recovery codes to restore

## Requirements
- Android 7.0 (API 24) or higher
- ~50 MB storage
- Internet connection for messaging

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "Not Connected" when sending | Check server URL in Settings. Make sure your server is running. |
| Can't install APK | Enable "Install from unknown sources" for your file manager |
| App crashes on launch | Clear app data: Settings > Apps > CipherLink > Clear Data |
| Messages not arriving | Both users must be connected to the same server |
| Safety numbers don't match | One of you may have reinstalled. Re-verify keys in person. |
