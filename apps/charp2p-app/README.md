# CharP2P application

Adaptive Tauri 2 client shell for Windows and Android.

```powershell
pnpm install
pnpm dev
pnpm build
pnpm tauri dev
```

The current shell implements the three-step device onboarding flow. Identity
creation and restart detection use Rust commands and platform-protected storage;
encrypted recovery export remains a later increment.
