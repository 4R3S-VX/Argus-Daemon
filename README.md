# Ἄργος: The Argus Daemon
> "The hundred-eyed giant who sees absolutely everything."

**Argus Daemon** is a lightweight Python-based heuristic scanner designed to detect **Fileless Malware** and **Living Off The Land (LotL)** attacks that bypass traditional signature-based AVs.

### 🛠️ Detection Logic
Argus doesn't look for "bad files." It looks for **bad behavior**:
1.  **Orphaned Memory:** Flags processes that have no corresponding executable on the disk (common in reflective DLL injection).
2.  **Networked Shells:** Flags native system tools (PowerShell, CMD) that have established active outbound network connections.

### 🚀 Usage
**Installation:**
```bash
pip install psutil colorama
Standard Scan:

Bash
python argus_daemon.py
Active Neutralization:

Bash
python argus_daemon.py --purge

---

## 3. The Technical Breakdown

### The "Ghost" Detection
In a standard OS environment, every process should map back to a binary file on the storage drive. When malware uses **Reflective Loading**, it injects code directly into RAM. The OS sees the process running, but `proc.exe()` returns `None` or points to a path that no longer exists. This is a massive red flag.

### The "LotL" Logic
Attackers use `powershell.exe` because it’s trusted. However, a developer’s local PowerShell rarely needs an active TCP connection to an external IP unless it's downloading a payload or exfiltrating data. By checking `proc.connections()`, Argus identifies these high-risk outliers instantly.