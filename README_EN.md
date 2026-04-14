# DragonCode Sandbox (Python) — Project Documentation (English)

This repository contains the **Python port** of *DragonCode Sandbox*, originally written in Rust. The goal is to preserve the same high-level architecture (modules/interfaces) while providing a runnable Python implementation.

Run the simulation entrypoint:

```bash
python -m dragoncode_sandbox
```

## Overview

DragonCode Sandbox is a sandbox simulation / analysis framework that collects signals from multiple engines (Static/Dynamic/Memory/Network/Policy) and turns them into a final **Verdict** (risk score + threat level + explanation).

Important note: parts of “real isolation” and low-level Windows features are implemented as **stubs/mocks or simplified implementations** in Python to preserve the project flow. A production-grade sandbox requires deeper OS integration.

## Requirements

- **Python**: recommended Python 3.11+ (tested on 3.12).
- **OS**: Windows is preferred because the memory scanner uses Windows APIs via `ctypes`. The project can still run on other OSes, but some features will be disabled/simplified.

## Setup & Run

### 1) Create a virtual environment

```bash
python -m venv .venv
```

On Windows:

```powershell
.\.venv\Scripts\Activate.ps1
```

### 2) Install dependencies

```bash
pip install -r requirements.txt
```

### 3) Run

```bash
python -m dragoncode_sandbox
```

The entrypoint follows a flow similar to the original Rust `main.rs`: it creates a `SandboxContext`, logs dynamic events, calculates the Verdict, and prints an analysis report.

## Project Layout

The Python package lives under:

```text
dragoncode_sandbox/
  __main__.py
  bridge.py
  analysis/
  core/
  deception/
  defense/
  disk/
  governance/
  intelligence/
  registry/
```

## Modules

### 1) Core

- **`core/context.py`**
  - `SandboxContext`: holds `sample_hash`, `IsolationLevel`, verdict state, and a thread-safe shared memory dictionary.
- **`core/isolation.py`**
  - `SandboxIsolation`: isolation/execution interface (simplified) inspired by the Rust Job Object / restricted token model.
- **`core/lifecycle.py`**
  - `LifecycleManager`: stage transitions, validation, and timeouts.
- **`core/scheduler.py`**
  - `TaskScheduler`: scheduled tasks with triggers and delayed execution.
- **`core/resource_limits.py`**
  - Resource limit models (`CpuLimits`, `MemoryLimits`, `DiskLimits`, `GpuLimits`) + validation (`ResourceValidator`) + `ResourceUsage`.
- **`core/resource_monitor.py`**
  - `ResourceMonitor`: reads CPU/RAM usage via `psutil` when available.
- **`core/gpu_limits.py`**
  - `GpuController`: GPU policy stubs (software rendering, blocking).
- **`core/complete_sandbox.py`**
  - `CompleteSandbox`: composition of isolation + resource limits + monitoring + filesystem isolation + policy.
  - `SandboxBuilder`: builder pattern for easier sandbox configuration.

### 2) Analysis

- **`analysis/static.py`**
  - `StaticEngine`: PE analysis (when `pefile` is installed) + entropy + suspicious imports + threat score.
- **`analysis/dynamic.py`**
  - `DynamicEngine`: runtime events (e.g., process creation, registry writes, injections) and behavior graph / risk scoring.
- **`analysis/memory.py`**
  - `MemoryScanner`: attempts memory scanning via Windows APIs for patterns like shellcode / high entropy regions.
- **`analysis/network.py`**
  - `NetworkMonitor`: simplified TLS fingerprint logging + DNS beacon interval analysis.
- **`analysis/script.py`**
  - `ScriptAnalyzer`: keyword-based heuristics for suspicious PowerShell/Python scripts.
- **`analysis/installer.py`**
  - `InstallerAnalyzer`: detects “installation intent” from command-line / indicators.

### 3) Disk

- **`disk/virtual_disk.py`**: `VirtualDisk` simplified creation/prep.
- **`disk/fs_isolation.py`**: `FilesystemIsolation` path restrictions + virtual root enforcement.
- **`disk/fs_redirect.py`**: `FilesystemRedirector` simplified redirection / copy-on-write.
- **`disk/snapshot.py`** / **`disk/diff.py`**: snapshot and diff logic.

### 4) Registry

- **`registry/hive.py`**: simplified `HiveParser`.
- **`registry/virtualization.py`**: `RegistryVirtualizer`.
- **`registry/diff.py`**: `RegistryDiff` heuristics.

### 5) Deception

- **`deception/env.py`**: `FakeEnvironment`.
- **`deception/fake_os.py`**: `FakeOS`.
- **`deception/anti_vm.py`**: `AntiVMCountermeasures` stubs.
- **`deception/mutation.py`**: `EnvironmentMutator`.

### 6) Defense

- **`defense/network_isolation.py`**: network/IPC/clipboard isolation policies.
- **`defense/self_protection.py`**: self-protection stubs (heartbeat/anti-debug).
- **`defense/escape_detection.py`**: escape detection stubs.

### 7) Governance

- **`governance/policy.py`**: `Policy` and `PolicyEnforcer`.

### 8) Intelligence

- **`intelligence/verdict.py`**: `VerdictEngine` merges analysis scores into a final verdict.
- **`intelligence/campaign.py`**: `CampaignTracker`.
- **`intelligence/trust_abuse.py`**: `TrustAnalyzer`.
- **`intelligence/long_run.py`**: `LongTermMonitor`.

### 9) Bridge

- **`bridge.py`**: `DragonCodeBridge` heartbeat stub for future integration.

## Dependencies (`requirements.txt`)

- **psutil**: system resource usage (CPU/RAM).
- **pefile**: PE parsing on Windows.

## Security / Operational Notes

- Running real malware requires strict isolation (VM, isolated network, strict policy). This Python port focuses on architecture and analysis flow, not a full production isolation boundary.
