# DragonCode Sandbox (Python) — توثيق المشروع

[English README](README_EN.md)

هذا المستودع هو **نسخة بايثون** (Python Port) لمشروع *DragonCode Sandbox* . الهدف هو الحفاظ على نفس الأفكار والبنية (Modules/Interfaces) مع تنفيذ قابل للتشغيل عبر:

```bash
python -m dragoncode_sandbox
```

## الفكرة العامة

DragonCode Sandbox عبارة عن منصة تحليل سلوكيات (Sandbox Simulation) مصممة لتجميع إشارات من مصادر متعددة (Static/Dynamic/Memory/Network/Policy) ثم تحويلها إلى **Verdict** نهائي (درجة خطورة + مستوى تهديد + تفسير).

ملاحظة مهمة: بعض أجزاء “العزل الحقيقي” وواجهات Windows منخفضة المستوى تم تمثيلها في بايثون **بشكل Stub/Mock** (أو تنفيذ مبسط) للحفاظ على التدفق العام للمشروع، مع مراعاة أن التنفيذ الإنتاجي يتطلب تكامل أعمق مع النظام.

## المتطلبات

- **Python**: يفضّل Python 3.11+ (تم اختبار التشغيل على 3.12).
- **نظام التشغيل**: Windows هو الأنسب لأن بعض التحليلات (Memory) تستخدم Windows APIs عبر `ctypes`، لكن المشروع قادر على التشغيل على أنظمة أخرى مع تعطيل/تبسيط بعض الخصائص.

## التثبيت والتشغيل

### 1) إنشاء بيئة افتراضية

```bash
python -m venv .venv
```

على Windows:

```powershell
.\.venv\Scripts\Activate.ps1
```

### 2) تثبيت الاعتمادات

```bash
pip install -r requirements.txt
```

### 3) تشغيل المحاكاة

```bash
python -m dragoncode_sandbox
```

سيقوم الـ entrypoint بمحاكاة تدفق مشابه لـ `main.rs` في نسخة Rust: إنشاء `SandboxContext`، تسجيل أحداث ديناميكية، حساب الـ Verdict، ثم طباعة تقرير.

## هيكل المشروع

المجلد الأساسي لنسخة بايثون هو:

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

## شرح الموديولات (Modules)

### 1) Core — قلب النظام

- **`core/context.py`**
  - **SandboxContext**: يحمل `sample_hash`، مستوى العزل `IsolationLevel`، وحالة verdict + مساحة ذاكرة مشتركة Thread-safe.
- **`core/isolation.py`**
  - **SandboxIsolation**: واجهة عزل وتشغيل (تمثيل مبسط) مع إعدادات مثل Job Object/Token في نسخة Rust.
- **`core/lifecycle.py`**
  - **LifecycleManager**: إدارة مراحل التشغيل/التحليل (Stages) والتحقق من الانتقالات والـ timeouts.
- **`core/scheduler.py`**
  - **TaskScheduler**: جدولة مهام مع Triggers وتأخير زمني.
- **`core/resource_limits.py`**
  - تعريف حدود الموارد (`CpuLimits`, `MemoryLimits`, `DiskLimits`, `GpuLimits`) + التحقق (`ResourceValidator`) + تمثيل الاستخدام (`ResourceUsage`).
- **`core/resource_monitor.py`**
  - **ResourceMonitor**: مراقبة استخدام CPU/RAM عبر `psutil` (عند توفره).
- **`core/gpu_limits.py`**
  - **GpuController**: إعدادات/قيود GPU بشكل stub (Software rendering, blocking).
- **`core/complete_sandbox.py`**
  - **CompleteSandbox**: نقطة تجميع لمكونات العزل والموارد والـ policy والـ filesystem isolation.
  - **SandboxBuilder**: builder pattern لتجهيز Sandbox بسهولة.

### 2) Analysis — محركات التحليل

- **`analysis/static.py`**
  - **StaticEngine**: تحليل ملف PE (عند توفر `pefile`) + حساب Entropy + imports مشبوهة + Threat Score.
- **`analysis/dynamic.py`**
  - **DynamicEngine**: تسجيل أحداث Runtime (مثل ProcessCreate/RegistryWrite/Injection) وبناء Behavior Graph مع Risk Scores.
- **`analysis/memory.py`**
  - **MemoryScanner**: محاولة مسح الذاكرة عبر Windows APIs لاكتشاف مؤشرات مثل shellcode patterns / high entropy regions.
- **`analysis/network.py`**
  - **NetworkMonitor**: تتبع fingerprints مبسّط + تحليل beacon intervals للـ DNS.
- **`analysis/script.py`**
  - **ScriptAnalyzer**: فحص سكربتات PowerShell/Python بالكلمات المفتاحية المشبوهة.
- **`analysis/installer.py`**
  - **InstallerAnalyzer**: استنتاج “نية التثبيت” مثل service creation / driver load من خلال command-line أو مؤشرات.

### 3) Disk — عزل وتتبّع الملفات

- **`disk/virtual_disk.py`**
  - **VirtualDisk**: إنشاء/تجهيز قرص افتراضي بشكل مبسّط.
- **`disk/fs_isolation.py`**
  - **FilesystemIsolation**: قواعد منع الوصول لمسارات خطرة + التحقق من الخروج خارج الـ virtual root.
- **`disk/fs_redirect.py`**
  - **FilesystemRedirector**: تحويل المسارات وcopy-on-write بشكل مبسط.
- **`disk/snapshot.py`** / **`disk/diff.py`**
  - **DiskSnapshot** و **DiskDiff**: تتبع تغييرات الملفات وتحليلها.

### 4) Registry — محاكاة/افتراضية الريجيستري

- **`registry/hive.py`**: **HiveParser** (تمثيل مبسط).
- **`registry/virtualization.py`**: **RegistryVirtualizer**.
- **`registry/diff.py`**: **RegistryDiff** لاكتشاف تغييرات مشبوهة.

### 5) Deception — تضليل مضاد للـ Anti-VM

- **`deception/env.py`**: **FakeEnvironment**.
- **`deception/fake_os.py`**: **FakeOS**.
- **`deception/anti_vm.py`**: **AntiVMCountermeasures**.
- **`deception/mutation.py`**: **EnvironmentMutator**.

### 6) Defense — حماية ومراقبة محاولات الهروب

- **`defense/network_isolation.py`**: سياسات عزل الشبكة/الـ IPC/الـ Clipboard.
- **`defense/self_protection.py`**: آليات حماية (stub) مثل heartbeat/anti-debug.
- **`defense/escape_detection.py`**: رصد مؤشرات escape (stub).

### 7) Governance — قواعد التشغيل (Rules of Engagement)

- **`governance/policy.py`**
  - **Policy** و **PolicyEnforcer**: قرارات مثل السماح بالشبكة/منع الكتابة/قيود عامة.

### 8) Intelligence — إصدار الحكم النهائي

- **`intelligence/verdict.py`**
  - **VerdictEngine**: دمج درجات التحليل (static/dynamic/network/...) لتوليد Threat Score وConfidence وتفسير.
- **`intelligence/campaign.py`**: **CampaignTracker**.
- **`intelligence/trust_abuse.py`**: **TrustAnalyzer**.
- **`intelligence/long_run.py`**: **LongTermMonitor**.

### 9) Bridge — تكامل/ربط (Stub)

- **`bridge.py`**
  - **DragonCodeBridge**: heartbeat وتنسيق مبسط لتكامل مستقبلي.

## الاعتمادات (requirements)

- **psutil**: لقراءة استهلاك الموارد (CPU/RAM) من النظام.
- **pefile**: لتحليل ملفات PE على Windows.

## ملاحظات أمنية وتشغيلية

- **تشغيل العينات الخبيثة الحقيقية** يتطلب بيئة معزولة بالكامل (VM/شبكة معزولة/سياسات صارمة). هذه النسخة تركّز على هيكل التحليل والمنطق وليس العزل الإنتاجي الكامل.

