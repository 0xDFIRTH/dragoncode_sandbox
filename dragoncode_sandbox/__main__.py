from __future__ import annotations
from .analysis.dynamic import DynamicEngine, Injection, ProcessCreate, RegistryWrite
from .core.context import SandboxContext
from .core.isolation import IsolationLevel
from .intelligence.verdict import VerdictEngine


def main() -> None:
    print("DragonCode Sandbox: Launching Simulation...")

    sample_hash = "abc123deadbeef"
    context = SandboxContext(sample_hash=sample_hash, isolation_level=IsolationLevel.STANDARD)
    print(f"[*] Context Initialized for sample: {context.sample_hash}")
    print(f"[*] Isolation Level: {context.isolation_level.value}")

    dynamic = DynamicEngine()
    verdict_engine = VerdictEngine()

    dynamic.start_logging("suspicious_sample.exe")
    print("[*] Dynamic Analysis Started. Logging events...")

    event_a = ProcessCreate(
        pid=1024,
        image="cmd.exe",
        cmd="cmd.exe /c powershell -nop",
    )
    dynamic.log_event(parent_pid=0, event=event_a)
    print("[!] Event Logged: Process Creation (cmd.exe)")

    event_b = RegistryWrite(
        key=r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        value=r"C:\\Malware.exe",
    )
    dynamic.log_event(parent_pid=1024, event=event_b)
    print("[!] Event Logged: Registry Persistence Attempt")

    event_c = Injection(
        target_pid=444,
        technique="ProcessHollowing",
    )
    dynamic.log_event(parent_pid=1024, event=event_c)
    print("[!] Event Logged: Code Injection Detected")

    timeline = dynamic.get_timeline()
    dynamic_risk_score = 0
    for node in timeline:
        if node.risk_score > dynamic_risk_score:
            dynamic_risk_score = node.risk_score

    verdict = verdict_engine.calculate(
        static_score=40,
        dynamic_score=dynamic_risk_score,
        network_score=0,
        tags=["Persistence", "Injection"],
    )

    context.set_verdict(verdict.score)

    print("\n--- ANALYSIS REPORT ---")
    print(f"Verdict Score: {verdict.score}/100")
    print(f"Threat Level: {verdict.level.value}")
    print(f"Confidence: {verdict.confidence * 100.0:.1f}%")
    print("Explanation:")
    for reason in verdict.explanation:
        print(f" - {reason}")
    print("-----------------------")


if __name__ == "__main__":
    main()
