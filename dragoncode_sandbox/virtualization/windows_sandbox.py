import os
import sys
from pathlib import Path

class WindowsSandboxGenerator:
    @staticmethod
    def generate_wsb(project_root: str, python_path: str) -> str:
        """
        Generates a .wsb configuration file to run the persistent analysis agent.
        Maps:
        1. The Project Root -> C:\\Project (Read/Write)
        2. The Host Python Environment -> C:\\PythonHost (Read)
        """
        project_abs = str(Path(project_root).resolve())
        python_abs = str(Path(sys.prefix).resolve())
        
        wsb_content = f"""<Configuration>
  <VGpu>Enable</VGpu>
  <Networking>Enable</Networking>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>{project_abs}</HostFolder>
      <SandboxFolder>C:\\Project</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>{python_abs}</HostFolder>
      <SandboxFolder>C:\\PythonHost</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>cmd /k "set PYTHONPATH=C:\\Project &amp;&amp; C:\\PythonHost\\python.exe -m dragoncode_sandbox.agent"</Command>
  </LogonCommand>
</Configuration>
"""
        wsb_path = os.path.join(project_root, "analysis.wsb")
        with open(wsb_path, "w", encoding="utf-8") as f:
            f.write(wsb_content)
            
        return wsb_path
