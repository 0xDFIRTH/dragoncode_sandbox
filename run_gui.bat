@echo off
echo [*] Launching DragonCode Sandbox GUI...
set PYTHONPATH=%CD%
python -m dragoncode_sandbox.gui.app
pause
