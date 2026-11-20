Option Explicit
Dim sh, fso, root, py, core, url, cmd
Set sh = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
root = fso.GetParentFolderName(WScript.ScriptFullName)
py = "C:\msys64\ucrt64\bin\pythonw.exe"
If Not fso.FileExists(py) Then py = "pythonw.exe"
core = root & "\core.py"
url = "http://127.0.0.1:8765"
cmd = """" & py & """ """ & core & """ --ui"
sh.Run cmd, 0, False
WScript.Sleep 1200
sh.Run url, 1, False
