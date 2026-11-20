Option Explicit

Dim sh, fso, root, py, core, url, cmd
Dim http, running, i

Set sh = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

root = fso.GetParentFolderName(WScript.ScriptFullName)
py = "C:\msys64\ucrt64\bin\pythonw.exe"
If Not fso.FileExists(py) Then py = "pythonw.exe"

core = root & "\core.py"
url = "http://127.0.0.1:8765"
cmd = """" & py & """ """ & core & """ --ui"

running = False
On Error Resume Next
Set http = CreateObject("WinHttp.WinHttpRequest.5.1")
http.SetTimeouts 250, 250, 250, 250
http.Open "GET", url & "/api/status", False
http.Send
If Err.Number = 0 Then
    If http.Status = 200 Then running = True
End If
Err.Clear
On Error GoTo 0

If Not running Then
    sh.Run cmd, 0, False
    For i = 1 To 40
        WScript.Sleep 250
        On Error Resume Next
        http.Open "GET", url & "/api/status", False
        http.Send
        If Err.Number = 0 Then
            If http.Status = 200 Then running = True
        End If
        Err.Clear
        On Error GoTo 0
        If running Then Exit For
    Next
End If

If running Then
    sh.Run url, 1, False
Else
    MsgBox "ProxyDeck could not start. Check the Python installation and port 8765.", vbExclamation, "ProxyDeck"
End If
