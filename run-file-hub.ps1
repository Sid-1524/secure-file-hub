# Change these paths to your actual project locations
$serverScript = "D:\Coding\Server\server.py"
$guiScript    = "D:\Coding\Server\file_hub_gui.py"

# Activate your Python environment if needed
# & "D:\Coding\Server\venv\Scripts\Activate.ps1"

# Start the Flask server in a new PowerShell window
Start-Process powershell -ArgumentList "-NoExit", "-Command", "python `"$serverScript`""

# Wait a few seconds to ensure the server is up
Start-Sleep -Seconds 3

# Start the Tkinter GUI (optional)
Start-Process powershell -ArgumentList "-NoExit", "-Command", "python `"$guiScript`""

Write-Host "File Hub server and GUI started. Access the server at http://localhost:8000"
