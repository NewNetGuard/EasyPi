# Registers only a read-only observer. Never starts or restarts a test.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ConfigPath,
    [Parameter(Mandatory)][string]$PythonPath,
    [ValidatePattern('^EasyPi-Prism-Watch-[A-Za-z0-9-]+$')]
    [string]$TaskName = 'EasyPi-Prism-Watch-Infrastructure',
    [ValidateRange(1,12)][int]$Hours = 12
)
$ErrorActionPreference = 'Stop'
$config = (Resolve-Path -LiteralPath $ConfigPath).Path
$python = (Resolve-Path -LiteralPath $PythonPath).Path
# Interactive tasks must not open a console on the user's desktop each minute.
if ((Split-Path $python -Leaf) -ieq 'python.exe') {
    $windowless = Join-Path (Split-Path $python -Parent) 'pythonw.exe'
    if (Test-Path -LiteralPath $windowless -PathType Leaf) { $python = $windowless }
}
$root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$observer = Join-Path $root 'tests\acceptance\prism_duration_watch.py'
foreach ($value in @($config, $python, $observer)) {
    if ($value.Contains('"')) { throw 'Quotes are not permitted in task paths' }
}
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    throw 'Task already exists; inspect it before replacing it'
}
$action = New-ScheduledTaskAction -Execute $python -Argument ('"{0}" --config "{1}"' -f $observer, $config) -WorkingDirectory $root
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(15) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Hours $Hours)
$principal = New-ScheduledTaskPrincipal -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -Hidden -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Seconds 40)
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Read-only Prism test health observer; no network or test restart actions.' | Out-Null
Get-ScheduledTask -TaskName $TaskName | Select-Object TaskName, State
