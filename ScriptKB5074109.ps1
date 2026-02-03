<# 
  ScriptKB5074109.ps1 (v5.2)
  - Detecta KB5074109 (Get-HotFix)
  - Identifica LCU RollupFix instalada mais recente (DISM /get-packages)
  - Remove via DISM usando Start-Process (mais confiável) e packagename entre aspas
  - Pausa Windows Update SOMENTE se a remoção for bem-sucedida
  - Pausa configurada por DATA LIMITE fixa (editar manualmente no futuro)
  - Log: C:\LogRemoveKB5074109.txt
  - Reinicia em 30 segundos
#>

$TargetKbId    = "KB5074109"
$DelaySeconds  = 30
$LogPath       = "C:\LogRemoveKB5074109.txt"

# >>> ALTERAÇÃO: Defina aqui a DATA LIMITE (edite manualmente quando quiser)
# Formatos aceitos: "YYYY-MM-DD" ou "YYYY-MM-DD HH:mm"
$PauseUntil    = [datetime]"2026-06-03 23:59"

$EventSource   = "DAV-RemoveKB5074109"
$EventLogName  = "Application"
$EventId       = 54109

function Write-Log {
    param([string]$Message,[ValidateSet("INFO","WARN","ERROR")][string]$Level="INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts][$Level] $Message"
    Add-Content -Path $LogPath -Value $line -Encoding UTF8
    Write-Host $line
}

function Test-IsAdmin {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-EventSource {
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
            New-EventLog -LogName $EventLogName -Source $EventSource
            Start-Sleep -Seconds 1
        }
    } catch {
        Write-Log "Event Source '$EventSource' não pôde ser criado/validado: $($_.Exception.Message)" "WARN"
    }
}

function Write-Event {
    param([string]$Message,[ValidateSet("Information","Warning","Error")][string]$EntryType="Information")
    try {
        Ensure-EventSource
        Write-EventLog -LogName $EventLogName -Source $EventSource -EventId $EventId -EntryType $EntryType -Message $Message
    } catch {
        Write-Log "Falha ao registrar no Event Viewer: $($_.Exception.Message)" "WARN"
    }
}

function Restart-WithMessage {
    param([string]$Message,[int]$Seconds=30)
    Write-Log $Message "INFO"
    Write-Event $Message "Information"
    shutdown.exe /r /t $Seconds /c $Message | Out-Null
}

function Get-OSBuildInfo {
    try {
        $cv = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction Stop
        [pscustomobject]@{
            DisplayVersion = $cv.DisplayVersion
            CurrentBuild   = $cv.CurrentBuild
            UBR            = $cv.UBR
            BuildString    = "$($cv.CurrentBuild).$($cv.UBR)"
        }
    } catch { $null }
}

function Get-InstalledHotFix {
    param([string]$KbId)
    try { Get-HotFix -Id $KbId -ErrorAction SilentlyContinue } catch { $null }
}

function Get-DismPackagesTable {
    try {
        $out = & dism.exe /online /get-packages /format:table 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $out) { return $null }
        $out
    } catch { $null }
}

function Find-LatestInstalledRollupFixPackage {
    param([string[]]$DismTableLines)
    if (-not $DismTableLines) { return $null }

    $candidates = @()
    foreach ($line in $DismTableLines) {
        if ($line -match "Package_for_RollupFix" -and ($line -match "\|\s*Instalado\s*\|" -or $line -match "\|\s*Installed\s*\|")) {
            $parts = $line -split "\|"
            if ($parts.Count -ge 4) {
                $pkg  = $parts[0].Trim()
                $time = $parts[3].Trim()
                $dt = $null
                try { $dt = [datetime]::Parse($time, (Get-Culture "pt-BR")) } catch {}
                if (-not $dt) { try { $dt = [datetime]::Parse($time) } catch {} }

                $candidates += [pscustomobject]@{
                    PackageName    = $pkg
                    InstallTime    = $dt
                    InstallTimeRaw = $time
                    Line           = $line.Trim()
                }
            }
        }
    }

    if (-not $candidates) { return $null }
    $candidates | Sort-Object @{Expression="InstallTime";Descending=$true}, @{Expression="InstallTimeRaw";Descending=$true} | Select-Object -First 1
}

function Remove-PackageWithDism {
    param([string]$PackageName)

    # IMPORTANTÍSSIMO: DISM é sensível; use Start-Process e packagename entre aspas.
    $argList = @(
        "/online",
        "/remove-package",
        "/packagename:`"$PackageName`"",
        "/quiet",
        "/norestart"
    )

    Write-Log ("Executando: dism.exe {0}" -f ($argList -join " ")) "INFO"

    $p = Start-Process -FilePath "dism.exe" -ArgumentList $argList -Wait -PassThru
    Write-Log "DISM finalizado. ExitCode: $($p.ExitCode)" "INFO"
    return $p.ExitCode
}

# >>> ALTERAÇÃO: Pause por DATA LIMITE fixa
function Pause-WindowsUpdate {
    param([datetime]$Until)

    try {
        $pauseStart = Get-Date

        if ($Until -le $pauseStart) {
            Write-Log "PAUSA NÃO APLICADA: a data limite ($Until) é <= agora ($pauseStart)." "WARN"
            return $false
        }

        $startStr = $pauseStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        $endStr   = $Until.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

        $regPath = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"

        Write-Log "Pausando Windows Update até $Until (best-effort)." "INFO"
        Write-Log "Pause Start(UTC): $startStr | Pause End(UTC): $endStr" "INFO"

        if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }

        New-ItemProperty -Path $regPath -Name "PauseUpdatesStartTime"        -Value $startStr -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $regPath -Name "PauseUpdatesExpiryTime"       -Value $endStr   -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $regPath -Name "PauseFeatureUpdatesStartTime" -Value $startStr -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $regPath -Name "PauseFeatureUpdatesEndTime"   -Value $endStr   -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $regPath -Name "PauseQualityUpdatesStartTime" -Value $startStr -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $regPath -Name "PauseQualityUpdatesEndTime"   -Value $endStr   -PropertyType String -Force | Out-Null

        Write-Log "Windows Update pausado até (UTC): $endStr (best-effort). Políticas/limites do Windows podem reverter." "INFO"
        Write-Event "Windows Update pausado até $Until (best-effort). Pode ser revertido por política/limites do Windows." "Warning"
        return $true
    } catch {
        Write-Log "Falha ao pausar Windows Update: $($_.Exception.Message)" "WARN"
        return $false
    }
}

# ===================== INÍCIO =====================

"=============================================================" | Out-File -FilePath $LogPath -Append -Encoding UTF8
"Inicio - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"            | Out-File -FilePath $LogPath -Append -Encoding UTF8
"Usuario: $env:USERNAME | Computador: $env:COMPUTERNAME"        | Out-File -FilePath $LogPath -Append -Encoding UTF8
"=============================================================" | Out-File -FilePath $LogPath -Append -Encoding UTF8

try {
    if (-not (Test-IsAdmin)) { throw "Permissão insuficiente. Execute o PowerShell como Administrador." }

    $os = Get-OSBuildInfo
    if ($os) { Write-Log "Windows: DisplayVersion=$($os.DisplayVersion) Build=$($os.BuildString)" "INFO" }

    Write-Log "Verificando presença da $TargetKbId..." "INFO"
    $hf = Get-InstalledHotFix -KbId $TargetKbId

    if (-not $hf) {
        Write-Log "$TargetKbId NÃO encontrada. Nenhuma remoção será realizada." "WARN"
        Restart-WithMessage "ATUALIZAÇÃO NÃO ENCONTRADA. REINICIANDO EM 30 SEGUNDOS..." $DelaySeconds
        return
    }

    Write-Log "$TargetKbId encontrada (InstalledOn: $($hf.InstalledOn))." "INFO"
    Write-Event "$TargetKbId encontrada. Iniciando remoção controlada (LCU/RollupFix via DISM)." "Warning"

    $dismTable = Get-DismPackagesTable
    if (-not $dismTable) {
        Write-Log "Falha ao obter lista de pacotes via DISM. Não é seguro prosseguir." "ERROR"
        Restart-WithMessage "FALHA AO CONSULTAR DISM. REINICIANDO EM 30 SEGUNDOS..." $DelaySeconds
        return
    }

    $rollup = Find-LatestInstalledRollupFixPackage -DismTableLines $dismTable
    if (-not $rollup) {
        Write-Log "Não foi encontrado Package_for_RollupFix em estado 'Instalado/Installed'. Não é seguro prosseguir." "ERROR"
        Restart-WithMessage "KB DETECTADA, MAS LCU INSTALADA NÃO FOI IDENTIFICADA COM SEGURANÇA. REINICIANDO EM 30 SEGUNDOS..." $DelaySeconds
        return
    }

    Write-Log "LCU selecionada para remoção:" "INFO"
    Write-Log "  Package: $($rollup.PackageName)" "INFO"
    Write-Log "  InstallTime: $($rollup.InstallTimeRaw)" "INFO"
    Write-Log "  Linha DISM: $($rollup.Line)" "INFO"

    $exit = Remove-PackageWithDism -PackageName $rollup.PackageName

    if ($exit -eq 0 -or $exit -eq 3010) {
        Pause-WindowsUpdate -Until $PauseUntil | Out-Null
        Restart-WithMessage "ATUALIZAÇÃO REMOVIDA COM SUCESSO. REINICIANDO EM 30 SEGUNDOS..." $DelaySeconds
    } else {
        Write-Log "Falha ao remover pacote via DISM. ExitCode: $exit" "ERROR"
        Restart-WithMessage "FALHA AO REMOVER ATUALIZAÇÃO (DISM ExitCode: $exit). REINICIANDO EM 30 SEGUNDOS..." $DelaySeconds
    }
}
catch {
    Write-Log "Exceção: $($_.Exception.Message)" "ERROR"
    Restart-WithMessage "ERRO AO EXECUTAR O SCRIPT. REINICIANDO EM 30 SEGUNDOS..." $DelaySeconds
}
finally {
    Write-Log "Fim do processo." "INFO"
}
