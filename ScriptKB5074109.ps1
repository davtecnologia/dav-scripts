<# 
.SYNOPSIS
  Remoção segura do impacto associado à KB5074109 (Outlook Classic instável).
  - Detecta KB5074109 via Get-HotFix
  - Remove o pacote cumulativo (LCU/RollupFix) instalado correspondente via DISM /remove-package
  - Pausa Windows Update por X dias SOMENTE se a remoção for bem-sucedida
  - Log em C:\LogRemoveKB5074109.txt
  - Event Viewer (Application) com Source próprio e EventId válido
  - Reinicia em 30 segundos (em ambos os casos)

.NOTES
  Execute como Administrador.
#>

$TargetKbId    = "KB5074109"
$DelaySeconds  = 30
$LogPath       = "C:\LogRemoveKB5074109.txt"

# Pausa Windows Update (best-effort) - SOMENTE se remoção for bem-sucedida
$PauseDays     = 7

$EventSource   = "DAV-RemoveKB5074109"
$EventLogName  = "Application"
$EventId       = 54109  # precisa ser <= 65535

function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet("INFO","WARN","ERROR")][string]$Level = "INFO"
    )
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts][$Level] $Message"
    Add-Content -Path $LogPath -Value $line -Encoding UTF8
    Write-Host $line
}

function Test-IsAdmin {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-EventSource {
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
            New-EventLog -LogName $EventLogName -Source $EventSource
            Start-Sleep -Seconds 1
        }
    } catch {
        Write-Log -Message "Não foi possível criar/validar Event Source '$EventSource': $($_.Exception.Message)" -Level "WARN"
    }
}

function Write-Event {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet("Information","Warning","Error")][string]$EntryType = "Information"
    )
    try {
        Ensure-EventSource
        Write-EventLog -LogName $EventLogName -Source $EventSource -EventId $EventId -EntryType $EntryType -Message $Message
    } catch {
        Write-Log -Message "Falha ao registrar no Event Viewer: $($_.Exception.Message)" -Level "WARN"
    }
}

function Restart-WithMessage {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [int]$Seconds = 30
    )
    Write-Log   -Message $Message -Level "INFO"
    Write-Event -Message $Message -EntryType "Information"
    shutdown.exe /r /t $Seconds /c $Message | Out-Null
}

function Get-OSBuildInfo {
    try {
        $cv = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction Stop
        return [pscustomobject]@{
            DisplayVersion = $cv.DisplayVersion
            CurrentBuild   = $cv.CurrentBuild
            UBR            = $cv.UBR
            BuildString    = "$($cv.CurrentBuild).$($cv.UBR)"
        }
    } catch {
        return $null
    }
}

function Get-InstalledHotFix {
    param([Parameter(Mandatory=$true)][string]$KbId)
    try {
        return Get-HotFix -Id $KbId -ErrorAction SilentlyContinue
    } catch {
        return $null
    }
}

function Get-DismPackagesTable {
    try {
        $out = & dism.exe /online /get-packages /format:table 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $out) { return $null }
        return $out
    } catch { 
        return $null 
    }
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

    if (-not $candidates -or $candidates.Count -eq 0) { return $null }

    $sorted = $candidates | Sort-Object @{Expression="InstallTime";Descending=$true}, @{Expression="InstallTimeRaw";Descending=$true}
    return $sorted | Select-Object -First 1
}

function Remove-PackageWithDism {
    param([Parameter(Mandatory=$true)][string]$PackageName)

    $args = "/online /remove-package /packagename:$PackageName /quiet /norestart"
    Write-Log -Message "Executando: dism.exe $args" -Level "INFO"

    & dism.exe $args | Out-Null
    $code = $LASTEXITCODE

    Write-Log -Message "DISM finalizado. ExitCode: $code" -Level "INFO"
    return $code
}

function Validate-PackageState {
    param([Parameter(Mandatory=$true)][string]$PackageName)
    $table = Get-DismPackagesTable
    if (-not $table) { return $null }

    $line = $table | Where-Object { $_ -match [regex]::Escape($PackageName) } | Select-Object -First 1
    return $line
}

function Pause-WindowsUpdate {
    param([int]$Days = 7)

    try {
        $pauseStart = Get-Date
        $pauseEnd   = $pauseStart.AddDays($Days)

        # Formato ISO 8601
        $startStr = $pauseStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        $endStr   = $pauseEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

        $regPath = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"

        Write-Log -Message "Tentando pausar Windows Update por $Days dias (best-effort)..." -Level "INFO"
        Write-Log -Message "Pause Start(UTC): $startStr | Pause End(UTC): $endStr" -Level "INFO"

        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }

        New-ItemProperty -Path $regPath -Name "PauseUpdatesStartTime"        -Value $startStr -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $regPath -Name "PauseUpdatesExpiryTime"       -Value $endStr   -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $regPath -Name "PauseFeatureUpdatesStartTime" -Value $startStr -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $regPath -Name "PauseFeatureUpdatesEndTime"   -Value $endStr   -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $regPath -Name "PauseQualityUpdatesStartTime" -Value $startStr -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $regPath -Name "PauseQualityUpdatesEndTime"   -Value $endStr   -PropertyType String -Force | Out-Null

        # Tenta "refrescar" o serviço (best-effort; pode ser bloqueado por política)
        try {
            Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            Start-Service wuauserv -ErrorAction SilentlyContinue
        } catch {}

        Write-Log -Message "Windows Update pausado por $Days dias (best-effort). Políticas corporativas podem reverter." -Level "INFO"
        Write-Event -Message "Windows Update pausado por $Days dias (best-effort). Pode ser revertido por política corporativa." -EntryType "Warning"
        return $true
    }
    catch {
        Write-Log -Message "Falha ao pausar Windows Update: $($_.Exception.Message)" -Level "WARN"
        Write-Event -Message "Falha ao pausar Windows Update: $($_.Exception.Message)" -EntryType "Warning"
        return $false
    }
}

# ===================== INÍCIO =====================

"=============================================================" | Out-File -FilePath $LogPath -Append -Encoding UTF8
"Inicio - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"            | Out-File -FilePath $LogPath -Append -Encoding UTF8
"Usuario: $env:USERNAME | Computador: $env:COMPUTERNAME"        | Out-File -FilePath $LogPath -Append -Encoding UTF8
"=============================================================" | Out-File -FilePath $LogPath -Append -Encoding UTF8

try {
    if (-not (Test-IsAdmin)) {
        Write-Log -Message "Script não executado como Administrador. Abortando." -Level "ERROR"
        Write-Event -Message "Script não executado como Administrador. Abortando." -EntryType "Error"
        throw "Permissão insuficiente. Execute o PowerShell como Administrador."
    }

    $os = Get-OSBuildInfo
    if ($os) {
        Write-Log -Message "Windows: DisplayVersion=$($os.DisplayVersion) Build=$($os.BuildString)" -Level "INFO"
    }

    Write-Log -Message "Verificando presença da $TargetKbId..." -Level "INFO"
    $hf = Get-InstalledHotFix -KbId $TargetKbId

    if (-not $hf) {
        Write-Log -Message "$TargetKbId NÃO encontrada. Nenhuma remoção será realizada." -Level "WARN"
        Restart-WithMessage -Message "ATUALIZAÇÃO NÃO ENCONTRADA. REINICIANDO EM 30 SEGUNDOS..." -Seconds $DelaySeconds
        return
    }

    Write-Log -Message "$TargetKbId encontrada (InstalledOn: $($hf.InstalledOn))." -Level "INFO"
    Write-Event -Message "$TargetKbId encontrada. Iniciando procedimento de remoção controlada (LCU/RollupFix via DISM)." -EntryType "Warning"

    $dismTable = Get-DismPackagesTable
    if (-not $dismTable) {
        Write-Log -Message "Falha ao obter lista de pacotes via DISM. Não é seguro prosseguir." -Level "ERROR"
        Restart-WithMessage -Message "FALHA AO CONSULTAR DISM. REINICIANDO EM 30 SEGUNDOS..." -Seconds $DelaySeconds
        return
    }

    $rollup = Find-LatestInstalledRollupFixPackage -DismTableLines $dismTable
    if (-not $rollup) {
        Write-Log -Message "Não foi encontrado pacote Package_for_RollupFix com estado 'Instalado/Installed'. Não é seguro prosseguir." -Level "ERROR"
        Restart-WithMessage -Message "KB DETECTADA, MAS LCU INSTALADA NÃO FOI IDENTIFICADA COM SEGURANÇA. REINICIANDO EM 30 SEGUNDOS..." -Seconds $DelaySeconds
        return
    }

    Write-Log -Message "LCU selecionada para remoção (mais recente Instalado):" -Level "INFO"
    Write-Log -Message "  Package: $($rollup.PackageName)" -Level "INFO"
    Write-Log -Message "  InstallTime: $($rollup.InstallTimeRaw)" -Level "INFO"
    Write-Log -Message "  Linha DISM: $($rollup.Line)" -Level "INFO"

    $exit = Remove-PackageWithDism -PackageName $rollup.PackageName

    if ($exit -eq 0 -or $exit -eq 3010) {
        $postLine = Validate-PackageState -PackageName $rollup.PackageName
        if ($postLine) {
            Write-Log -Message "Pós-remoção (antes do reboot), estado atual na tabela DISM:" -Level "INFO"
            Write-Log -Message "  $postLine" -Level "INFO"
        } else {
            Write-Log -Message "Pós-remoção (antes do reboot), pacote não localizado na tabela DISM (pode ser esperado)." -Level "INFO"
        }

        # Pausa SOMENTE se remoção foi bem-sucedida
        Pause-WindowsUpdate -Days $PauseDays | Out-Null

        Restart-WithMessage -Message "ATUALIZAÇÃO REMOVIDA COM SUCESSO. REINICIANDO EM 30 SEGUNDOS..." -Seconds $DelaySeconds
    }
    else {
        Write-Log -Message "Falha ao remover pacote via DISM. ExitCode: $exit" -Level "ERROR"
        Restart-WithMessage -Message "FALHA AO REMOVER ATUALIZAÇÃO (DISM ExitCode: $exit). REINICIANDO EM 30 SEGUNDOS..." -Seconds $DelaySeconds
    }
}
catch {
    Write-Log -Message "Exceção: $($_.Exception.Message)" -Level "ERROR"
    Restart-WithMessage -Message "ERRO AO EXECUTAR O SCRIPT. REINICIANDO EM 30 SEGUNDOS..." -Seconds $DelaySeconds
}
finally {
    Write-Log -Message "Fim do processo." -Level "INFO"
}
