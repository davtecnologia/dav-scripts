<# 
.SYNOPSIS
  Verifica a presença da KB5074109 e, se encontrada com evidência forte, remove.
  Em ambos os casos, reinicia o computador em 30 segundos.
  Gera log em C:\LogRemoveKB5074109.txt e registra no Event Viewer (Application).

.NOTES
  Execute como Administrador.
#>

$KbId         = "KB5074109"
$KbNumber     = $KbId.Replace("KB","")
$DelaySeconds = 30
$LogPath      = "C:\LogRemoveKB5074109.txt"

$EventSource  = "DAV-RemoveKB5074109"
$EventLogName = "Application"
$EventId      = 5074109

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

function Ensure-EventSource {
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
            New-EventLog -LogName $EventLogName -Source $EventSource
            Start-Sleep -Seconds 1
        }
    } catch {
        # Se não conseguir criar source (policy), apenas loga em arquivo
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

function Test-IsAdmin {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Detect-KB {
    <#
      Retorna um objeto com:
        - IsInstalled (bool)
        - Evidence (array de strings)
    #>
    $evidence = New-Object System.Collections.Generic.List[string]
    $installed = $false

    # 1) Get-HotFix
    try {
        $hf = Get-HotFix -Id $KbId -ErrorAction SilentlyContinue
        if ($null -ne $hf) {
            $installed = $true
            $evidence.Add("Get-HotFix encontrou $KbId (InstalledOn: $($hf.InstalledOn)).")
        } else {
            $evidence.Add("Get-HotFix NÃO encontrou $KbId.")
        }
    } catch {
        $evidence.Add("Get-HotFix falhou: $($_.Exception.Message)")
    }

    # 2) Get-WindowsPackage -Online (DISM module) – nem sempre existe
    try {
        if (Get-Command Get-WindowsPackage -ErrorAction SilentlyContinue) {
            # PackageName às vezes contém o KB; depende do tipo de pacote. Buscamos por KBNumber.
            $pkgs = Get-WindowsPackage -Online -ErrorAction SilentlyContinue | Where-Object {
                $_.PackageName -match $KbNumber -or $_.PackageName -match $KbId
            }
            if ($pkgs) {
                $installed = $true
                $sample = ($pkgs | Select-Object -First 1).PackageName
                $evidence.Add("Get-WindowsPackage encontrou pacote relacionado (ex.: $sample).")
            } else {
                $evidence.Add("Get-WindowsPackage NÃO encontrou pacote relacionado ao $KbId.")
            }
        } else {
            $evidence.Add("Cmdlet Get-WindowsPackage não disponível neste sistema.")
        }
    } catch {
        $evidence.Add("Get-WindowsPackage falhou: $($_.Exception.Message)")
    }

    # 3) Fallback: dism.exe /online /get-packages
    try {
        $dismOut = & dism.exe /online /get-packages 2>$null
        if ($LASTEXITCODE -eq 0 -and $dismOut) {
            $match = $dismOut | Select-String -SimpleMatch $KbNumber -ErrorAction SilentlyContinue
            if ($match) {
                $installed = $true
                $evidence.Add("dism.exe /get-packages encontrou referência ao $KbNumber.")
            } else {
                $evidence.Add("dism.exe /get-packages NÃO encontrou referência ao $KbNumber.")
            }
        } else {
            $evidence.Add("dism.exe /get-packages não retornou saída válida (ExitCode: $LASTEXITCODE).")
        }
    } catch {
        $evidence.Add("dism.exe falhou: $($_.Exception.Message)")
    }

    [pscustomobject]@{
        IsInstalled = $installed
        Evidence    = $evidence.ToArray()
    }
}

function Uninstall-KB {
    <#
      Retorna objeto com:
        - ExitCode (int)
        - Message (string)
    #>
    $args = "/uninstall /kb:$KbNumber /quiet /norestart"
    Write-Log -Message "Executando: wusa.exe $args" -Level "INFO"

    $proc = Start-Process -FilePath "wusa.exe" -ArgumentList $args -Wait -PassThru
    $code = $proc.ExitCode

    # Códigos comuns:
    # 0     = sucesso (nem sempre)
    # 3010  = sucesso, reinício necessário
    # 2359302 = não aplicável
    $msg = "WUSA finalizado. ExitCode: $code"

    [pscustomobject]@{
        ExitCode = $code
        Message  = $msg
    }
}

# Cabeçalho do log
"=============================================================" | Out-File -FilePath $LogPath -Append -Encoding UTF8
"Inicio - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"            | Out-File -FilePath $LogPath -Append -Encoding UTF8
"Usuario: $env:USERNAME | Computador: $env:COMPUTERNAME"        | Out-File -FilePath $LogPath -Append -Encoding UTF8
"OS: $([Environment]::OSVersion.VersionString)"                 | Out-File -FilePath $LogPath -Append -Encoding UTF8
"=============================================================" | Out-File -FilePath $LogPath -Append -Encoding UTF8

try {
    if (-not (Test-IsAdmin)) {
        Write-Log   -Message "Script não executado como Administrador. Abortando." -Level "ERROR"
        Write-Event -Message "Script não executado como Administrador. Abortando." -EntryType "Error"
        throw "Permissão insuficiente. Execute o PowerShell como Administrador."
    }

    Write-Log -Message "Iniciando detecção da $KbId..." -Level "INFO"
    $det = Detect-KB

    foreach ($ev in $det.Evidence) {
        Write-Log -Message $ev -Level "INFO"
    }

    if ($det.IsInstalled) {
        Write-Log -Message "$KbId CONFIRMADA como instalada (evidência forte). Prosseguindo com remoção." -Level "INFO"
        Write-Event -Message "$KbId confirmada como instalada. Iniciando remoção." -EntryType "Warning"

        $un = Uninstall-KB
        Write-Log -Message $un.Message -Level "INFO"

        # Validação pós-remoção (antes do reboot)
        Write-Log -Message "Validando presença da KB após tentativa de remoção..." -Level "INFO"
        $post = Detect-KB
        $stillThere = $post.IsInstalled

        if (-not $stillThere -and ($un.ExitCode -eq 0 -or $un.ExitCode -eq 3010 -or $un.ExitCode -eq 2359302)) {
            # Mesmo com 2359302, se a validação pós não vê a KB, consideramos ok
            Restart-WithMessage -Message "ATUALIZAÇÃO REMOVIDA COM SUCESSO. REINICIANDO EM 30 SEGUNDOS..." -Seconds $DelaySeconds
        }
        elseif ($un.ExitCode -eq 3010) {
            # Sucesso, mas validação pode ser inconsistente; ainda assim reiniciar
            Restart-WithMessage -Message "ATUALIZAÇÃO REMOVIDA (REINÍCIO NECESSÁRIO). REINICIANDO EM 30 SEGUNDOS..." -Seconds $DelaySeconds
        }
        else {
            # Falha/ambiguidade: reinicia (conforme solicitado), mas deixa claro no log
            Write-Log -Message "A remoção não pôde ser confirmada com segurança (ExitCode: $($un.ExitCode))." -Level "WARN"
            foreach ($ev in $post.Evidence) { Write-Log -Message "Pós-validação: $ev" -Level "INFO" }
            Restart-WithMessage -Message "FALHA OU INDETERMINADO AO REMOVER $KbId. REINICIANDO EM 30 SEGUNDOS..." -Seconds $DelaySeconds
        }
    }
    else {
        Write-Log -Message "$KbId não encontrada com evidência suficiente. Não será removida." -Level "WARN"
        Restart-WithMessage -Message "ATUALIZAÇÃO NÃO ENCONTRADA. REINICIANDO EM 30 SEGUNDOS..." -Seconds $DelaySeconds
    }
}
catch {
    Write-Log   -Message "Exceção: $($_.Exception.Message)" -Level "ERROR"
    Write-Event -Message "Exceção: $($_.Exception.Message)" -EntryType "Error"
    Restart-WithMessage -Message "ERRO AO EXECUTAR O SCRIPT. REINICIANDO EM 30 SEGUNDOS..." -Seconds $DelaySeconds
}
finally {
    Write-Log -Message "Fim do processo." -Level "INFO"
}
