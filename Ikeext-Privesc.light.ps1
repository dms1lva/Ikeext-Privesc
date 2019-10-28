function Invoke-IkeextCheck {
    param(
        [switch] $Verbose = $False,
        [switch] $PassThru = $False
    )
    Write-Host "+----------------------------------------------------------+"
    Write-Host "|                Invoke Check"
    Write-Host "+----------------------------------------------------------+"
    $is_vulnerable = $True
    if ($Verbose) { Write-Host -NoNewLine -ForeGroundColor Blue "[*] " ; Write-Host "Checking system version" }
    $os_wmi_object = Get-WmiObject -Class Win32_OperatingSystem
    $os_version = $os_wmi_object.version
    $os_name = $os_wmi_object.caption
    $os_arch = $os_wmi_object.OSArchitecture
    $os_v1 = "6.0"
    $os_v2 = "6.1"
    $os_v3 = "6.2"
    if ($Verbose) {
        Write-Host "[*] " -NoNewLine -ForeGroundColor Blue ; Write-Host "|__ OS Version: $($os_version)"
        Write-Host "[*] " -NoNewLine -ForeGroundColor Blue ; Write-Host "|__ OS Name: $($os_name)"
        Write-Host "[*] " -NoNewLine -ForeGroundColor Blue ; Write-Host "|__ OS Architecture: $($os_arch)"
    }
    if ($os_version -Like "$os_v1*" -or $os_version -Like "$os_v2*" -or $os_version -Like "$os_v3*") {
        Write-Host "[+] " -NoNewLine -ForeGroundColor Green ; Write-Host "$($os_name) is vulnerable."
    }
    else {
        $is_vulnerable = $False
        Write-Host "[-] " -NoNewLine -ForeGroundColor Red ; Write-Host "$($os_name) is not vulnerable."
    }
    if ($Verbose) { Write-Host "" }
    if ($Verbose) { Write-Host -NoNewLine -ForeGroundColor Blue "[*] " ; Write-Host "Checking IKEEXT service status and start mode" }
    $service = Get-Service -Name "IKEEXT"
    if ($service.Status -eq "Running") {
        if ($Verbose) { Write-Host "[*] " -NoNewLine -ForeGroundColor Blue ; Write-Host "|__ Service status: Running" }
    }
    else {
        if ($Verbose) { Write-Host "[*] " -NoNewLine -ForeGroundColor Blue ; Write-Host "|__ Service status: Not running" }
    }
    $start_mode = (Get-WmiObject -Query "Select StartMode From Win32_Service Where Name='IKEEXT'").StartMode
    if ($start_mode -eq "Auto") {
        if ($Verbose) { Write-Host "[*] " -NoNewLine -ForeGroundColor Blue ; Write-Host "|__ Service start mode: Auto" }
        Write-Host "[+] " -NoNewLine -ForeGroundColor Green ; Write-Host "IKEEXT is enabled."
    }
    elseif ($start_mode -eq "Manual") {
        if ($Verbose) { Write-Host "[*] " -NoNewLine -ForeGroundColor Blue ; Write-Host "|__ Service start mode: Manual" }
        Write-Host "[+] " -NoNewLine -ForeGroundColor Green ; Write-Host "IKEEXT is enabled."
    }
    else {
        $is_vulnerable = $False
        if ($Verbose) { Write-Host "[-] " -NoNewLine -ForeGroundColor Red ; Write-Host "|__ Service start mode: Disabled" }
        Write-Host "[-] " -NoNewLine -ForeGroundColor Red ; Write-Host "IKEEXT is not disabled."
    }
    if ($Verbose) { Write-Host "" }
    if ($Verbose) { Write-Host -NoNewLine -ForeGroundColor Blue "[*] " ; Write-Host "Searching for PATH folders with weak permissions" }
    $sys_env_path = ((Get-ItemProperty -Path Registry::"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name "Path").Path).Split("{;}")
    $vulnerable_folders = @()
    $final_string = @()
    For ($i = 1; $i -le 16; $i++) {
        $final_string += [CHAR][BYTE](get-random -min 97 -max 122)
    }
    $dummy_file = (-join $final_string) + ".txt"
    $sys_env_path | foreach {
        if ($_.length -gt 0) {
            $test_path = Test-Path -Path $_ -errorAction SilentlyContinue -errorVariable errors
            if ($errors.count -eq 0) {
                if ($test_path) {
                    $dummy_file_path = "$($_)\$($dummy_file)"
                    New-Item "$($dummy_file_path)" -Type file -ErrorAction SilentlyContinue -ErrorVariable errors | Out-Null
                    if ($errors.count -eq 0) {
                        $vulnerable_folders += $_
                        if ($Verbose) { Write-Host -NoNewLine -ForeGroundColor Green "[+] " ; Write-Host "|__ Access granted: '$_'" }
                        Remove-Item "$($dummy_file_path)"
                    }
                    else {
                        if ($Verbose) { Write-Host -NoNewLine -ForeGroundColor Red "[-] " ; Write-Host "|__ Access denied: '$_'" }
                    }
                }
                else {
                    if ($Verbose) { Write-Host -NoNewLine -ForeGroundColor Yellow "[!] " ; Write-Host "|__ Invalid path: '$_'" }
                }
            }
            else {
                if ($Verbose) { Write-Host -NoNewLine -ForeGroundColor Red "[-] " ; Write-Host "|__ Access denied: '$_'" }
            }
        }
    }
    if ($vulnerable_folders.count -ge 1) {
        Write-Host "[+] " -NoNewLine -ForeGroundColor Green ; Write-Host "Found $($vulnerable_folders.count) PATH folder(s) with weak permissions."
        $vulnerable_folders | foreach {
            Write-Host "[+] " -NoNewLine -ForeGroundColor Green ; Write-Host "|__ Found: '$($_)'"
        }
    }
    else {
        $is_vulnerable = $False
        Write-Host "[-] " -NoNewLine -ForeGroundColor Red ; Write-Host "Found $($vulnerable_folders.count) PATH folder(s) with weak permissions."
    }
    if ($Verbose) { Write-Host "" }
    if ($Verbose) { Write-Host -NoNewLine -ForeGroundColor Blue "[*] " ; Write-Host "Searching for 'wlbsctrl.dll' (DLL search Path only)" }
    $dll_files = @()
    $dll_files += Get-ChildItem -Path "C:\Windows\System32" -Filter "wlbsctrl.dll" -ErrorAction SilentlyContinue -Force
    $dll_files += Get-ChildItem -Path "C:\Windows\System" -Filter "wlbsctrl.dll" -ErrorAction SilentlyContinue -Force
    $dll_files += Get-ChildItem -Path "C:\Windows" -Filter "wlbsctrl.dll" -ErrorAction SilentlyContinue -Force
    $sys_env_path = ((Get-ItemProperty -Path Registry::"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name "Path").Path).Split("{;}")
    $sys_env_path | foreach {
        if ($_.length -gt 0) {
            if (Test-Path -ErrorAction SilentlyContinue $_) {
                $dll_files += Get-ChildItem -Path $_ -Filter "wlbsctrl.dll" -ErrorAction SilentlyContinue -Force
            }
        }
    }
    $dll_files_final = @()
    $dll_files | foreach { if (-not $_ -eq "") { $dll_files_final += $_ } }
    if ($dll_files_final.count -gt 0) {
        $dll_files_final | foreach {
            if ($Verbose) { Write-Host -NoNewLine -ForeGroundColor Blue "[*] " ; Write-Host "|__ Found file: '$($_.FullName)'" }
        }
        $is_vulnerable = $False
        Write-Host -NoNewLine -ForeGroundColor Red "[-] " ; Write-Host "'wlbsctrl.dll' was found." ;
    }
    else {
        Write-Host -NoNewLine -ForeGroundColor Green "[+] " ; Write-Host "'wlbsctrl.dll' wasn't found."
    }
    if ($Verbose) { Write-Host "" }
    if ($is_vulnerable) {
        Write-Host -NoNewLine -ForeGroundColor Green "[+] " ; Write-Host "Result: VULNERABLE`n"
        if ($PassThru) { return $vulnerable_folders }
    }
    else {
        Write-Host -NoNewLine -ForeGroundColor Red "[-] " ; Write-Host "Result: NOT VULNERABLE`n"
        if ($PassThru) { return @() }
    }
}
Invoke-IkeextCheck 
