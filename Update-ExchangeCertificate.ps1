function Update-ExchangeCertificate {
    <#
        .SYNOPSIS
        Update the certificate used by an Exchange server.

        .DESCRIPTION
        The Update-ExchangeCertificate function updates the certificate used by an Exchange
        server by importing a new certificate from an SMB share, assigning all services to the
        new certificate, updating the send connector with the new certificate, and removing the
        old certificate. It also provides the option to run in WhatIf and Confirm mode.

        .PARAMETER SmbSharePath
        Required. The path of the SMB share where the PFX file is located.

        .PARAMETER Fqdn
        Required. The fully qualified domain name of the certificate.

        .PARAMETER SmbShareUsername
        Required. The username used to access the SMB share.

        .PARAMETER SmbSharePassword
        Required. The password used to access the SMB share.

        .PARAMETER PfxPasswordHashPath
        Required. The path of the file containing the password hash for the PFX file.

        .PARAMETER Initiate
        Optional. A switch parameter to initiate the the hash files for the password.

        .PARAMETER WhatIf
        Optional. A switch parameter to simulate the update process.

        .PARAMETER Confirm
        Optional. A switch parameter to confirm the update process.

        .EXAMPLE
        Update-ExchangeCertificate -SmbSharePath \\fileshare\certs -Fqdn mail.contoso.com
        -SmbShareUsername user -SmbSharePassword (ConvertTo-SecureString -String 'P@ssw0rd'
        -AsPlainText -Force) -PfxPasswordHashPath C:\temp\pfxpassword.txt -Confirm
        This example updates the certificate used by an Exchange server by importing a new
        certificate from the \\fileshare\certs SMB share, using the username 'user' and
        password 'P@ssw0rd' to access the share, and the password hash file located at
        C:\temp\pfxpassword.txt for the PFX file. It also prompts for confirmation before
        proceeding with the update process.

        .NOTES
        This function uses the PSCredential, System.Management.Automation, and
        Import-PfxCertificate cmdlets.
    #>

    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory=$true)]
        [string]$SmbSharePath,
        [Parameter(Mandatory=$true)]
        [string]$Fqdn,
        [Parameter(Mandatory=$true)]
        [string]$SmbShareUsername,
        [Parameter()]
        $SmbPassword,
        [Parameter(Mandatory=$true)]
        [string]$SmbPasswordHashFilePath,
        [Parameter()]
        $pfxPassword,
        [Parameter(Mandatory=$true)]
        [string]$PfxPasswordHashPath,
        [switch]$Initiate
        #[switch]$WhatIf,
        #[switch]$Confirm
    )

    begin {
        # If the -Initiate switch is used, create a password hash file for the PFX certificate and a separate one for the SMB share, and then store them in the provided paths
        if ($Initiate) {
            if ($WhatIf) {
                Write-Warning "WhatIf: the PFX password and SMB share password would have been prompted for and stored in the specified files"
            } else {
                $SmbKeyFile = $SmbPasswordHashFilePath + '\SmbAes.key'
                $SmbKey = New-Object Byte[] 32
                [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($SmbKey)
                $SmbKey | out-file $SmbKeyFile

                $SmbPasswordFile = $SmbPasswordHashFilePath + '\SmbAesPassword.txt'
                #$KeyFile = "\\dc01\Share\powershell\AES.key"
                $SmbKey = Get-Content $SmbKeyFile
                $smbPassword = $smbPassword | ConvertTo-SecureString -AsPlainText -Force
                $smbPassword | ConvertFrom-SecureString -key $SmbKey | Out-File $SmbPasswordFile

                $PfxKeyFile = $SmbPasswordHashFilePath + '\PfxAes.key'
                $PfxKey = New-Object Byte[] 32
                [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($PfxKey)
                $PfxKey | out-file $PfxKeyFile

                $PfxPasswordFile = $SmbPasswordHashFilePath + '\PfxAesPassword.txt'
                #$KeyFile = "\\dc01\Share\powershell\AES.key"
                $PfxKey = Get-Content $PfxKeyFile
                $PfxPassword = $PfxPassword | ConvertTo-SecureString -AsPlainText -Force
                $PfxPassword | ConvertFrom-SecureString -key $PfxKey | Out-File $PfxPasswordFile
            }
        }

        #$User = "administrator@vsphere.local"
        #$PasswordFile = "\\dc01\Share\powershell\AESpassword.txt"
        #$KeyFile = "\\dc01\Share\powershell\AES.key"
        $SmbKeyFile = $SmbPasswordHashFilePath + '\SmbAes.key'
        $SmbPasswordFile = $SmbPasswordHashFilePath + '\SmbAesPassword.txt'
        $SmbKey = Get-Content $SmbKeyFile
        $smbCredentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $SmbShareUsername, (Get-Content $SmbPasswordFile | ConvertTo-SecureString -Key $SmbKey)

        #$User = "administrator@vsphere.local"
        #$PasswordFile = "\\dc01\Share\powershell\AESpassword.txt"
        #$KeyFile = "\\dc01\Share\powershell\AES.key"
        $PfxKeyFile = $SmbPasswordHashFilePath + '\PfxAes.key'
        $PfxPasswordFile = $SmbPasswordHashFilePath + '\PfxAesPassword.txt'
        $PfxKey = Get-Content $PfxKeyFile
        $PfxCredentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList user,(Get-Content $PfxPasswordFile | ConvertTo-SecureString -Key $PfxKey)

        $CompletePfxFilePath = $SmbSharePath + '\' + $Fqdn + '.pfx'

        # Connecting to the Exchange PowerShell
        #$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://$env:COMPUTERNAME/PowerShell/ -Authentication Kerberos
        #Import-PSSession $Session -DisableNameChecking
        #Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn

        . 'D:\Microsoft Exchange\Bin\RemoteExchange.ps1'
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
    }
    process {
        try {
            # Connect to the SMB share and get the PFX certificate
            New-PSDrive -Name P -PSProvider FileSystem -Root $SmbSharePath -Credential $VIcred
            #New-SmbMapping -LocalPath "Y:" -RemotePath $SmbSharePath -UserName $SmbShareUsername -Password $decryptedPw
            #New-SmbSession -Credential $smbCredentials -RemotePath $SmbSharePath

            if(!(Test-Path -Path $SmbSharePath))
            {
                Write-Host -ForegroundColor Red "SMB Share not accessible"
                return
            }
            
            if(!(Test-Path -Path $CompletePfxFilePath)) {
                Write-Host -ForegroundColor Red "The specified PFX file does not exist"
                return
            }

            # Import the new certificate to the Exchange server
            if(!$WhatIf){
                if ($Confirm -and !(ShouldContinue("Are you sure you want to update the Exchange certificate?","Confirm Update") )){
                    return
                }
                $pfxCertificate = Import-PfxCertificate -FilePath $CompletePfxFilePath -CertStoreLocation Cert:\LocalMachine\My -Password $PfxCredentials.Password
                
                # Store the thumbprint of the existing certificate
                $existingCertificateThumbprint = (Get-ExchangeCertificate | Where-Object {$_.Subject -eq $pfxCertificate.Subject -and $_.Thumbprint -ne $pfxCertificate.Thumbprint}).Thumbprint
                
                # Store the assigned services of the existing certificate
                $existingCertificateServices = (Get-ExchangeCertificate -Thumbprint $existingCertificateThumbprint).Services
                
                if ($WhatIf -or ($Confirm -and !(ShouldProcess("Updating the Exchange certificate","Updating the Exchange certificate") ))){
                    return
                }
                # Assign all services to the new certificate
                if($PSCmdlet.ShouldProcess("Assign all services to the new certificate")) {
                    Enable-ExchangeCertificate -Thumbprint $pfxCertificate.Thumbprint -Services $existingCertificateServices -Force -Confirm:$false
                }
                
                # Update the send connector with the new certificate
                $sendConnector = Get-SendConnector -Identity "Outbound to Office 365*"
                
                if($PSCmdlet.ShouldProcess("Updating the sendConnector with the new certificate")) {
                    $TLSCertName = "<I>$($pfxCertificate.Issuer)<S>$($pfxCertificate.Subject)"
                    Set-SendConnector -Identity $sendConnector.Identity -TlsCertificateName $TLSCertName

                    $ReceiveConnectors = Get-ReceiveConnector | Where-Object { $_.TlsCertificateName -eq $TLSCertName }
                    foreach ($ReceiveConnector in $ReceiveConnectors) {
                        Set-ReceiveConnector -Identity $ReceiveConnector.Identity -TlsCertificateName $TLSCertName
                    }
                }
                
                # Remove the old certificate
                if($PSCmdlet.ShouldProcess("Removing the old certificate")) {
                    #Remove-ExchangeCertificate -Thumbprint $existingCertificateThumbprint -Confirm:$Confirm
                    Get-Item -Path Cert:\LocalMachine\My\$existingCertificateThumbprint | Remove-Item
                }

                # load in the admin scripts for doing stuff with IIS:
                Import-Module Webadministration
                # fetch the default web site:
                $site = Get-ChildItem -Path "IIS:\Sites" | where {( $_.Name -eq "Default Web Site" )}

                $bindings = $site.Bindings.Collection | Where-Object {( $_.protocol -eq 'https' -and $_.bindingInformation -like '*:443:*')}

                foreach ($binding in $bindings) {
                    $binding.AddSslCertificate($pfxCertificate.Thumbprint, "my")
                }

                Get-Service W3SVC | Restart-Service
            }
        } catch {
            Write-Host -ForegroundColor Red "An error occurred: $($_.Exception.Message)"
        }
    }
    end {}
}
