function Update-ExchangeCertificate {
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
            # This part checks if the $WhatIf variable is set to true. If it is, a warning
            # message is written indicating that the PFX password and SMB share password would
            # have been prompted for and stored in the specified files.
            if ($WhatIf) {
                Write-Warning "WhatIf: the PFX password and SMB share password would have been prompted for and stored in the specified files"
            } else {
                # This part generates a random 32-byte AES key and stores it in a file named
                # "SmbAes.key" in the directory specified by the $SmbPasswordHashFilePath
                # variable.
                $SmbKeyFile = $SmbPasswordHashFilePath + '\SmbAes.key'
                $SmbKey = New-Object Byte[] 32
                [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($SmbKey)
                $SmbKey | out-file $SmbKeyFile

                # This part converts the SMB password to a secure string, then encrypts the
                # secure string using the AES key from the previous step and stores it in a
                # file named "SmbAesPassword.txt" in the specified directory.
                $SmbPasswordFile = $SmbPasswordHashFilePath + '\SmbAesPassword.txt'
                $SmbKey = Get-Content $SmbKeyFile
                $smbPassword = $smbPassword | ConvertTo-SecureString -AsPlainText -Force
                $smbPassword | ConvertFrom-SecureString -key $SmbKey | Out-File $SmbPasswordFile

                # This part generates another random 32-byte AES key and stores it in a file
                # named "PfxAes.key" in the specified directory.
                $PfxKeyFile = $SmbPasswordHashFilePath + '\PfxAes.key'
                $PfxKey = New-Object Byte[] 32
                [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($PfxKey)
                $PfxKey | out-file $PfxKeyFile

                # This part converts the PFX password to a secure string, then encrypts the
                # secure string using the AES key from the previous step and stores it in a
                # file named "PfxAesPassword.txt" in the specified directory.
                $PfxPasswordFile = $SmbPasswordHashFilePath + '\PfxAesPassword.txt'
                $PfxKey = Get-Content $PfxKeyFile
                $PfxPassword = $PfxPassword | ConvertTo-SecureString -AsPlainText -Force
                $PfxPassword | ConvertFrom-SecureString -key $PfxKey | Out-File $PfxPasswordFile
            }
        }

        # This part creates a secure string for SMB credentials by using AES encryption. The
        # $SmbKeyFile variable is created by combining the file path in
        # $SmbPasswordHashFilePath and the file name 'SmbAes.key'. The $SmbPasswordFile
        # variable is created in the same manner, but with a different file name. The AES key
        # is then retrieved using the Get-Content cmdlet on $SmbKeyFile and stored in the
        # $SmbKey variable. Finally, the SMB credentials are created using the New-Object
        # cmdlet with the System.Management.Automation.PSCredential type and the arguments
        # $SmbShareUsername and the secure string created from the contents of the
        # $SmbPasswordFile and encrypted with the $SmbKey.
        $SmbKeyFile = $SmbPasswordHashFilePath + '\SmbAes.key'
        $SmbPasswordFile = $SmbPasswordHashFilePath + '\SmbAesPassword.txt'
        $SmbKey = Get-Content $SmbKeyFile
        $smbCredentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $SmbShareUsername, (Get-Content $SmbPasswordFile | ConvertTo-SecureString -Key $SmbKey)

        # This part creates a secure string for PFX credentials by using AES encryption. The
        # $PfxKeyFile variable is created by combining the file path in
        # $SmbPasswordHashFilePath and the file name 'PfxAes.key'. The $PfxPasswordFile
        # variable is created in the same manner, but with a different file name. The AES key
        # is then retrieved using the Get-Content cmdlet on $PfxKeyFile and stored in the
        # $PfxKey variable. Finally, the PFX credentials are created using the New-Object
        # cmdlet with the System.Management.Automation.PSCredential type and the arguments
        # "user" and the secure string created from the contents of the $PfxPasswordFile and
        # encrypted with the $PfxKey.
        $PfxKeyFile = $SmbPasswordHashFilePath + '\PfxAes.key'
        $PfxPasswordFile = $SmbPasswordHashFilePath + '\PfxAesPassword.txt'
        $PfxKey = Get-Content $PfxKeyFile
        $PfxCredentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList user,(Get-Content $PfxPasswordFile | ConvertTo-SecureString -Key $PfxKey)

        # This sets the variable $CompletePfxFilePath to the path of the pfx file stored in
        # the SMB Share, using the concatenation of the SMB Share path, backslash, and the
        # fully-qualified domain name of the certificate.
        $CompletePfxFilePath = $SmbSharePath + '\' + $Fqdn + '.pfx'

        # This is loading the RemoteExchange.ps1 script and adding the Microsoft Exchange
        # Management PowerShell Snap-in.
        . 'D:\Microsoft Exchange\Bin\RemoteExchange.ps1'
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
    }
    process {
        try {
            # This part creates a new PowerShell drive with the name "P". The drive is created
            # using the FileSystem provider and the root path is set to the value of the
            # $SmbSharePath variable. The -Credential parameter is used to provide the
            # credentials to access the share path, which are stored in the $VIcred variable.
            New-PSDrive -Name P -PSProvider FileSystem -Root $SmbSharePath -Credential $VIcred

            # This checks if the SMB Share is accessible and returns an error message in red
            # if not.
            if(!(Test-Path -Path $SmbSharePath))
            {
                Write-Host -ForegroundColor Red "SMB Share not accessible"
                return
            }
            
            # This checks if the specified pfx file exists in the SMB Share and returns an
            # error message in red if not.
            if(!(Test-Path -Path $CompletePfxFilePath)) {
                Write-Host -ForegroundColor Red "The specified PFX file does not exist"
                return
            }

            # Import the new certificate to the Exchange server
            if(!$WhatIf){
                # This part checks for the confirmation of the update of the Exchange
                # certificate:
                # If the Confirm parameter is set to true and the result of the ShouldContinue
                # method is false, then the script will return.
                if ($Confirm -and !(ShouldContinue("Are you sure you want to update the Exchange certificate?","Confirm Update") )){
                    return
                }

                # This part imports the PFX certificate file into the local machine's "My"
                # certificate store using the specified password:
                # The PFX certificate file is imported using the Import-PfxCertificate cmdlet
                # with the file path, certificate store location, and password as parameters.
                $pfxCertificate = Import-PfxCertificate -FilePath $CompletePfxFilePath -CertStoreLocation Cert:\LocalMachine\My -Password $PfxCredentials.Password
                
                # This part retrieves the thumbprint of an existing certificate in the
                # Exchange with the same subject as the newly imported PFX certificate:
                # The Get-ExchangeCertificate cmdlet is used to retrieve all certificates in
                # the Exchange. The Where-Object cmdlet is used to filter out the certificate
                # that has the same subject as the newly imported PFX certificate and a
                # different thumbprint. The resulting thumbprint is stored in the
                # $existingCertificateThumbprint variable.
                $existingCertificateThumbprint = (Get-ExchangeCertificate | Where-Object {$_.Subject -eq $pfxCertificate.Subject -and $_.Thumbprint -ne $pfxCertificate.Thumbprint}).Thumbprint
                
                # This part retrieves the services of the existing certificate in the Exchange
                # with the specified thumbprint:
                # The Get-ExchangeCertificate cmdlet is used with the Thumbprint parameter to
                # retrieve the services of the existing certificate with the specified
                # thumbprint. The result is stored in the $existingCertificateServices variable.
                $existingCertificateServices = (Get-ExchangeCertificate -Thumbprint $existingCertificateThumbprint).Services
                
                # This part checks for the confirmation or WhatIf parameter before updating
                # the Exchange certificate:
                # If the WhatIf parameter is set or the Confirm parameter is set to true and
                # the result of the ShouldProcess method is false, then the script will return.
                if ($WhatIf -or ($Confirm -and !(ShouldProcess("Updating the Exchange certificate","Updating the Exchange certificate") ))){
                    return
                }
                # This part checks if the ShouldProcess method should execute for assigning all
                # services to the new certificate. If it does, it uses the
                # Enable-ExchangeCertificate cmdlet to assign the services to the new
                # certificate with the specified thumbprint, using the Force parameter and
                # Confirm parameter set to false.
                if($PSCmdlet.ShouldProcess("Assign all services to the new certificate")) {
                    Enable-ExchangeCertificate -Thumbprint $pfxCertificate.Thumbprint -Services $existingCertificateServices -Force -Confirm:$false
                }
                
                # This part retrieves the send connector with the identity "Outbound to Office
                # 365*" using the Get-SendConnector cmdlet.
                $sendConnector = Get-SendConnector -Identity "Outbound to Office 365*"
                
                # It checks if the "ShouldProcess" method is true for the message "Updating the
                # sendConnector with the new certificate". This method is used to determine if
                # the user has confirmed the operation.
                # If the ShouldProcess method returns true, the script assigns a value to the
                # variable $TLSCertName using the values of $pfxCertificate.Issuer and
                # $pfxCertificate.Subject.
                # The Set-SendConnector cmdlet is then used to update the send connector with
                # the new certificate by setting its identity and TlsCertificateName to the
                # value of $TLSCertName.
                # The script then retrieves a list of receive connectors that have the same
                # TlsCertificateName as the newly updated send connector by using the
                # Get-ReceiveConnector cmdlet and filtering with the Where-Object cmdlet.
                # Finally, the script loops through each receive connector in the list and
                # updates its TlsCertificateName to the new value of $TLSCertName using the
                # Set-ReceiveConnector cmdlet.
                if($PSCmdlet.ShouldProcess("Updating the sendConnector with the new certificate")) {
                    $TLSCertName = "<I>$($pfxCertificate.Issuer)<S>$($pfxCertificate.Subject)"
                    Set-SendConnector -Identity $sendConnector.Identity -TlsCertificateName $TLSCertName

                    $ReceiveConnectors = Get-ReceiveConnector | Where-Object { $_.TlsCertificateName -eq $TLSCertName }
                    foreach ($ReceiveConnector in $ReceiveConnectors) {
                        Set-ReceiveConnector -Identity $ReceiveConnector.Identity -TlsCertificateName $TLSCertName
                    }
                }
                
                # This part of the code checks if the process of removing the old certificate
                # is approved by the user. If approved, it removes the old certificate using
                # the Remove-Item command with the specified thumbprint.
                if($PSCmdlet.ShouldProcess("Removing the old certificate")) {
                    Get-Item -Path Cert:\LocalMachine\My\$existingCertificateThumbprint | Remove-Item
                }

                # This part of the code imports the Webadministration module which provides
                # management functionalities for Internet Information Services (IIS).
                Import-Module Webadministration
                
                # This part of the code retrieves the Default Web Site from IIS, finds the
                # https bindings on port 443, and assigns the new certificate (specified by
                # its thumbprint) to those bindings using the AddSslCertificate method.
                $site = Get-ChildItem -Path "IIS:\Sites" | where {( $_.Name -eq "Default Web Site" )}
                $bindings = $site.Bindings.Collection | Where-Object {( $_.protocol -eq 'https' -and $_.bindingInformation -like '*:443:*')}
                foreach ($binding in $bindings) {
                    $binding.AddSslCertificate($pfxCertificate.Thumbprint, "my")
                }

                # This part of the code restarts the World Wide Web Publishing Service (W3SVC)
                # using the Restart-Service command.
                Get-Service W3SVC | Restart-Service
            }
        } catch {
            # This part of the code writes an error message to the console if there was an
            # exception during the execution of the code. The error message is displayed in
            # red color.
            Write-Host -ForegroundColor Red "An error occurred: $($_.Exception.Message)"
        }
    }
    end {}
}
