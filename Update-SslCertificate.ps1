function Update-SslCertificate {
    <#
        .SYNOPSIS
        The Update-SslCertificate function updates the SSL certificate the server where it is
        executed server by accessing an SMB share and the corresponding certificate file.

        .DESCRIPTION
        The Update-SslCertificate function takes parameters for the SMB share path, FQDN,
        SMB share username, SMB password, SMB password hash file path, PFX password, PFX
        password hash path, and a switch to initiate password hash file creation. If the
        initiate switch is used, AES-encrypted password hash files are created and stored in
        the specified paths for both the SMB share and the PFX file. The function also creates
        secure strings for the SMB credentials and PFX password by using AES encryption to
        access the required resources. 

        .PARAMETER SmbSharePath
        The mandatory string parameter for the SMB share path.

        .PARAMETER Fqdn
        The mandatory string parameter for the FQDN of the Exchange server.

        .PARAMETER SmbShareUsername
        The mandatory string parameter for the username for the SMB share.

        .PARAMETER SmbPassword
        An optional parameter for the password for the SMB share.

        .PARAMETER SmbPasswordHashFilePath
        The mandatory string parameter for the path to the SMB password hash file.

        .PARAMETER pfxPassword
        An optional parameter for the password for the PFX file.

        .PARAMETER PfxPasswordHashPath
        The mandatory string parameter for the path to the PFX password hash file.

        .PARAMETER Initiate
        The mandatory switch parameter to initiate password hash file creation.

        .EXAMPLE
        Update-SslCertificate -SmbSharePath \\server\share -Fqdn exchange.contoso.com
        -SmbShareUsername user1 -SmbPassword secret -SmbPasswordHashFilePath C:\hashfiles
        -PfxPassword secret123 -PfxPasswordHashPath C:\hashfiles -Initiate

        In this example, the Update-SslCertificate function is executed with parameters
        for the SMB share path, FQDN, SMB share username, SMB password, SMB password hash file
        path, PFX password, PFX password hash path, and initiate switch. The function will
        create AES-encrypted password hash files for both the SMB share and the PFX file, and
        use them to securely access the required resources.

        .NOTES
        The AES encryption used in this function is a basic implementation for demonstration
        purposes only and should not be used in a production environment without additional
        security measures.
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
        [switch]$Initiate,
        [switch]$ExchangeServer,
        [switch]$AbacusServer,
        [switch]$MobotixServer
        #[switch]$WhatIf,
        #[switch]$Confirm
    )

    begin {
        # If the -Initiate switch is used, create a password hash file for the PFX certificate
        # and a separate one for the SMB share, and then store them in the provided paths
        if ($Initiate) {
            if ($WhatIf) {
                Write-Warning "WhatIf: The Update-SslCertificate function updates the SSL certificate the server where it is executed server by accessing an SMB share and the corresponding certificate file."
            } else {
                # This part checks if only one of the additional statements are equal to true.
                # When you need to add more statement only add the corresponding parameters.
                # Here is an example with three statements:
                # if (($ExchangeServer -eq $true -and $AbacusServer -ne $true -and $sharepoint -ne $true) -or ($ExchangeServer -ne $true -and $AbacusServer -eq $true -and $sharepoint -ne $true) -or ($ExchangeServer -ne $true -and $AbacusServer -ne $true -and $sharepoint -eq $true)) {
                # if (($ExchangeServer -eq $true -and $AbacusServer -ne $true) -or ($ExchangeServer -ne $true -and $AbacusServer -eq $true)) {
                    if (($ExchangeServer -eq $true -and $AbacusServer -ne $true -and $MobotixServer -ne $true) -or ($ExchangeServer -ne $true -and $AbacusServer -eq $true -and $MobotixServer -ne $true) -or ($ExchangeServer -ne $true -and $AbacusServer -ne $true -and $MobotixServer -eq $true)) {
                    # This part checks if the $WhatIf variable is set to true. If it is, a warning
                    # message is written indicating that the PFX password and SMB share password would
                    # have been prompted for and stored in the specified files.

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
                    
                    if ($ExchangeServer -or $MobotixServer) {
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
                        if (!$PfxPassword) {
                            Write-Error "Error: PfxPassword is not set."
                            return
                        }
                        else {
                            $PfxPassword = $PfxPassword | ConvertTo-SecureString -AsPlainText -Force
                            $PfxPassword | ConvertFrom-SecureString -key $PfxKey | Out-File $PfxPasswordFile
                        }

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

                        # This is loading the RemoteExchange.ps1 script and adding the Microsoft Exchange
                        # Management PowerShell Snap-in.
                        . 'D:\Microsoft Exchange\Bin\RemoteExchange.ps1'
                        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn

                        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "& 'C:\scripts\Update-SslCertificate.ps1'; Update-SslCertificate -SmbSharePath $($SmbSharePath) -Fqdn $($Fqdn) -SmbShareUsername $($SmbShareUsername) -SmbPasswordHashFilePath $($SmbPasswordHashFilePath) -ExchangeServer"
                    }
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

            $trigger = New-ScheduledTaskTrigger -Daily -At "00:00"
            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel "Highest"
            $settings = New-ScheduledTaskSettingsSet

            Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "Update-SslCertificate" -Description "It Updates the ssl certificate of the specified server type" -Principal $principal -Settings $settings
        }
    }
    process {
        try {
            if(!$WhatIf) {
                # This part creates a new PowerShell drive with the name "P". The drive is created
                # using the FileSystem provider and the root path is set to the value of the
                # $SmbSharePath variable. The -Credential parameter is used to provide the
                # credentials to access the share path, which are stored in the $VIcred variable.
                New-PSDrive -Name P -PSProvider FileSystem -Root $SmbSharePath -Credential $smbCredentials

                # This checks if the SMB Share is accessible and returns an error message in red
                # if not.
                if(!(Test-Path -Path $SmbSharePath))
                {
                    Write-Host -ForegroundColor Red "SMB Share not accessible"
                    return
                }

                $ConvertedFile = $SmbSharePath + '\' + $Fqdn + '.converted'
                If($ConvertedFile) {
                    # This part checks if the $AbacusServer parameter was passed to the script. If
                    # it was, then this code block will be executed.
                    if ($AbacusServer) {
                        # Import the new certificate to the Abacus server
                        
                        # This part creates a variable named $CompleteCrtFilePath and assigns it a
                        # value that is the concatenation of the string value stored in
                        # $SmbSharePath, a backslash, and the string value stored in $Fqdn with
                        # '.crt' appended to the end.
                        $CompleteCrtFilePath = $SmbSharePath + '\' + $Fqdn + '.crt'

                        # This part creates a variable named $CompleteKeyFilePath and assigns it a
                        # value that is the concatenation of the string value stored in
                        # $SmbSharePath, a backslash, and the string value stored in $Fqdn with
                        # '.key' appended to the end.
                        $CompleteKeyFilePath = $SmbSharePath + '\' + $Fqdn + '.key'

                        # This checks if the specified crt file exists in the SMB Share and returns
                        # an error message in red if not.
                        if(!(Test-Path -Path $CompleteCrtFilePath)) {
                            Write-Host -ForegroundColor Red "The specified CRT file does not exist"
                            return
                        }

                        # This checks if the specified key file exists in the SMB Share and returns
                        # an error message in red if not.
                        if(!(Test-Path -Path $CompleteKeyFilePath)) {
                            Write-Host -ForegroundColor Red "The specified KEY file does not exist"
                            return
                        }

                        # This part checks for the confirmation of the update of the Abacus
                        # certificate:
                        # If the Confirm parameter is set to true and the result of the
                        # ShouldContinue method is false, then the script will return.
                        if ($Confirm -and !(ShouldContinue("Are you sure you want to update the Abacus certificate?","Confirm Update") )){
                            return
                        }

                        # $AbacusDestionFolder is assigned the value of the destination folder
                        # where the certificate and key files will be copied.
                        $AbacusDestionFolder = 'D:\abac\kd\cert\private'
                        
                        # $CrtFileName is assigned the value of the certificate file name. The
                        # file name is obtained by splitting the complete path of the certificate
                        # file using the Split-Path cmdlet with the Leaf parameter. 
                        $CrtFileName = Split-Path $CompleteCrtFilePath -Leaf
                        
                        # $CompleteDestinationCrtFilePath is assigned the complete destination
                        # path for the certificate file by concatenating the destination folder and
                        # the certificate file name.
                        $CompleteDestinationCrtFilePath = $AbacusDestionFolder + '\' + $CrtFileName
                        
                        # $KeyFileName is assigned the value of the key file name. The file name
                        # is obtained by splitting the complete path of the key file using the
                        # Split-Path cmdlet with the Leaf parameter.
                        # $CompleteDestinationKeyFilePath is assigned the complete destination path for the key file by concatenating the destination folder and the key file name.
                        $KeyFileName = Split-Path $CompleteKeyFilePath -Leaf
                        
                        # $CompleteDestinationKeyFilePath is assigned the complete destination path for the key file by concatenating the destination folder and the key file name.
                        $CompleteDestinationKeyFilePath = $AbacusDestionFolder + '\' + $KeyFileName

                        # If a certificate file already exists in the destination folder, it will
                        # be renamed with a ".bak" extension. The check for the existence of the
                        # file is done using the Test-Path cmdlet. If the file exists, the
                        # Rename-Item cmdlet is used to rename it.
                        if (Test-Path $CompleteDestinationCrtFilePath) {
                            Rename-Item $CompleteDestinationCrtFilePath -NewName "$($CompleteDestinationCrtFilePath + '.bak')"
                        }
                        
                        # If a key file already exists in the destination folder, it will be
                        # renamed with a ".bak" extension. The check for the existence of the file
                        # is done using the Test-Path cmdlet. If the file exists, the Rename-Item
                        # cmdlet is used to rename it.
                        if (Test-Path $CompleteDestinationKeyFilePath) {
                            Rename-Item $CompleteDestinationKeyFilePath -NewName "$($CompleteDestinationKeyFilePath + '.bak')"
                        }

                        # The certificate file is copied from its original location to the
                        # destination folder using the Copy-Item cmdlet.
                        Copy-Item $CompleteCrtFilePath -Destination $AbacusDestionFolder
                        
                        # The key file is copied from its original location to the destination
                        # folder using the Copy-Item cmdlet.
                        Copy-Item $CompleteKeyFilePath -Destination $AbacusDestionFolder
                        
                        # This part invokes the servicemanagerconsole.exe application with the /certificate switch and the path to the certificate file.
                        Invoke-Expression "& 'D:\abac\df_win64\servicemanagerconsole.exe /certificate=$($CompleteDestinationCrtFilePath)'"

                        # This part invokes the servicemanagerconsole.exe application with the /privatecertificate /certificate switches and the path to the key file.
                        Invoke-Expression "& 'D:\abac\df_win64\servicemanagerconsole.exe /privatecertificate /certificate=$($CompleteDestinationKeyFilePath)'"
                    }

                    # This part checks if the $ExchangeServer parameter was passed to the script. If
                    # it was, then this code block will be executed.
                    if ($ExchangeServer) {
                        # Import the new certificate to the Exchange server
                        if(!$WhatIf){
                            # This part creates a variable named $CompletePfxFilePath and assigns it a
                            # value that is the concatenation of the string value stored in
                            # $SmbSharePath, a backslash, and the string value stored in $Fqdn with
                            # '.pfx' appended to the end.
                            $CompletePfxFilePath = $SmbSharePath + '\' + $Fqdn + '.pfx'
                            
                            # This checks if the specified pfx file exists in the SMB Share and returns an
                            # error message in red if not.
                            if(!(Test-Path -Path $CompletePfxFilePath)) {
                                Write-Host -ForegroundColor Red "The specified PFX file does not exist"
                                return
                            }

                            # This part checks for the confirmation of the update of the Exchange
                            # certificate:
                            # If the Confirm parameter is set to true and the result of the
                            # ShouldContinue method is false, then the script will return.
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
                            # thumbprint. The result is stored in the $existingCertificateServices
                            # variable.
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
                    }

                    # This part checks if the $MobotixServer parameter was passed to the script. If
                    # it was, then this code block will be executed.
                    if ($MobotixServer) {
                        # Import the new certificate to the Mobotix server
                        if(!$WhatIf){
                            # This part creates a variable named $CompletePfxFilePath and assigns it a
                            # value that is the concatenation of the string value stored in
                            # $SmbSharePath, a backslash, and the string value stored in $Fqdn with
                            # '.pfx' appended to the end.
                            $CompletePfxFilePath = $SmbSharePath + '\' + $Fqdn + '.pfx'
                            
                            # This checks if the specified pfx file exists in the SMB Share and returns an
                            # error message in red if not.
                            if(!(Test-Path -Path $CompletePfxFilePath)) {
                                Write-Host -ForegroundColor Red "The specified PFX file does not exist"
                                return
                            }

                            # This part checks for the confirmation of the update of the Mobotix
                            # certificate:
                            # If the Confirm parameter is set to true and the result of the
                            # ShouldContinue method is false, then the script will return.
                            if ($Confirm -and !(ShouldContinue("Are you sure you want to update the Mobotix certificate?","Confirm Update") )){
                                return
                            }

                            # This part imports the PFX certificate file into the local machine's "My"
                            # certificate store using the specified password:
                            # The PFX certificate file is imported using the Import-PfxCertificate cmdlet
                            # with the file path, certificate store location, and password as parameters.
                            $pfxCertificate = Import-PfxCertificate -FilePath $CompletePfxFilePath -CertStoreLocation Cert:\LocalMachine\My -Password $PfxCredentials.Password
                            
                            # This part retrieves the thumbprint of an existing certificate in the
                            # Mobotix with the same subject as the newly imported PFX certificate:
                            # The Get-ChildItem cmdlet is used to retrieve all certificates in
                            # the Exchange. The Where-Object cmdlet is used to filter out the certificate
                            # that has the same subject as the newly imported PFX certificate and a
                            # different thumbprint. The resulting thumbprint is stored in the
                            # $existingCertificateThumbprint variable.
                            $existingCertificateThumbprint = (Get-ChildItem | Where-Object {$_.Subject -eq $pfxCertificate.Subject -and $_.Thumbprint -ne $pfxCertificate.Thumbprint}).Thumbprint
                            
                            # This part checks for the confirmation or WhatIf parameter before updating
                            # the Exchange certificate:
                            # If the WhatIf parameter is set or the Confirm parameter is set to true and
                            # the result of the ShouldProcess method is false, then the script will return.
                            if ($WhatIf -or ($Confirm -and !(ShouldProcess("Updating the Mobotix certificate","Updating the Mobotix certificate") ))){
                                return
                            }
                            # This part checks if the ShouldProcess method should execute for assigning all
                            # services to the new certificate. If it does, it uses the
                            # Enable-ExchangeCertificate cmdlet to assign the services to the new
                            # certificate with the specified thumbprint, using the Force parameter and
                            # Confirm parameter set to false.
                            if($PSCmdlet.ShouldProcess("Assign all services to the new certificate")) {
                                & "C:\Program Files\MOBOTIX\Server Configurator\ServerConfigurator.exe" /enableencryption /certificategroup=76cfc719-a852-4210-913e-703eadab139a /thumbprint=$pfxCertificate.Thumbprint
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
                    }
                    
                    Remove-Item -Path $ConvertedFile -Force -Confirm:$false
                }
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
