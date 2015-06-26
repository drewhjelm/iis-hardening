function Set-IISSecurity {

	$appcmd = $($env:windir + "\system32\inetsrv\appcmd.exe")

	#remove IIS server information
	#http://stackoverflow.com/questions/1178831/remove-server-response-header-iis7/12615970#12615970

	Write-Output 'Removing IIS and ASP.NET Server identification...'
	Write-Output '--------------------------------------------------------------------------------'
	& $appcmd set config  -section:system.webServer/rewrite/outboundRules /+"[name='Remove_RESPONSE_Server']" /commit:apphost
	& $appcmd set config  -section:system.webServer/rewrite/outboundRules "/[name='Remove_RESPONSE_Server'].patternSyntax:`"Wildcard`""  /commit:apphost
	& $appcmd set config  -section:system.webServer/rewrite/outboundRules "/[name='Remove_RESPONSE_Server'].match.serverVariable:'RESPONSE_Server'" "/[name='Remove_RESPONSE_Server'].match.pattern:`"*`"" /commit:apphost
	& $appcmd set config  -section:system.webServer/rewrite/outboundRules "/[name='Remove_RESPONSE_Server'].action.type:`"Rewrite`"" "/[name='Remove_RESPONSE_Server'].action.value:`" `""  /commit:apphost

	& $appcmd set config /section:httpProtocol "/-customHeaders.[name='X-Powered-By']"

	#Enable HTTPS only redirect and add HSTS header
	#https://www.owasp.org/index.php/HTTP_Strict_Transport_Security#IIS

	#Set HTTPS Only redirect
	Write-Output 'Setting HTTPS Only'
	Write-Output '--------------------------------------------------------------------------------'
	& $appcmd set config  -section:system.webServer/rewrite/rules /+"[name='HTTPS_301_Redirect',stopProcessing='False']" /commit:apphost
	& $appcmd set config  -section:system.webServer/rewrite/rules "/[name='HTTPS_301_Redirect',stopProcessing='False'].match.url:`"(.*)`""  /commit:apphost
	& $appcmd set config  -section:system.webServer/rewrite/rules "/+[name='HTTPS_301_Redirect',stopProcessing='False'].conditions.[input='{HTTPS}',pattern='off']" /commit:apphost
	& $appcmd set config  -section:system.webServer/rewrite/rules "/[name='HTTPS_301_Redirect',stopProcessing='False'].action.type:`"Redirect`"" "/[name='HTTPS_301_Redirect',stopProcessing='False'].action.url:`"https://{HTTP_HOST}{REQUEST_URI}`""  /commit:apphost


	#HSTS header
	Write-Output 'Configuring HSTS header...'
	Write-Output '--------------------------------------------------------------------------------'
	#precondition for HSTS header
	& $appcmd set config  -section:system.webServer/rewrite/outboundRules /+"preConditions.[name='USING_HTTPS']" /commit:apphost
	& $appcmd set config  -section:system.webServer/rewrite/outboundRules /"+preConditions.[name='USING_HTTPS'].[input='{HTTPS}',pattern='on']" /commit:apphost

	#set header
	& $appcmd set config  -section:system.webServer/rewrite/outboundRules /+"[name='Add_HSTS_Header',preCondition='USING_HTTPS']" /commit:apphost
	& $appcmd set config  -section:system.webServer/rewrite/outboundRules "/[name='Add_HSTS_Header'].patternSyntax:`"Wildcard`""  /commit:apphost
	& $appcmd set config  -section:system.webServer/rewrite/outboundRules "/[name='Add_HSTS_Header',preCondition='USING_HTTPS'].match.serverVariable:`"RESPONSE_Strict-Transport-Security`"" "/[name='Add_HSTS_Header',preCondition='USING_HTTPS'].match.pattern:`"*`"" /commit:apphost
	& $appcmd set config  -section:system.webServer/rewrite/outboundRules "/[name='Add_HSTS_Header',preCondition='USING_HTTPS'].action.type:`"Rewrite`"" "/[name='Add_HSTS_Header',preCondition='USING_HTTPS'].action.value:`"max-age=31536000`""  /commit:apphost

	#prevent framejacking
	#https://support.microsoft.com/en-us/kb/2694329
	& $appcmd set config -section:httpProtocol "/+customHeaders.[name='X-Frame-Options',value='SAMEORIGIN']"

	#Improve SSL ciphers, add PFS, disable SSLv3
	#https://www.hass.de/content/setup-your-iis-ssl-perfect-forward-secrecy-and-tls-12
	 
	Write-Output 'Configuring IIS with SSL/TLS Deployment Best Practices...'
	Write-Output '--------------------------------------------------------------------------------'
	 
	# Disable Multi-Protocol Unified Hello
	New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -Force | Out-Null
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
	Write-Output 'Multi-Protocol Unified Hello has been disabled.'
	 
	# Disable PCT 1.0
	New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -Force | Out-Null
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
	Write-Output 'PCT 1.0 has been disabled.'
	 
	# Disable SSL 2.0 (PCI Compliance)
	New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Force | Out-Null
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
	Write-Output 'SSL 2.0 has been disabled.'
	 
	# NOTE: If you disable SSL 3.0 the you may lock out some people still using
	# Windows XP with IE6/7. Without SSL 3.0 enabled, there is no protocol available
	# for these people to fall back. Safer shopping certifications may require that
	# you disable SSLv3.
	#
	# Disable SSL 3.0 (PCI Compliance) and enable "Poodle" protection
	New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Force | Out-Null
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
	Write-Output 'SSL 3.0 has been disabled.'
	 
	# Add and Enable TLS 1.0 for client and server SCHANNEL communications
	New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Force | Out-Null
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
	Write-Output 'TLS 1.0 has been enabled.'
	 
	# Add and Enable TLS 1.1 for client and server SCHANNEL communications
	New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Force | Out-Null
	New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Force | Out-Null
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'Enabled' -value 1 -PropertyType 'DWord' -Force | Out-Null
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
	Write-Output 'TLS 1.1 has been enabled.'
	 
	# Add and Enable TLS 1.2 for client and server SCHANNEL communications
	New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force | Out-Null
	New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force | Out-Null
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -name 'Enabled' -value 1 -PropertyType 'DWord' -Force | Out-Null
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
	Write-Output 'TLS 1.2 has been enabled.'
	 
	# Re-create the ciphers key.
	New-Item 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers' -Force | Out-Null
	 
	# Disable insecure/weak ciphers.
	$insecureCiphers = @(
	  'DES 56/56',
	  'NULL',
	  'RC2 128/128',
	  'RC2 40/128',
	  'RC2 56/128',
	  'RC4 40/128',
	  'RC4 56/128',
	  'RC4 64/128',
	  'RC4 128/128'
	)
	Foreach ($insecureCipher in $insecureCiphers) {
	  $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey($insecureCipher)
	  $key.SetValue('Enabled', 0, 'DWord')
	  $key.close()
	  Write-Output "Weak cipher $insecureCipher has been disabled."
	}
	 
	# Enable new secure ciphers.
	# - RC4: It is recommended to disable RC4, but you may lock out WinXP/IE8 if you enforce this. This is a requirement for FIPS 140-2.
	# - 3DES: It is recommended to disable these in near future.
	$secureCiphers = @(
	  'AES 128/128',
	  'AES 256/256',
	  'Triple DES 168/168'
	)
	Foreach ($secureCipher in $secureCiphers) {
	  $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey($secureCipher)
	  New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$secureCipher" -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
	  $key.close()
	  Write-Output "Strong cipher $secureCipher has been enabled."
	}
	 
	# Set hashes configuration.
	New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5' -Force | Out-Null
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
	 
	New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA' -Force | Out-Null
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA' -name Enabled -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
	 
	# Set KeyExchangeAlgorithms configuration.
	New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman' -Force | Out-Null
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman' -name Enabled -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
	 
	New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS' -Force | Out-Null
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS' -name Enabled -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
	 
	# Set cipher suites order as secure as possible (Enables Perfect Forward Secrecy).
	$cipherSuitesOrder = @(
	  'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P521',
	  'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P384',
	  'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P256',
	  'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P521',
	  'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P384',
	  'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P256',
	  'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P521',
	  'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P521',
	  'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P384',
	  'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256',
	  'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P384',
	  'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P256',
	  'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P521',
	  'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384',
	  'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P521',
	  'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P384',
	  'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256',
	  'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P521',
	  'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P384',
	  'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P521',
	  'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P384',
	  'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P256',
	  'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P521',
	  'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P384',
	  'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P256',
	  'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P521',
	  'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P384',
	  'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P256',
	  'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256',
	  'TLS_DHE_DSS_WITH_AES_256_CBC_SHA',
	  'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256',
	  'TLS_DHE_DSS_WITH_AES_128_CBC_SHA',
	  'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA',
	  'TLS_RSA_WITH_AES_256_CBC_SHA256',
	  'TLS_RSA_WITH_AES_256_CBC_SHA',
	  'TLS_RSA_WITH_AES_128_CBC_SHA256',
	  'TLS_RSA_WITH_AES_128_CBC_SHA',
	  'TLS_RSA_WITH_3DES_EDE_CBC_SHA'
	)
	$cipherSuitesAsString = [string]::join(',', $cipherSuitesOrder)
	New-ItemProperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -name 'Functions' -value $cipherSuitesAsString -PropertyType 'String' -Force | Out-Null
	 
	Write-Output '--------------------------------------------------------------------------------'
	Write-Output 'NOTE: After the system has been rebooted you can verify your server'
	Write-Output '      configuration at https://www.ssllabs.com/ssltest/'
	Write-Output "--------------------------------------------------------------------------------`n"
	 
	Write-Output -ForegroundColor Red 'A computer restart is required to apply settings. Restart computer now?'
	Restart-Computer -Force -Confirm

}