function Get-SslCipher {

	Param(
	[Parameter(Mandatory=$true)]
   [string]$serverName
	)

	try
	{
		$client = New-Object System.Net.Sockets.TcpClient
		$client.Connect($serverName, 443)

		$sslStream = New-Object System.Net.Security.SslStream($client.GetStream())
		$sslStream.AuthenticateAsClient($serverName)

		$sslStream | Format-List CipherAlgorithm,CipherStrength,HashAlgorithm,HashStrength,KeyExchangeAlgorithm,KeyExchangeStrength
	}
	finally
	{
		if ($null -ne $sslStream)
		{
			$sslStream.Dispose()
		}

		if ($null -ne $client)
		{
			$client.Dispose()
		}
	}

}