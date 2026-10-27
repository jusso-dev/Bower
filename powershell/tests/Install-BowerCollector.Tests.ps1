BeforeAll {
    # Dot-sourcing loads the installer's functions without running msiexec.
    . (Join-Path $PSScriptRoot '../../deploy/installers/windows/Install-BowerCollector.ps1')
    $script:Token = 'bwe1.0123456789abcdef.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
}

Describe 'Install-BowerCollector.ps1 (Windows offline installer)' {
    It 'reads a bwe1 token and refuses anything else' {
        $file = Join-Path $TestDrive 'token'
        Set-Content -LiteralPath $file -Value "$script:Token`n" -NoNewline
        Read-BowerEnrolmentToken -Path $file | Should -Be $script:Token

        Set-Content -LiteralPath $file -Value 'not-a-token'
        { Read-BowerEnrolmentToken -Path $file } | Should -Throw '*bwe1*'
        Set-Content -LiteralPath $file -Value ('bwe1.ab.' + ('A' * 2000))
        { Read-BowerEnrolmentToken -Path $file } | Should -Throw '*too large*'
    }

    It 'never puts the token on the msiexec command line' {
        $arguments = Get-BowerMsiArgument -Msi 'C:\bundle\bower-collector-0.1.0-x64.msi' -Log 'C:\Temp\bower.log' -Property ([ordered]@{
                MANAGEMENTENDPOINT = 'https://bower-management.example.com/'
                COLLECTORID        = 'edge-01'
                BOWERENVIRONMENT   = ''
                PACKTRUSTEDKEYS    = 'C:\ProgramData\Bower\keys\pack-trusted.pem'
            })

        $arguments[0..3] | Should -Be @('/i', '"C:\bundle\bower-collector-0.1.0-x64.msi"', '/qn', '/norestart')
        $arguments | Should -Contain 'MANAGEMENTENDPOINT=https://bower-management.example.com/'
        $arguments | Should -Contain 'COLLECTORID=edge-01'
        $arguments | Should -Contain 'PACKTRUSTEDKEYS=C:\ProgramData\Bower\keys\pack-trusted.pem'
        ($arguments -join ' ') | Should -Not -Match 'BOWERENVIRONMENT|bwe1'
    }

    It 'refuses property values that could break out of the msiexec command line' {
        foreach ($value in @('edge 01', 'a"b', '[ProgramFilesFolder]', "a`nb")) {
            { Get-BowerMsiArgument -Msi 'x.msi' -Log 'x.log' -Property @{ COLLECTORID = $value } } | Should -Throw '*COLLECTORID*'
        }
    }

    It 'accepts HTTPS endpoints and HTTP only to loopback, without credentials or a query' {
        Test-BowerManagementEndpoint -Endpoint 'https://bower-management.example.com/' | Should -BeTrue
        Test-BowerManagementEndpoint -Endpoint 'http://127.0.0.1:4320/' | Should -BeTrue
        Test-BowerManagementEndpoint -Endpoint 'http://bower-management.example.com/' | Should -BeFalse
        Test-BowerManagementEndpoint -Endpoint 'https://user:pass@bower-management.example.com/' | Should -BeFalse
        Test-BowerManagementEndpoint -Endpoint 'https://bower-management.example.com/?key=1' | Should -BeFalse
        Test-BowerManagementEndpoint -Endpoint 'not a url' | Should -BeFalse
    }

    It 'hashes the token like the collector (lower-case SHA-256 of the UTF-8 text)' {
        Get-BowerSha256Hex -Text 'abc' | Should -Be 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    }
}
