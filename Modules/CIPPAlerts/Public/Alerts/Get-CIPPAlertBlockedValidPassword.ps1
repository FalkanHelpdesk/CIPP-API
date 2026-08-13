function Get-CIPPAlertBlockedValidPassword {
    <#
    .FUNCTIONALITY
        Entrypoint
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [Alias('input')]
        $InputValue,

        $TenantFilter
    )

    try {
        $LookbackMinutes = 35
        $CandidateErrorCodes = @(53003, 7000112)
        $AlertPartitionKey = 'BlockedValidPassword'

        $StartTime = (Get-Date).ToUniversalTime().AddMinutes(-$LookbackMinutes).ToString('yyyy-MM-ddTHH:mm:ssZ')

        $Uri = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=createdDateTime ge $StartTime&`$orderby=createdDateTime desc&`$top=500"

        $SignIns = New-GraphGetRequest -uri $Uri -tenantid $TenantFilter

        $PreviousSignInIds = @()

        try {
            $AlertTable = Get-CIPPTable -TableName 'AlertLastRun'
            $CmdletName = $MyInvocation.MyCommand.ToString()
            $RowKey = "$TenantFilter-$CmdletName"

            $PreviousRow = Get-CIPPAzDataTableEntity @AlertTable -Filter "RowKey eq '$RowKey' and PartitionKey eq '$AlertPartitionKey'"

            if ($PreviousRow.LogData) {
                $PreviousData = $PreviousRow.LogData | ConvertFrom-Json

                $PreviousSignInIds = @(
                    $PreviousData |
                        ForEach-Object { $_.SignInId } |
                        Where-Object { $_ } |
                        Select-Object -Unique
                )
            }
        } catch {
            Write-Information "No previous blocked-password alert data found for $TenantFilter."
        }

        $AlertData = foreach ($SignIn in $SignIns) {
            $ErrorCode = [int64]$SignIn.status.errorCode

            if ($ErrorCode -notin $CandidateErrorCodes) {
                continue
            }

            if ($SignIn.id -in $PreviousSignInIds) {
                continue
            }

            $SuccessfulPasswordSteps = @(
                $SignIn.authenticationDetails | Where-Object {
                    $_.authenticationMethod -eq 'Password' -and
                    $_.succeeded -eq $true -and
                    $_.authenticationStepResultDetail -eq 'Correct password'
                }
            )

            if ($SuccessfulPasswordSteps.Count -eq 0) {
                continue
            }

            $FailedPolicies = @(
                $SignIn.appliedConditionalAccessPolicies |
                    Where-Object {
                        $_.result -eq 'failure'
                    } |
                    ForEach-Object {
                        '{0}: {1} ({2})' -f `
                            $_.displayName,
                            $_.result,
                            ($_.enforcedGrantControls -join ', ')
                    }
            )

            $ReportOnlyFailures = @(
                $SignIn.appliedConditionalAccessPolicies |
                    Where-Object {
                        $_.result -eq 'reportOnlyFailure'
                    } |
                    ForEach-Object {
                        '{0}: {1} ({2})' -f `
                            $_.displayName,
                            $_.result,
                            ($_.enforcedGrantControls -join ', ')
                    }
            )

            [PSCustomObject]@{
                AlertType                       = 'CorrectPasswordBlocked'
                AlertID                         = $SignIn.id
                Confidence                      = 'High'
                DetectionReason                 = 'Correct password confirmed; access was prevented by a later security control.'
                CreatedDateTime                 = $SignIn.createdDateTime
                UserDisplayName                 = $SignIn.userDisplayName
                UserPrincipalName               = $SignIn.userPrincipalName
                UserId                          = $SignIn.userId
                AppDisplayName                  = $SignIn.appDisplayName
                AppId                           = $SignIn.appId
                ResourceDisplayName             = $SignIn.resourceDisplayName
                ResourceId                      = $SignIn.resourceId
                ErrorCode                       = $ErrorCode
                FailureReason                   = $SignIn.status.failureReason
                ConditionalAccessStatus         = $SignIn.conditionalAccessStatus
                PasswordSucceeded               = $true
                PasswordDetail                  = ($SuccessfulPasswordSteps.authenticationMethodDetail -join ', ')
                AuthenticationFlow              = $SignIn.originalTransferMethod
                IsInteractive                   = $SignIn.isInteractive
                IPAddress                       = $SignIn.ipAddress
                City                            = $SignIn.location.city
                State                           = $SignIn.location.state
                Country                         = $SignIn.location.countryOrRegion
                OperatingSystem                 = $SignIn.deviceDetail.operatingSystem
                Browser                         = $SignIn.deviceDetail.browser
                IsManaged                       = $SignIn.deviceDetail.isManaged
                IsCompliant                     = $SignIn.deviceDetail.isCompliant
                FailedConditionalAccessPolicies = ($FailedPolicies -join '; ')
                ReportOnlyPolicyMatches         = ($ReportOnlyFailures -join '; ')
                CorrelationId                   = $SignIn.correlationId
                SignInId                        = $SignIn.id
                Tenant                          = $TenantFilter
            }
        }

        if ($AlertData) {
            Write-AlertTrace `
                -cmdletName $MyInvocation.MyCommand `
                -tenantFilter $TenantFilter `
                -data $AlertData `
                -PartitionKey $AlertPartitionKey
        }
    } catch {
        $ErrorMessage = Get-CippException -Exception $_

        Write-LogMessage `
            -API 'Alerts' `
            -tenant $TenantFilter `
            -message "Could not check blocked correct-password sign-ins for $($TenantFilter): $($ErrorMessage.NormalizedError)" `
            -sev Error `
            -LogData $ErrorMessage
    }
}
