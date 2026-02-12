---
name: microsoft-azure-webjobs-extensions-authentication-events-dotnet
description: Microsoft Entra Authentication Events SDK for .NET. Azure Functions triggers for custom authentication extensions. Use for token enrichment, custom claims, attribute collection, and OTP customization 
category: Business & Marketing
source: antigravity
tags: [api, ai, workflow, azure, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/microsoft-azure-webjobs-extensions-authentication-events-dotnet
---


# Microsoft.Azure.WebJobs.Extensions.AuthenticationEvents (.NET)

Azure Functions extension for handling Microsoft Entra ID custom authentication events.

## Installation

```bash
dotnet add package Microsoft.Azure.WebJobs.Extensions.AuthenticationEvents
```

**Current Version**: v1.1.0 (stable)

## Supported Events

| Event | Purpose |
|-------|---------|
| `OnTokenIssuanceStart` | Add custom claims to tokens during issuance |
| `OnAttributeCollectionStart` | Customize attribute collection UI before display |
| `OnAttributeCollectionSubmit` | Validate/modify attributes after user submission |
| `OnOtpSend` | Custom OTP delivery (SMS, email, etc.) |

## Core Workflows

### 1. Token Enrichment (Add Custom Claims)

Add custom claims to access or ID tokens during sign-in.

```csharp
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.AuthenticationEvents;
using Microsoft.Azure.WebJobs.Extensions.AuthenticationEvents.TokenIssuanceStart;
using Microsoft.Extensions.Logging;

public static class TokenEnrichmentFunction
{
    [FunctionName("OnTokenIssuanceStart")]
    public static WebJobsAuthenticationEventResponse Run(
        [WebJobsAuthenticationEventsTrigger] WebJobsTokenIssuanceStartRequest request,
        ILogger log)
    {
        log.LogInformation("Token issuance event for user: {UserId}", 
            request.Data?.AuthenticationContext?.User?.Id);

        // Create response with custom claims
        var response = new WebJobsTokenIssuanceStartResponse();
        
        // Add claims to the token
        response.Actions.Add(new WebJobsProvideClaimsForToken
        {
            Claims = new Dictionary<string, string>
            {
                { "customClaim1", "customValue1" },
                { "department", "Engineering" },
                { "costCenter", "CC-12345" },
                { "apiVersion", "v2" }
            }
        });

        return response;
    }
}
```

### 2. Token Enrichment with External Data

Fetch claims from external systems (databases, APIs).

```csharp
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.AuthenticationEvents;
using Microsoft.Azure.WebJobs.Extensions.AuthenticationEvents.TokenIssuanceStart;
using Microsoft.Extensions.Logging;
using System.Net.Http;
using System.Text.Json;

public static class TokenEnrichmentWithExternalData
{
    private static readonly HttpClient _httpClient = new();

    [FunctionName("OnTokenIssuanceStartExternal")]
    public static async Task<WebJobsAuthenticationEventResponse> Run(
        [WebJobsAuthenticationEventsTrigger] WebJobsTokenIssuanceStartRequest request,
        ILogger log)
    {
        string? userId = request.Data?.AuthenticationContext?.User?.Id;
        
        if (string.IsNullOrEmpty(userId))
        {
            log.LogWarning("No user ID in request");
            return new WebJobsTokenIssuanceStartResponse();
        }

        // Fetch user data from external API
        var userProfile = await GetUserProfileAsync(userId);
        
        var response = new WebJobsTokenIssuanceStartResponse();
        response.Actions.Add(new WebJobsProvideClaimsForToken
        {
            Claims = new Dictionary<string, string>
            {
                { "employeeId", userProfile.EmployeeId },
                { "department", userProfile.Department },
                { "roles", string.Join(",", userProfile.Roles) }
            }
        });

        return response;
    }

    private static async Task<UserProfile> GetUserProfileAsync(string userId)
    {
        var response = await _httpClient.GetAsync($"https://api.example.com/users/{userId}");
        response.EnsureSuccessStatusCode();
        var json = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<UserProfile>(json)!;
    }
}

public record UserProfile(string EmployeeId, string Department, string[] Roles);
```

### 3. Attribute Collection - Customize UI (Start Event)

Customize the attribute collection page before it's displayed.

```csharp
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.AuthenticationEvents;
using Microsoft.Azure.WebJobs.Extensions.AuthenticationEvents.Framework;
using Microsoft.Extensions.Logging;

public static class AttributeCollectionStartFunction
{
    [FunctionName("OnAttributeCollectionStart")]
    public static WebJobsAuthenticationEventResponse Run(
        [WebJobsAuthenticationEventsTrigger] WebJobsAttributeCollectionStartRequest request,
        ILogger log)
    {
        log.LogInformation("Attribute collection start for correlation: {CorrelationId}",
            request.Data?.AuthenticationContext?.CorrelationId);

        var response = new WebJobsAttributeCollectionStartResponse();

        // Option 1: Continue with default behavior
        response.Actions.Add(new WebJobsContinueWithDefaultBehavior());

        // Option 2: Prefill attributes
        // response.Actions.Add(new WebJobsSetPrefillValues
        // {
