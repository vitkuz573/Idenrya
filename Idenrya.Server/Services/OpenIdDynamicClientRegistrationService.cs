using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Idenrya.Server.Models;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;

namespace Idenrya.Server.Services;

public sealed class OpenIdDynamicClientRegistrationService(
    IOpenIddictApplicationManager applicationManager,
    IIdentityProviderScopeService scopeService,
    IIdentityProviderClientSecretAuditService clientSecretAuditService,
    IOptions<IdentityProviderOptions> identityProviderOptions)
    : IOpenIdDynamicClientRegistrationService
{
    private const string RegistrationSource = "dynamic_registration";

    public async Task<OpenIdDynamicClientRegistrationResponse> RegisterAsync(
        OpenIdDynamicClientRegistrationRequest request,
        Uri registrationEndpointUri,
        string? initialAccessToken,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(registrationEndpointUri);
        ValidateDynamicRegistrationEnabled();
        ValidateInitialAccessToken(initialAccessToken);

        var supportedScopes = await scopeService.GetSupportedScopesAsync(cancellationToken);
        if (supportedScopes.Count == 0)
        {
            throw new InvalidOperationException("No supported scopes configured for dynamic registration.");
        }

        var normalized = NormalizeRequest(
            request,
            supportedScopes,
            identityProviderOptions.Value.DynamicClientRegistration.AllowUnsignedIdTokens);

        var generatedClientId = await GenerateUniqueClientIdAsync(cancellationToken);
        var generatedClientSecret = normalized.RequiresClientSecret
            ? GenerateClientSecret()
            : null;
        var registrationAccessToken = GenerateRegistrationAccessToken();
        var registrationAccessTokenHash = HashRegistrationAccessToken(registrationAccessToken);
        var issuedAt = DateTimeOffset.UtcNow;

        var descriptor = BuildDescriptor(
            generatedClientId,
            generatedClientSecret,
            normalized,
            registrationAccessTokenHash,
            issuedAt.ToUnixTimeSeconds());

        await applicationManager.CreateAsync(descriptor, cancellationToken);
        if (!string.IsNullOrWhiteSpace(generatedClientSecret))
        {
            await clientSecretAuditService.RecordAsync(
                generatedClientId,
                issuedAt,
                RegistrationSource,
                cancellationToken);
        }

        var registrationClientUri = BuildRegistrationClientUri(registrationEndpointUri, generatedClientId);

        return new OpenIdDynamicClientRegistrationResponse
        {
            ClientId = generatedClientId,
            ClientSecret = generatedClientSecret,
            ClientIdIssuedAt = issuedAt.ToUnixTimeSeconds(),
            ClientSecretExpiresAt = generatedClientSecret is null ? null : 0,
            RedirectUris = normalized.RedirectUris,
            RequestUris = normalized.RequestUris.Count == 0 ? null : normalized.RequestUris,
            GrantTypes = normalized.GrantTypes,
            ResponseTypes = normalized.ResponseTypes,
            TokenEndpointAuthMethod = normalized.TokenEndpointAuthMethod,
            ClientName = normalized.ClientName,
            ApplicationType = normalized.ApplicationType,
            Scope = normalized.Scopes.Count == 0 ? null : string.Join(" ", normalized.Scopes),
            IdTokenSignedResponseAlg = normalized.IdTokenSignedResponseAlg,
            Contacts = normalized.Contacts.Count == 0 ? null : normalized.Contacts,
            RegistrationClientUri = registrationClientUri,
            RegistrationAccessToken = registrationAccessToken
        };
    }

    public async Task<OpenIdDynamicClientRegistrationResponse?> GetAsync(
        string clientId,
        Uri registrationEndpointUri,
        string? registrationAccessToken,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(registrationEndpointUri);
        ValidateDynamicRegistrationEnabled();
        var normalizedClientId = NormalizeClientId(clientId);

        var application = await applicationManager.FindByClientIdAsync(normalizedClientId, cancellationToken);
        if (application is null)
        {
            return null;
        }

        var descriptor = new OpenIddictApplicationDescriptor();
        await applicationManager.PopulateAsync(descriptor, application, cancellationToken);

        ValidateManagementAccessToken(descriptor, registrationAccessToken);

        var registrationClientUri = BuildRegistrationClientUri(registrationEndpointUri, normalizedClientId);
        return BuildResponseFromDescriptor(descriptor, registrationClientUri);
    }

    public async Task<bool> DeleteAsync(
        string clientId,
        string? registrationAccessToken,
        CancellationToken cancellationToken = default)
    {
        ValidateDynamicRegistrationEnabled();
        var normalizedClientId = NormalizeClientId(clientId);

        var application = await applicationManager.FindByClientIdAsync(normalizedClientId, cancellationToken);
        if (application is null)
        {
            return false;
        }

        var descriptor = new OpenIddictApplicationDescriptor();
        await applicationManager.PopulateAsync(descriptor, application, cancellationToken);

        ValidateManagementAccessToken(descriptor, registrationAccessToken);
        await applicationManager.DeleteAsync(application, cancellationToken);
        return true;
    }

    private void ValidateDynamicRegistrationEnabled()
    {
        if (!identityProviderOptions.Value.DynamicClientRegistration.Enabled)
        {
            throw new InvalidOperationException("Dynamic client registration is disabled.");
        }
    }

    private void ValidateInitialAccessToken(string? presentedToken)
    {
        var options = identityProviderOptions.Value.DynamicClientRegistration;
        var configuredTokens = options.InitialAccessTokens
            .Where(static token => !string.IsNullOrWhiteSpace(token))
            .Select(static token => token.Trim())
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        if (options.RequireInitialAccessToken && configuredTokens.Length == 0)
        {
            throw new InvalidOperationException(
                "Dynamic client registration is configured to require an initial access token but none are configured.");
        }

        if (!options.RequireInitialAccessToken && configuredTokens.Length == 0)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(presentedToken))
        {
            throw new UnauthorizedAccessException("Initial access token is required.");
        }

        if (!configuredTokens.Contains(presentedToken, StringComparer.Ordinal))
        {
            throw new UnauthorizedAccessException("Initial access token is invalid.");
        }
    }

    private static string NormalizeClientId(string clientId)
    {
        if (string.IsNullOrWhiteSpace(clientId))
        {
            throw new ArgumentException("Client identifier must be provided.", nameof(clientId));
        }

        return clientId.Trim();
    }

    private static RegistrationConfiguration NormalizeRequest(
        OpenIdDynamicClientRegistrationRequest request,
        IReadOnlyList<string> supportedScopes,
        bool allowUnsignedIdTokens)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(supportedScopes);

        var redirectUris = NormalizeAbsoluteHttpsUris(
            request.RedirectUris,
            "redirect_uris must contain at least one absolute URI.",
            "redirect_uri");

        var requestUris = NormalizeAbsoluteHttpsUris(
            request.RequestUris,
            null,
            "request_uri");

        var tokenEndpointAuthMethod = (request.TokenEndpointAuthMethod ?? OpenIddictConstants.ClientAuthenticationMethods.ClientSecretBasic)
            .Trim()
            .ToLowerInvariant();

        var requiresClientSecret = tokenEndpointAuthMethod switch
        {
            OpenIddictConstants.ClientAuthenticationMethods.ClientSecretBasic => true,
            OpenIddictConstants.ClientAuthenticationMethods.ClientSecretPost => true,
            OpenIddictConstants.ClientAuthenticationMethods.ClientSecretJwt => true,
            OpenIddictConstants.ClientAuthenticationMethods.None => false,
            OpenIddictConstants.ClientAuthenticationMethods.PrivateKeyJwt => false,
            _ => throw new ArgumentException(
                "Unsupported token_endpoint_auth_method. Allowed: client_secret_basic, client_secret_post, " +
                "client_secret_jwt, private_key_jwt, none.")
        };

        var publicClient = string.Equals(
            tokenEndpointAuthMethod,
            OpenIddictConstants.ClientAuthenticationMethods.None,
            StringComparison.Ordinal);

        var grantTypes = request.GrantTypes
            .Where(static grantType => !string.IsNullOrWhiteSpace(grantType))
            .Select(static grantType => grantType.Trim())
            .Distinct(StringComparer.Ordinal)
            .ToList();

        if (grantTypes.Count == 0)
        {
            grantTypes.Add(OpenIddictConstants.GrantTypes.AuthorizationCode);
        }

        foreach (var grantType in grantTypes)
        {
            if (!string.Equals(grantType, OpenIddictConstants.GrantTypes.AuthorizationCode, StringComparison.Ordinal) &&
                !string.Equals(grantType, OpenIddictConstants.GrantTypes.RefreshToken, StringComparison.Ordinal))
            {
                throw new ArgumentException(
                    "Unsupported grant_types value. Allowed: authorization_code, refresh_token.");
            }
        }

        if (grantTypes.Contains(OpenIddictConstants.GrantTypes.AuthorizationCode, StringComparer.Ordinal) &&
            !grantTypes.Contains(OpenIddictConstants.GrantTypes.RefreshToken, StringComparer.Ordinal))
        {
            grantTypes.Add(OpenIddictConstants.GrantTypes.RefreshToken);
        }

        var responseTypes = request.ResponseTypes
            .Where(static responseType => !string.IsNullOrWhiteSpace(responseType))
            .Select(static responseType => responseType.Trim())
            .Distinct(StringComparer.Ordinal)
            .ToList();

        if (responseTypes.Count == 0)
        {
            responseTypes.Add(OpenIddictConstants.ResponseTypes.Code);
        }

        foreach (var responseType in responseTypes)
        {
            if (!string.Equals(responseType, OpenIddictConstants.ResponseTypes.Code, StringComparison.Ordinal))
            {
                throw new ArgumentException("Unsupported response_types value. Allowed: code.");
            }
        }

        var clientName = string.IsNullOrWhiteSpace(request.ClientName)
            ? "Idenrya dynamic client"
            : request.ClientName.Trim();

        var applicationType = string.IsNullOrWhiteSpace(request.ApplicationType)
            ? OpenIddictConstants.ApplicationTypes.Web
            : request.ApplicationType.Trim().ToLowerInvariant();

        if (!string.Equals(applicationType, OpenIddictConstants.ApplicationTypes.Web, StringComparison.Ordinal) &&
            !string.Equals(applicationType, OpenIddictConstants.ApplicationTypes.Native, StringComparison.Ordinal))
        {
            throw new ArgumentException("application_type must be either 'web' or 'native'.");
        }

        var contacts = request.Contacts
            .Where(static contact => !string.IsNullOrWhiteSpace(contact))
            .Select(static contact => contact.Trim())
            .Distinct(StringComparer.Ordinal)
            .ToList();

        var requestedScopes = ParseScopes(request.Scope);
        var grantedScopes = requestedScopes.Count == 0
            ? supportedScopes
                .Distinct(StringComparer.Ordinal)
                .OrderBy(static scope => scope, StringComparer.Ordinal)
                .ToList()
            : ValidateRequestedScopes(requestedScopes, supportedScopes);

        var idTokenSignedResponseAlg = NormalizeIdTokenSignedResponseAlg(
            request.IdTokenSignedResponseAlg,
            allowUnsignedIdTokens);

        return new RegistrationConfiguration
        {
            RedirectUris = redirectUris,
            RequestUris = requestUris,
            GrantTypes = grantTypes
                .OrderBy(static grantType => grantType, StringComparer.Ordinal)
                .ToList(),
            ResponseTypes = responseTypes
                .OrderBy(static responseType => responseType, StringComparer.Ordinal)
                .ToList(),
            Scopes = grantedScopes,
            TokenEndpointAuthMethod = tokenEndpointAuthMethod,
            RequiresClientSecret = requiresClientSecret,
            PublicClient = publicClient,
            ClientName = clientName,
            ApplicationType = applicationType,
            IdTokenSignedResponseAlg = idTokenSignedResponseAlg,
            Contacts = contacts
        };
    }

    private static OpenIddictApplicationDescriptor BuildDescriptor(
        string clientId,
        string? clientSecret,
        RegistrationConfiguration configuration,
        string registrationAccessTokenHash,
        long issuedAt)
    {
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientSecret = clientSecret,
            DisplayName = configuration.ClientName,
            ApplicationType = configuration.ApplicationType,
            ClientType = configuration.PublicClient
                ? OpenIddictConstants.ClientTypes.Public
                : OpenIddictConstants.ClientTypes.Confidential,
            ConsentType = OpenIddictConstants.ConsentTypes.Implicit
        };

        foreach (var redirectUri in configuration.RedirectUris)
        {
            descriptor.RedirectUris.Add(new Uri(redirectUri));
        }

        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Authorization);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Token);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Revocation);
        if (!configuration.PublicClient)
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Introspection);
        }

        foreach (var grantType in configuration.GrantTypes)
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Prefixes.GrantType + grantType);
        }

        foreach (var responseType in configuration.ResponseTypes)
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Prefixes.ResponseType + responseType);
        }

        foreach (var scope in configuration.Scopes)
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Prefixes.Scope + scope);
        }

        if (configuration.PublicClient)
        {
            descriptor.Requirements.Add(OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange);
        }

        descriptor.Properties[OpenIdClientRegistrationPropertyNames.RegistrationAccessTokenHash] =
            JsonSerializer.SerializeToElement(registrationAccessTokenHash);
        descriptor.Properties[OpenIdClientRegistrationPropertyNames.TokenEndpointAuthMethod] =
            JsonSerializer.SerializeToElement(configuration.TokenEndpointAuthMethod);
        descriptor.Properties[OpenIdClientRegistrationPropertyNames.ClientIdIssuedAt] =
            JsonSerializer.SerializeToElement(issuedAt);

        if (configuration.RequestUris.Count > 0)
        {
            descriptor.Properties[OpenIdClientRegistrationPropertyNames.RequestUris] =
                JsonSerializer.SerializeToElement(configuration.RequestUris);
        }

        if (!string.IsNullOrWhiteSpace(configuration.IdTokenSignedResponseAlg))
        {
            descriptor.Properties[OpenIdClientRegistrationPropertyNames.IdTokenSignedResponseAlg] =
                JsonSerializer.SerializeToElement(configuration.IdTokenSignedResponseAlg);
        }

        return descriptor;
    }

    private static OpenIdDynamicClientRegistrationResponse BuildResponseFromDescriptor(
        OpenIddictApplicationDescriptor descriptor,
        string registrationClientUri)
    {
        var tokenEndpointAuthMethod = ReadTokenEndpointAuthMethod(descriptor);
        var clientType = descriptor.ClientType ?? OpenIddictConstants.ClientTypes.Confidential;
        if (string.Equals(clientType, OpenIddictConstants.ClientTypes.Public, StringComparison.Ordinal))
        {
            tokenEndpointAuthMethod = OpenIddictConstants.ClientAuthenticationMethods.None;
        }

        var grantedScopes = descriptor.Permissions
            .Where(static permission =>
                permission.StartsWith(OpenIddictConstants.Permissions.Prefixes.Scope, StringComparison.Ordinal))
            .Select(static permission => permission[OpenIddictConstants.Permissions.Prefixes.Scope.Length..])
            .OrderBy(static scope => scope, StringComparer.Ordinal)
            .ToList();

        return new OpenIdDynamicClientRegistrationResponse
        {
            ClientId = descriptor.ClientId ?? string.Empty,
            ClientIdIssuedAt = ReadIssuedAt(descriptor),
            RedirectUris = descriptor.RedirectUris
                .Select(static uri => uri.AbsoluteUri)
                .OrderBy(static uri => uri, StringComparer.Ordinal)
                .ToList(),
            RequestUris = ReadStringArrayProperty(descriptor, OpenIdClientRegistrationPropertyNames.RequestUris),
            GrantTypes = descriptor.Permissions
                .Where(static permission =>
                    permission.StartsWith(OpenIddictConstants.Permissions.Prefixes.GrantType, StringComparison.Ordinal))
                .Select(static permission => permission[OpenIddictConstants.Permissions.Prefixes.GrantType.Length..])
                .OrderBy(static grantType => grantType, StringComparer.Ordinal)
                .ToList(),
            ResponseTypes = descriptor.Permissions
                .Where(static permission =>
                    permission.StartsWith(OpenIddictConstants.Permissions.Prefixes.ResponseType, StringComparison.Ordinal))
                .Select(static permission => permission[OpenIddictConstants.Permissions.Prefixes.ResponseType.Length..])
                .OrderBy(static responseType => responseType, StringComparer.Ordinal)
                .ToList(),
            TokenEndpointAuthMethod = tokenEndpointAuthMethod,
            ClientName = descriptor.DisplayName ?? string.Empty,
            ApplicationType = descriptor.ApplicationType ?? OpenIddictConstants.ApplicationTypes.Web,
            Scope = grantedScopes.Count == 0 ? null : string.Join(" ", grantedScopes),
            IdTokenSignedResponseAlg = ReadStringProperty(descriptor, OpenIdClientRegistrationPropertyNames.IdTokenSignedResponseAlg),
            RegistrationClientUri = registrationClientUri
        };
    }

    private static string ReadTokenEndpointAuthMethod(OpenIddictApplicationDescriptor descriptor)
    {
        var configuredMethod = ReadStringProperty(descriptor, OpenIdClientRegistrationPropertyNames.TokenEndpointAuthMethod);
        return string.IsNullOrWhiteSpace(configuredMethod)
            ? OpenIddictConstants.ClientAuthenticationMethods.ClientSecretBasic
            : configuredMethod;
    }

    private static string? ReadStringProperty(OpenIddictApplicationDescriptor descriptor, string propertyName)
    {
        if (descriptor.Properties.TryGetValue(propertyName, out var value) &&
            value.ValueKind == JsonValueKind.String)
        {
            var stringValue = value.GetString();
            if (!string.IsNullOrWhiteSpace(stringValue))
            {
                return stringValue;
            }
        }

        return null;
    }

    private static List<string>? ReadStringArrayProperty(OpenIddictApplicationDescriptor descriptor, string propertyName)
    {
        if (!descriptor.Properties.TryGetValue(propertyName, out var value) ||
            value.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        var entries = value.EnumerateArray()
            .Where(static item => item.ValueKind == JsonValueKind.String)
            .Select(static item => item.GetString())
            .Where(static item => !string.IsNullOrWhiteSpace(item))
            .Select(static item => item!)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(static item => item, StringComparer.Ordinal)
            .ToList();

        return entries.Count == 0 ? null : entries;
    }

    private static long ReadIssuedAt(OpenIddictApplicationDescriptor descriptor)
    {
        if (!descriptor.Properties.TryGetValue(OpenIdClientRegistrationPropertyNames.ClientIdIssuedAt, out var issuedAtValue))
        {
            return DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        }

        if (issuedAtValue.ValueKind == JsonValueKind.Number &&
            issuedAtValue.TryGetInt64(out var unixTimestamp) &&
            unixTimestamp > 0)
        {
            return unixTimestamp;
        }

        if (issuedAtValue.ValueKind == JsonValueKind.String &&
            long.TryParse(issuedAtValue.GetString(), out unixTimestamp) &&
            unixTimestamp > 0)
        {
            return unixTimestamp;
        }

        return DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    }

    private static void ValidateManagementAccessToken(
        OpenIddictApplicationDescriptor descriptor,
        string? presentedAccessToken)
    {
        if (string.IsNullOrWhiteSpace(presentedAccessToken))
        {
            throw new UnauthorizedAccessException("Registration access token is required.");
        }

        var storedHash = ReadStringProperty(descriptor, OpenIdClientRegistrationPropertyNames.RegistrationAccessTokenHash);
        if (string.IsNullOrWhiteSpace(storedHash))
        {
            throw new UnauthorizedAccessException("Registration access token is not configured for this client.");
        }

        var presentedHash = HashRegistrationAccessToken(presentedAccessToken);
        var storedBytes = Encoding.UTF8.GetBytes(storedHash);
        var presentedBytes = Encoding.UTF8.GetBytes(presentedHash);
        if (storedBytes.Length != presentedBytes.Length ||
            !CryptographicOperations.FixedTimeEquals(storedBytes, presentedBytes))
        {
            throw new UnauthorizedAccessException("Registration access token is invalid.");
        }
    }

    private async Task<string> GenerateUniqueClientIdAsync(CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < 16; attempt++)
        {
            var clientId = "idenrya_" + WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(18));
            var existing = await applicationManager.FindByClientIdAsync(clientId, cancellationToken);
            if (existing is null)
            {
                return clientId;
            }
        }

        throw new InvalidOperationException("Failed to generate a unique client identifier.");
    }

    private static string GenerateClientSecret()
    {
        return WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(48));
    }

    private static string GenerateRegistrationAccessToken()
    {
        return WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
    }

    private static string HashRegistrationAccessToken(string accessToken)
    {
        var bytes = Encoding.UTF8.GetBytes(accessToken);
        var hash = SHA256.HashData(bytes);
        return WebEncoders.Base64UrlEncode(hash);
    }

    private static string BuildRegistrationClientUri(Uri registrationEndpointUri, string clientId)
    {
        var normalizedPath = registrationEndpointUri.AbsolutePath.TrimEnd('/');
        var escapedClientId = Uri.EscapeDataString(clientId);
        var path = $"{normalizedPath}/{escapedClientId}";
        var builder = new UriBuilder(registrationEndpointUri)
        {
            Path = path
        };

        return builder.Uri.AbsoluteUri;
    }

    private static List<string> ParseScopes(string? scope)
    {
        return string.IsNullOrWhiteSpace(scope)
            ? []
            : scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Distinct(StringComparer.Ordinal)
                .OrderBy(static value => value, StringComparer.Ordinal)
                .ToList();
    }

    private static List<string> ValidateRequestedScopes(
        IReadOnlyList<string> requestedScopes,
        IReadOnlyList<string> supportedScopes)
    {
        var supported = new HashSet<string>(supportedScopes, StringComparer.Ordinal);
        var granted = new List<string>(requestedScopes.Count);
        foreach (var scope in requestedScopes)
        {
            if (!supported.Contains(scope))
            {
                throw new ArgumentException($"Unsupported scope requested: '{scope}'.");
            }

            granted.Add(scope);
        }

        return granted
            .Distinct(StringComparer.Ordinal)
            .OrderBy(static value => value, StringComparer.Ordinal)
            .ToList();
    }

    private static string? NormalizeIdTokenSignedResponseAlg(string? idTokenSignedResponseAlg, bool allowUnsignedIdTokens)
    {
        if (string.IsNullOrWhiteSpace(idTokenSignedResponseAlg))
        {
            return null;
        }

        var normalized = idTokenSignedResponseAlg.Trim();
        if (string.Equals(normalized, "RS256", StringComparison.Ordinal))
        {
            return "RS256";
        }

        if (string.Equals(normalized, "none", StringComparison.Ordinal))
        {
            if (!allowUnsignedIdTokens)
            {
                throw new ArgumentException("Unsupported id_token_signed_response_alg value. Allowed: RS256.");
            }

            return "none";
        }

        throw new ArgumentException("Unsupported id_token_signed_response_alg value. Allowed: RS256" +
                                    (allowUnsignedIdTokens ? ", none." : "."));
    }

    private static List<string> NormalizeAbsoluteHttpsUris(
        IEnumerable<string> values,
        string? emptyMessage,
        string fieldName)
    {
        var result = values
            .Where(static uri => !string.IsNullOrWhiteSpace(uri))
            .Select(static uri => uri.Trim())
            .Distinct(StringComparer.Ordinal)
            .ToList();

        if (result.Count == 0)
        {
            if (!string.IsNullOrWhiteSpace(emptyMessage))
            {
                throw new ArgumentException(emptyMessage);
            }

            return [];
        }

        for (var index = 0; index < result.Count; index++)
        {
            var value = result[index];
            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
            {
                throw new ArgumentException($"{fieldName} '{value}' is not a valid absolute URI.");
            }

            if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException($"{fieldName} '{value}' must use https.");
            }

            result[index] = uri.AbsoluteUri;
        }

        return result
            .Distinct(StringComparer.Ordinal)
            .OrderBy(static uri => uri, StringComparer.Ordinal)
            .ToList();
    }

    private sealed class RegistrationConfiguration
    {
        public List<string> RedirectUris { get; init; } = [];

        public List<string> RequestUris { get; init; } = [];

        public List<string> GrantTypes { get; init; } = [];

        public List<string> ResponseTypes { get; init; } = [];

        public List<string> Scopes { get; init; } = [];

        public string TokenEndpointAuthMethod { get; init; } = OpenIddictConstants.ClientAuthenticationMethods.ClientSecretBasic;

        public bool RequiresClientSecret { get; init; }

        public bool PublicClient { get; init; }

        public string ClientName { get; init; } = string.Empty;

        public string ApplicationType { get; init; } = OpenIddictConstants.ApplicationTypes.Web;

        public string? IdTokenSignedResponseAlg { get; init; }

        public List<string> Contacts { get; init; } = [];
    }
}
