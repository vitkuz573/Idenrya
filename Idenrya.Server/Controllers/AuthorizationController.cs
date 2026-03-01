using System.Globalization;
using System.Security.Claims;
using System.Text.Json;
using Idenrya.Server.Models;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using OpenIddict.Validation.AspNetCore;

namespace Idenrya.Server.Controllers;

[ApiExplorerSettings(IgnoreApi = true)]
public sealed class AuthorizationController(
    UserManager<ApplicationUser> userManager,
    SignInManager<ApplicationUser> signInManager) : Controller
{
    private const string AcrClaimType = "acr";
    private const string UserInfoNameRequestedClaimType = "idenrya_userinfo_name_requested";

    [HttpGet("~/connect/authorize")]
    [HttpPost("~/connect/authorize")]
    public async Task<IActionResult> Authorize()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
                      ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        var authentication = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);

        if (!authentication.Succeeded || RequiresFreshAuthentication(request, authentication.Properties))
        {
            if (request.HasPromptValue(OpenIddictConstants.PromptValues.None))
            {
                var errorRedirectUri = BuildPromptNoneErrorRedirectUri(request);
                if (!string.IsNullOrWhiteSpace(errorRedirectUri))
                {
                    return Redirect(errorRedirectUri);
                }

                return Forbid(
                    new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.LoginRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "The user is not logged in."
                    }),
                    OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            return Challenge(
                new AuthenticationProperties
                {
                    RedirectUri = await BuildRedirectUriWithoutLoginPromptAsync(request)
                },
                IdentityConstants.ApplicationScheme);
        }

        var user = await userManager.GetUserAsync(authentication.Principal!);
        if (user is null)
        {
            await HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);
            return Challenge(
                new AuthenticationProperties
                {
                    RedirectUri = $"{Request.PathBase}{Request.Path}{Request.QueryString}"
                },
                IdentityConstants.ApplicationScheme);
        }

        var authenticationTime = authentication.Properties?.IssuedUtc ?? DateTimeOffset.UtcNow;
        var principal = await CreatePrincipalAsync(user, request, authenticationTime);

        return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [HttpPost("~/connect/token")]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
                      ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        if (!request.IsAuthorizationCodeGrantType() && !request.IsRefreshTokenGrantType())
        {
            throw new InvalidOperationException("The specified grant type is not supported by this endpoint.");
        }

        var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        var principal = result.Principal;
        if (principal is null)
        {
            return Forbid(
                new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "The authorization code or refresh token is no longer valid."
                }),
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        var user = await userManager.FindByIdAsync(principal.GetClaim(OpenIddictConstants.Claims.Subject)!);
        if (user is null)
        {
            return Forbid(
                new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "The user associated with the token no longer exists."
                }),
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        var authTime = principal.GetClaim(OpenIddictConstants.Claims.AuthenticationTime);
        var issuedAt = DateTimeOffset.UtcNow;
        if (long.TryParse(authTime, NumberStyles.Integer, CultureInfo.InvariantCulture, out var authTimeUnix))
        {
            issuedAt = DateTimeOffset.FromUnixTimeSeconds(authTimeUnix);
        }

        var renewedPrincipal = await CreatePrincipalAsync(user, request, issuedAt);
        renewedPrincipal.SetScopes(principal.GetScopes());
        renewedPrincipal.SetResources(principal.GetResources());

        var acr = principal.GetClaim(AcrClaimType);
        if (!string.IsNullOrWhiteSpace(acr))
        {
            renewedPrincipal.SetClaim(AcrClaimType, acr);
        }

        if (string.Equals(principal.GetClaim(UserInfoNameRequestedClaimType), "true", StringComparison.OrdinalIgnoreCase))
        {
            renewedPrincipal.SetClaim(UserInfoNameRequestedClaimType, "true");
        }

        return SignIn(renewedPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
    [HttpGet("~/connect/userinfo")]
    [HttpPost("~/connect/userinfo")]
    public async Task<IActionResult> UserInfo()
    {
        var result = await HttpContext.AuthenticateAsync(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
        var principal = result.Principal;
        if (principal is null)
        {
            return Challenge(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
        }

        var user = await userManager.FindByIdAsync(principal.GetClaim(OpenIddictConstants.Claims.Subject)!);
        if (user is null)
        {
            return Challenge(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
        }

        var payload = new Dictionary<string, object?>
        {
            [OpenIddictConstants.Claims.Subject] = user.Id
        };

        var requestedScopes = principal.GetScopes().ToArray();
        var onlyOpenIdScope = requestedScopes.Length == 1 &&
                              string.Equals(requestedScopes[0], OpenIddictConstants.Scopes.OpenId, StringComparison.Ordinal);
        var includeName = principal.HasScope(OpenIddictConstants.Scopes.Profile) ||
                          string.Equals(principal.GetClaim(UserInfoNameRequestedClaimType), "true", StringComparison.OrdinalIgnoreCase) ||
                          onlyOpenIdScope;
        if (includeName)
        {
            payload[OpenIddictConstants.Claims.Name] = $"{user.GivenName} {user.FamilyName}".Trim();
        }

        if (principal.HasScope(OpenIddictConstants.Scopes.Profile))
        {
            payload[OpenIddictConstants.Claims.GivenName] = user.GivenName;
            payload[OpenIddictConstants.Claims.FamilyName] = user.FamilyName;
            payload[OpenIddictConstants.Claims.PreferredUsername] = user.UserName;
            payload[OpenIddictConstants.Claims.MiddleName] = "Q";
            payload[OpenIddictConstants.Claims.Nickname] = user.UserName;
            payload[OpenIddictConstants.Claims.Profile] = "https://idenrya.local/users/foo";
            payload[OpenIddictConstants.Claims.Picture] = "https://idenrya.local/assets/foo.png";
            payload[OpenIddictConstants.Claims.Website] = "https://idenrya.local";
            payload[OpenIddictConstants.Claims.Gender] = "unspecified";
            payload[OpenIddictConstants.Claims.Birthdate] = "1970-01-01";
            payload[OpenIddictConstants.Claims.Zoneinfo] = "America/New_York";
            payload[OpenIddictConstants.Claims.Locale] = "en-US";
            payload[OpenIddictConstants.Claims.UpdatedAt] = 1700000000;
        }

        if (principal.HasScope(OpenIddictConstants.Scopes.Email))
        {
            payload[OpenIddictConstants.Claims.Email] = user.Email;
            payload[OpenIddictConstants.Claims.EmailVerified] = user.EmailConfirmed;
        }

        if (principal.HasScope(OpenIddictConstants.Scopes.Phone))
        {
            payload[OpenIddictConstants.Claims.PhoneNumber] = user.PhoneNumber;
            payload[OpenIddictConstants.Claims.PhoneNumberVerified] = user.PhoneNumberConfirmed;
        }

        if (principal.HasScope(OpenIddictConstants.Scopes.Address))
        {
            payload[OpenIddictConstants.Claims.Address] = new Dictionary<string, object?>
            {
                ["formatted"] = user.Address
            };
        }

        return Ok(payload);
    }

    private static bool RequiresFreshAuthentication(OpenIddictRequest request, AuthenticationProperties? properties)
    {
        if (request.HasPromptValue(OpenIddictConstants.PromptValues.Login))
        {
            return true;
        }

        var maxAge = request.MaxAge?.ToString();
        if (!long.TryParse(maxAge, NumberStyles.Integer, CultureInfo.InvariantCulture, out var maxAgeSeconds))
        {
            return false;
        }

        if (!properties?.IssuedUtc.HasValue ?? true)
        {
            return true;
        }

        return DateTimeOffset.UtcNow > properties!.IssuedUtc!.Value.AddSeconds(maxAgeSeconds);
    }

    private static string? BuildPromptNoneErrorRedirectUri(OpenIddictRequest request)
    {
        var redirectUri = request.RedirectUri?.ToString();
        if (string.IsNullOrWhiteSpace(redirectUri))
        {
            return null;
        }

        var parameters = new Dictionary<string, string?>
        {
            [OpenIddictConstants.Parameters.Error] = OpenIddictConstants.Errors.LoginRequired
        };

        if (!string.IsNullOrWhiteSpace(request.State))
        {
            parameters[OpenIddictConstants.Parameters.State] = request.State;
        }

        return QueryHelpers.AddQueryString(redirectUri, parameters);
    }

    private async Task<string> BuildRedirectUriWithoutLoginPromptAsync(OpenIddictRequest request)
    {
        var parameters = new List<KeyValuePair<string, string?>>();
        foreach (var pair in Request.Query)
        {
            if (pair.Key.Equals(OpenIddictConstants.Parameters.Prompt, StringComparison.Ordinal))
            {
                continue;
            }

            foreach (var value in pair.Value)
            {
                parameters.Add(new KeyValuePair<string, string?>(pair.Key, value));
            }
        }

        if (Request.HasFormContentType)
        {
            var form = await Request.ReadFormAsync();
            foreach (var pair in form)
            {
                if (pair.Key.Equals(OpenIddictConstants.Parameters.Prompt, StringComparison.Ordinal))
                {
                    continue;
                }

                foreach (var value in pair.Value)
                {
                    parameters.Add(new KeyValuePair<string, string?>(pair.Key, value));
                }
            }
        }

        var prompts = request.GetPromptValues()
            .Where(prompt => !string.Equals(prompt, OpenIddictConstants.PromptValues.Login, StringComparison.Ordinal))
            .ToArray();

        if (prompts.Length > 0)
        {
            parameters.Add(new KeyValuePair<string, string?>(
                OpenIddictConstants.Parameters.Prompt,
                string.Join(" ", prompts)));
        }

        return QueryHelpers.AddQueryString($"{Request.PathBase}{Request.Path}", parameters);
    }

    private async Task<ClaimsPrincipal> CreatePrincipalAsync(
        ApplicationUser user,
        OpenIddictRequest request,
        DateTimeOffset authenticationTime)
    {
        var principal = await signInManager.CreateUserPrincipalAsync(user);

        principal.SetClaim(OpenIddictConstants.Claims.Subject, user.Id);
        principal.SetClaim(OpenIddictConstants.Claims.PreferredUsername, user.UserName);
        principal.SetClaim(OpenIddictConstants.Claims.Name, $"{user.GivenName} {user.FamilyName}".Trim());
        principal.SetClaim(OpenIddictConstants.Claims.GivenName, user.GivenName);
        principal.SetClaim(OpenIddictConstants.Claims.FamilyName, user.FamilyName);
        principal.SetClaim(OpenIddictConstants.Claims.Email, user.Email);
        principal.SetClaim(OpenIddictConstants.Claims.EmailVerified, user.EmailConfirmed);
        principal.SetClaim(OpenIddictConstants.Claims.PhoneNumber, user.PhoneNumber);
        principal.SetClaim(OpenIddictConstants.Claims.PhoneNumberVerified, user.PhoneNumberConfirmed);

        principal.SetClaim(OpenIddictConstants.Claims.AuthenticationTime, authenticationTime.ToUnixTimeSeconds());

        var acrValues = request.GetParameter(OpenIddictConstants.Parameters.AcrValues)?.ToString();
        if (string.IsNullOrWhiteSpace(acrValues))
        {
            acrValues = request.AcrValues?.ToString();
        }

        var acr = (acrValues ?? string.Empty)
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(acr))
        {
            principal.SetClaim(AcrClaimType, acr);
        }

        if (IsUserInfoNameClaimRequested(request))
        {
            principal.SetClaim(UserInfoNameRequestedClaimType, "true");
        }

        principal.SetScopes(request.GetScopes());
        principal.SetResources("userinfo");
        principal.SetDestinations(GetDestinations);

        return principal;
    }

    private static IEnumerable<string> GetDestinations(Claim claim)
    {
        return claim.Type switch
        {
            OpenIddictConstants.Claims.Subject =>
            [
                OpenIddictConstants.Destinations.AccessToken,
                OpenIddictConstants.Destinations.IdentityToken
            ],

            OpenIddictConstants.Claims.AuthenticationTime =>
            [
                OpenIddictConstants.Destinations.IdentityToken
            ],

            AcrClaimType =>
            [
                OpenIddictConstants.Destinations.AccessToken,
                OpenIddictConstants.Destinations.IdentityToken
            ],

            UserInfoNameRequestedClaimType =>
            [
                OpenIddictConstants.Destinations.AccessToken
            ],

            OpenIddictConstants.Claims.Name or
            OpenIddictConstants.Claims.GivenName or
            OpenIddictConstants.Claims.FamilyName or
            OpenIddictConstants.Claims.PreferredUsername or
            OpenIddictConstants.Claims.Email or
            OpenIddictConstants.Claims.EmailVerified or
            OpenIddictConstants.Claims.PhoneNumber or
            OpenIddictConstants.Claims.PhoneNumberVerified or
            OpenIddictConstants.Claims.Address =>
            [
                OpenIddictConstants.Destinations.AccessToken
            ],

            _ => []
        };
    }

    private static bool IsUserInfoNameClaimRequested(OpenIddictRequest request)
    {
        var claims = request.GetParameter(OpenIddictConstants.Parameters.Claims)?.ToString();
        if (string.IsNullOrWhiteSpace(claims))
        {
            return false;
        }

        try
        {
            using var document = JsonDocument.Parse(claims);
            if (!document.RootElement.TryGetProperty("userinfo", out var userInfo) ||
                userInfo.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            return userInfo.TryGetProperty(OpenIddictConstants.Claims.Name, out _);
        }
        catch (JsonException)
        {
            return false;
        }
    }
}
