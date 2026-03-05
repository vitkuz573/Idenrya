using System.Security.Claims;
using Idenrya.Server.Data;
using Idenrya.Server.Models;
using Idenrya.Server.Options;
using Idenrya.Server.Services;
using Idenrya.Server.Services.OpenId;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;

namespace Idenrya.Server.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddIdenryaIdentityProvider(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.Configure<IdentityProviderOptions>(
            configuration.GetSection(IdentityProviderOptions.SectionName));
        services.Configure<OpenIdProviderCompatibilityOptions>(
            configuration.GetSection(OpenIdProviderCompatibilityOptions.SectionName));

        services.AddDbContext<ApplicationDbContext>(options =>
        {
            options.UseSqlite(configuration.GetConnectionString("DefaultConnection") ?? "Data Source=idenrya.db");
            options.UseOpenIddict();
        });

        services
            .AddIdentity<ApplicationUser, IdentityRole>(options =>
            {
                options.Password.RequiredLength = 3;
                options.Password.RequireDigit = false;
                options.Password.RequireLowercase = false;
                options.Password.RequireUppercase = false;
                options.Password.RequireNonAlphanumeric = false;
                options.User.RequireUniqueEmail = true;
            })
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();

        services.ConfigureApplicationCookie(options =>
        {
            options.LoginPath = "/account/login";
            options.AccessDeniedPath = "/account/login";
        });

        services.AddControllersWithViews();
        services.AddOpenIddictServer(configuration);

        services.AddScoped<IHttpRequestParameterReader, HttpRequestParameterReader>();
        services.AddScoped<IRequestObjectParser, RequestObjectParser>();
        services.AddScoped<IAuthorizationErrorRedirectUriBuilder, AuthorizationErrorRedirectUriBuilder>();
        services.AddScoped<IAuthorizationRequestParameterMerger, AuthorizationRequestParameterMerger>();
        services.AddScoped<IAuthorizationRequestObjectResolver, AuthorizationRequestObjectResolver>();
        services.AddScoped<IIdentityProviderSeeder, IdentityProviderSeeder>();

        return services;
    }

    private static void AddOpenIddictServer(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOpenIddict()
            .AddCore(options =>
            {
                options.UseEntityFrameworkCore()
                    .UseDbContext<ApplicationDbContext>();
            })
            .AddServer(options =>
            {
                var issuer = configuration[$"{IdentityProviderOptions.SectionName}:Issuer"];
                if (!string.IsNullOrWhiteSpace(issuer))
                {
                    options.SetIssuer(new Uri(issuer));
                }

                options.SetAuthorizationEndpointUris("/connect/authorize");
                options.SetTokenEndpointUris("/connect/token");
                options.SetUserInfoEndpointUris("/connect/userinfo");
                options.SetIntrospectionEndpointUris("/connect/introspect");
                options.SetRevocationEndpointUris("/connect/revocation");
                options.SetEndSessionEndpointUris("/connect/logout");

                options.AllowAuthorizationCodeFlow();
                options.AllowRefreshTokenFlow();

                options.RegisterScopes(
                    OpenIddictConstants.Scopes.OpenId,
                    OpenIddictConstants.Scopes.Profile,
                    OpenIddictConstants.Scopes.Email,
                    OpenIddictConstants.Scopes.Address,
                    OpenIddictConstants.Scopes.Phone,
                    OpenIddictConstants.Scopes.OfflineAccess);

                options.AddDevelopmentEncryptionCertificate();
                options.AddDevelopmentSigningCertificate();

                options.UseAspNetCore()
                    .EnableAuthorizationEndpointPassthrough()
                    .EnableTokenEndpointPassthrough()
                    .EnableUserInfoEndpointPassthrough()
                    .EnableEndSessionEndpointPassthrough()
                    .EnableStatusCodePagesIntegration();

                options.AddEventHandler<OpenIddictServerEvents.GenerateTokenContext>(builder => builder
                    .UseInlineHandler(static context =>
                    {
                        if (context.Principal is null || !IsIdentityToken(context.TokenType))
                        {
                            return default;
                        }

                        RemoveOpenIddictPrivateClaims(context.Principal);
                        RemoveOpenIddictPrivateClaims(context.SecurityTokenDescriptor);
                        return default;
                    })
                    .SetOrder(OpenIddictServerHandlers.Protection.AttachTokenMetadata.Descriptor.Order + 500));
            })
            .AddValidation(options =>
            {
                options.UseLocalServer();
                options.UseAspNetCore();
            });
    }

    private static void RemoveOpenIddictPrivateClaims(ClaimsPrincipal principal)
    {
        foreach (var identity in principal.Identities)
        {
            var claims = identity.Claims
                .Where(static claim => claim.Type.StartsWith("oi_", StringComparison.Ordinal))
                .ToArray();

            foreach (var claim in claims)
            {
                identity.RemoveClaim(claim);
            }
        }
    }

    private static void RemoveOpenIddictPrivateClaims(SecurityTokenDescriptor descriptor)
    {
        if (descriptor.Subject is not null)
        {
            var subjectClaims = descriptor.Subject.Claims
                .Where(static claim => claim.Type.StartsWith("oi_", StringComparison.Ordinal))
                .ToArray();

            foreach (var claim in subjectClaims)
            {
                descriptor.Subject.RemoveClaim(claim);
            }
        }

        if (descriptor.Claims is null || descriptor.Claims.Count == 0)
        {
            return;
        }

        var privateClaimKeys = descriptor.Claims.Keys
            .Where(static key => key.StartsWith("oi_", StringComparison.Ordinal))
            .ToArray();

        foreach (var key in privateClaimKeys)
        {
            descriptor.Claims.Remove(key);
        }
    }

    private static bool IsIdentityToken(string? tokenType)
    {
        return string.Equals(tokenType, OpenIddictConstants.TokenTypeIdentifiers.IdentityToken, StringComparison.Ordinal) ||
               string.Equals(tokenType, OpenIddictConstants.Parameters.IdToken, StringComparison.Ordinal) ||
               string.Equals(tokenType, OpenIddictConstants.ResponseTypes.IdToken, StringComparison.Ordinal);
    }
}
