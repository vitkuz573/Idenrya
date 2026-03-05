using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
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
        IConfiguration configuration,
        IHostEnvironment hostEnvironment)
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
        services.AddOpenIddictServer(configuration, hostEnvironment);

        services.AddScoped<IHttpRequestParameterReader, HttpRequestParameterReader>();
        services.AddScoped<IRequestObjectParser, RequestObjectParser>();
        services.AddScoped<IAuthorizationErrorRedirectUriBuilder, AuthorizationErrorRedirectUriBuilder>();
        services.AddScoped<IAuthorizationRequestParameterMerger, AuthorizationRequestParameterMerger>();
        services.AddScoped<IAuthorizationRequestObjectResolver, AuthorizationRequestObjectResolver>();
        services.AddSingleton<IIdentityProviderScopeService, IdentityProviderScopeService>();
        services.AddScoped<IIdentityProviderClientSecretAuditService, IdentityProviderClientSecretAuditService>();
        services.AddScoped<IIdentityProviderClientService, IdentityProviderClientService>();
        services.AddScoped<IIdentityProviderUserService, IdentityProviderUserService>();
        services.AddScoped<IIdentityProviderRoleService, IdentityProviderRoleService>();
        services.AddScoped<IIdentityProviderSeeder, IdentityProviderSeeder>();

        return services;
    }

    private static void AddOpenIddictServer(
        this IServiceCollection services,
        IConfiguration configuration,
        IHostEnvironment hostEnvironment)
    {
        var identityProviderOptions =
            configuration.GetSection(IdentityProviderOptions.SectionName).Get<IdentityProviderOptions>()
            ?? new IdentityProviderOptions();
        var supportedScopes = IdentityProviderScopeNormalizer.NormalizeSupportedScopes(identityProviderOptions.SupportedScopes);

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

                options.RegisterScopes(supportedScopes);

                ConfigureServerCredentials(options, identityProviderOptions.Credentials, hostEnvironment.ContentRootPath);

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

    private static void ConfigureServerCredentials(
        OpenIddictServerBuilder options,
        IdentityProviderCredentialsOptions credentials,
        string contentRootPath)
    {
        var signingCertificate = TryLoadCertificate(credentials.SigningCertificate, contentRootPath);
        var encryptionCertificate = TryLoadCertificate(credentials.EncryptionCertificate, contentRootPath);

        if (signingCertificate is not null)
        {
            options.AddSigningCertificate(signingCertificate);
        }

        if (encryptionCertificate is not null)
        {
            options.AddEncryptionCertificate(encryptionCertificate);
        }

        if (signingCertificate is not null && encryptionCertificate is not null)
        {
            return;
        }

        if (!credentials.AllowDevelopmentCertificates)
        {
            throw new InvalidOperationException(
                "IdentityProvider credentials are not configured. Set both signing and encryption certificates " +
                "or enable IdentityProvider:Credentials:AllowDevelopmentCertificates for non-production usage.");
        }

        if (signingCertificate is null)
        {
            options.AddDevelopmentSigningCertificate();
        }

        if (encryptionCertificate is null)
        {
            options.AddDevelopmentEncryptionCertificate();
        }
    }

    private static X509Certificate2? TryLoadCertificate(
        IdentityProviderCertificateOptions certificateOptions,
        string contentRootPath)
    {
        if (string.IsNullOrWhiteSpace(certificateOptions.Path))
        {
            return null;
        }

        var path = certificateOptions.Path!;
        if (!Path.IsPathRooted(path))
        {
            path = Path.Combine(contentRootPath, path);
        }

        if (!File.Exists(path))
        {
            throw new InvalidOperationException($"Certificate file not found: '{path}'.");
        }

        var storageFlags = X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable;
        var extension = Path.GetExtension(path);

        if (string.Equals(extension, ".pfx", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(extension, ".p12", StringComparison.OrdinalIgnoreCase) ||
            !string.IsNullOrWhiteSpace(certificateOptions.Password))
        {
            return X509CertificateLoader.LoadPkcs12FromFile(
                path,
                certificateOptions.Password ?? string.Empty,
                storageFlags,
                Pkcs12LoaderLimits.Defaults);
        }

        return X509CertificateLoader.LoadCertificateFromFile(path);
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
