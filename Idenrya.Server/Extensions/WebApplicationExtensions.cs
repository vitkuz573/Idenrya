using Idenrya.Server.Data;
using Idenrya.Server.Middleware;
using Idenrya.Server.Services;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.EntityFrameworkCore;

namespace Idenrya.Server.Extensions;

public static class WebApplicationExtensions
{
    public static IApplicationBuilder UseIdenryaOpenIdCompatibility(this IApplicationBuilder app)
    {
        app.UseMiddleware<DiscoveryDocumentCompatibilityMiddleware>();
        app.UseMiddleware<AuthorizationRequestObjectMiddleware>();
        return app;
    }

    public static async Task InitializeIdenryaDataAsync(this WebApplication app)
    {
        var cancellationToken = app.Lifetime.ApplicationStopping;
        await using var scope = app.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var logger = scope.ServiceProvider
            .GetRequiredService<ILoggerFactory>()
            .CreateLogger("Idenrya.DatabaseInitialization");

        if (await IsLegacyEnsureCreatedDatabaseAsync(db, cancellationToken))
        {
            if (app.Environment.IsDevelopment() || app.Environment.IsEnvironment("Conformance"))
            {
                logger.LogWarning(
                    "Detected legacy database initialized via EnsureCreated() without migration history " +
                    "in environment '{Environment}'. Recreating database before applying migrations.",
                    app.Environment.EnvironmentName);
                await db.Database.EnsureDeletedAsync(cancellationToken);
            }
            else
            {
                throw new InvalidOperationException(
                    "Detected legacy database initialized with EnsureCreated() and without migration history. " +
                    "Run a one-time baseline/migration procedure before starting this environment.");
            }
        }

        await db.Database.MigrateAsync(cancellationToken);
        var seeder = scope.ServiceProvider.GetRequiredService<IIdentityProviderSeeder>();
        await seeder.SeedAsync(cancellationToken);
    }

    private static async Task<bool> IsLegacyEnsureCreatedDatabaseAsync(
        ApplicationDbContext db,
        CancellationToken cancellationToken)
    {
        if (!db.Database.IsRelational())
        {
            return false;
        }

        var creator = db.GetService<IRelationalDatabaseCreator>();
        if (!await creator.ExistsAsync(cancellationToken) ||
            !await creator.HasTablesAsync(cancellationToken))
        {
            return false;
        }

        var historyRepository = db.GetService<IHistoryRepository>();
        if (await historyRepository.ExistsAsync(cancellationToken))
        {
            return false;
        }

        return (await db.Database.GetPendingMigrationsAsync(cancellationToken)).Any();
    }
}
