using Idenrya.Server.Data;
using Idenrya.Server.Middleware;
using Idenrya.Server.Services;
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
        await using var scope = app.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        await db.Database.EnsureCreatedAsync();
        await SeedData.InitializeAsync(scope.ServiceProvider);
    }
}
