namespace Idenrya.Server.Services;

public interface IIdentityProviderSeeder
{
    Task SeedAsync(CancellationToken cancellationToken = default);
}
