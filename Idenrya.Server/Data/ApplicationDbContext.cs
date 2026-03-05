using Idenrya.Server.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Idenrya.Server.Data;

public sealed class ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
    : IdentityDbContext<ApplicationUser>(options)
{
    public DbSet<ClientSecretRotationAuditEntry> ClientSecretRotationAudits => Set<ClientSecretRotationAuditEntry>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.UseOpenIddict();

        builder.Entity<ClientSecretRotationAuditEntry>(entity =>
        {
            entity.ToTable("ClientSecretRotationAudits");
            entity.HasKey(static entry => entry.Id);

            entity.Property(static entry => entry.ClientId)
                .HasMaxLength(100)
                .IsRequired();

            entity.Property(static entry => entry.Source)
                .HasMaxLength(32)
                .IsRequired();

            entity.Property(static entry => entry.RotatedAtUtc)
                .IsRequired();

            entity.HasIndex(static entry => entry.ClientId);
            entity.HasIndex(static entry => new { entry.ClientId, entry.RotatedAtUtc });
        });
    }
}
