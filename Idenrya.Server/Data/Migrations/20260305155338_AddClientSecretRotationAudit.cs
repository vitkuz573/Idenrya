using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Idenrya.Server.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddClientSecretRotationAudit : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ClientSecretRotationAudits",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    ClientId = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    RotatedAtUtc = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    Source = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ClientSecretRotationAudits", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ClientSecretRotationAudits_ClientId",
                table: "ClientSecretRotationAudits",
                column: "ClientId");

            migrationBuilder.CreateIndex(
                name: "IX_ClientSecretRotationAudits_ClientId_RotatedAtUtc",
                table: "ClientSecretRotationAudits",
                columns: new[] { "ClientId", "RotatedAtUtc" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ClientSecretRotationAudits");
        }
    }
}
