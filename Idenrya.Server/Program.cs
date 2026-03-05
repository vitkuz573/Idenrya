using Idenrya.Server.Extensions;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddIdenryaIdentityProvider(builder.Configuration);

var app = builder.Build();

await app.InitializeIdenryaDataAsync();

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

app.UseStatusCodePagesWithReExecute("/error");
app.UseIdenryaOpenIdCompatibility();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
