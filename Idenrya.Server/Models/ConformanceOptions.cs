namespace Idenrya.Server.Models;

public sealed class ConformanceOptions
{
    public const string SectionName = "Conformance";

    public string Issuer { get; set; } = "https://oidcc-provider:3000";

    public string CallbackBaseUrl { get; set; } = "https://nginx:8443/test/a/idenrya-basic";

    public string? CallbackBaseUrl2 { get; set; }

    public string ClientId { get; set; } = "idenrya-basic-client";

    public string ClientSecret { get; set; } = "idenrya-basic-secret";

    public string Client2Id { get; set; } = "idenrya-basic-client-2";

    public string Client2Secret { get; set; } = "idenrya-basic-secret-2";

    public string RedirectUri => $"{CallbackBaseUrl.TrimEnd('/')}/callback";

    public string RedirectUri2 => $"{(CallbackBaseUrl2 ?? CallbackBaseUrl).TrimEnd('/')}/callback";

    public IEnumerable<string> GetKnownRedirectUris()
    {
        yield return RedirectUri;
        yield return RedirectUri2;
    }
}
