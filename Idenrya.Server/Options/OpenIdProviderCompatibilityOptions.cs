namespace Idenrya.Server.Options;

public sealed class OpenIdProviderCompatibilityOptions
{
    public const string SectionName = "OpenIdProviderCompatibility";

    public bool RewriteDiscoveryRequestParameterSupported { get; set; } = true;

    public bool EnableRequestObjectParameterSupport { get; set; } = true;

    public bool RejectRequestUriParameter { get; set; } = true;
}
