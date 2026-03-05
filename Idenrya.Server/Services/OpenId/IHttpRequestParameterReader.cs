namespace Idenrya.Server.Services.OpenId;

public interface IHttpRequestParameterReader
{
    Task<string?> GetParameterAsync(HttpRequest request, string name, CancellationToken cancellationToken = default);

    Task<List<KeyValuePair<string, string?>>> GetParametersAsync(
        HttpRequest request,
        ISet<string> excludedParameters,
        CancellationToken cancellationToken = default);
}
