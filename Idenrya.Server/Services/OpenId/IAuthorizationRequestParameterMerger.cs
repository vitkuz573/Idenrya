namespace Idenrya.Server.Services.OpenId;

public interface IAuthorizationRequestParameterMerger
{
    Task<List<KeyValuePair<string, string?>>> MergeAsync(
        HttpRequest request,
        IReadOnlyDictionary<string, string?> requestObjectParameters,
        CancellationToken cancellationToken = default);
}
