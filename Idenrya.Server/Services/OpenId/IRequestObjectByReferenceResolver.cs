namespace Idenrya.Server.Services.OpenId;

public interface IRequestObjectByReferenceResolver
{
    Task<RequestObjectByReferenceResolutionResult> ResolveAsync(
        HttpRequest request,
        string requestUri,
        CancellationToken cancellationToken = default);
}

public sealed class RequestObjectByReferenceResolutionResult
{
    private RequestObjectByReferenceResolutionResult(
        IReadOnlyDictionary<string, string?>? parameters,
        string? error)
    {
        Parameters = parameters;
        Error = error;
    }

    public IReadOnlyDictionary<string, string?>? Parameters { get; }

    public string? Error { get; }

    public bool IsSuccess => Parameters is not null && string.IsNullOrWhiteSpace(Error);

    public static RequestObjectByReferenceResolutionResult Success(IReadOnlyDictionary<string, string?> parameters)
    {
        return new RequestObjectByReferenceResolutionResult(parameters, null);
    }

    public static RequestObjectByReferenceResolutionResult Failure(string error)
    {
        return new RequestObjectByReferenceResolutionResult(null, error);
    }
}
