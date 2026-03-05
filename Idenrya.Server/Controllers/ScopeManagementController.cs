using Idenrya.Server.Models;
using Idenrya.Server.Models.Admin;
using Idenrya.Server.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Idenrya.Server.Controllers;

[ApiController]
[Route("api/admin/scopes")]
[Authorize(Roles = IdentityRoles.Administrator)]
public sealed class ScopeManagementController(
    IIdentityProviderScopeService scopeService) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<IReadOnlyList<OpenIdScopeResponse>>> List(CancellationToken cancellationToken)
    {
        var scopes = (await scopeService.GetSupportedScopesAsync(cancellationToken))
            .OrderBy(static scope => scope, StringComparer.Ordinal)
            .Select(static scope => new OpenIdScopeResponse { Name = scope })
            .ToArray();

        return Ok(scopes);
    }
}
