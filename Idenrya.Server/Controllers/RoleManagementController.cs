using Idenrya.Server.Models;
using Idenrya.Server.Models.Admin;
using Idenrya.Server.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Idenrya.Server.Controllers;

[ApiController]
[Route("api/admin/roles")]
[Authorize(Roles = IdentityRoles.Administrator)]
public sealed class RoleManagementController(
    IIdentityProviderRoleService roleService) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<IReadOnlyList<OpenIdRoleResponse>>> List(CancellationToken cancellationToken)
    {
        return Ok(await roleService.ListAsync(cancellationToken));
    }

    [HttpPost]
    public async Task<ActionResult<OpenIdRoleResponse>> Create(
        [FromBody] CreateOpenIdRoleRequest request,
        CancellationToken cancellationToken)
    {
        try
        {
            var created = await roleService.CreateAsync(request, cancellationToken);
            return CreatedAtAction(nameof(List), new { name = created.Name }, created);
        }
        catch (ArgumentException exception)
        {
            ModelState.AddModelError(string.Empty, exception.Message);
            return ValidationProblem(ModelState);
        }
        catch (InvalidOperationException exception)
        {
            return Conflict(new ProblemDetails
            {
                Title = "Role operation failed",
                Detail = exception.Message,
                Status = StatusCodes.Status409Conflict
            });
        }
    }

    [HttpDelete("{roleName}")]
    public async Task<IActionResult> Delete(string roleName, CancellationToken cancellationToken)
    {
        try
        {
            return await roleService.DeleteAsync(roleName, cancellationToken) ? NoContent() : NotFound();
        }
        catch (ArgumentException exception)
        {
            ModelState.AddModelError(string.Empty, exception.Message);
            return ValidationProblem(ModelState);
        }
        catch (InvalidOperationException exception)
        {
            return Conflict(new ProblemDetails
            {
                Title = "Role operation failed",
                Detail = exception.Message,
                Status = StatusCodes.Status409Conflict
            });
        }
    }
}
