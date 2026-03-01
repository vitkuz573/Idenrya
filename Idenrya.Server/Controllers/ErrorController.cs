using Idenrya.Server.Models;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Mvc;

namespace Idenrya.Server.Controllers;

[ApiExplorerSettings(IgnoreApi = true)]
public sealed class ErrorController : Controller
{
    [HttpGet("~/error")]
    [HttpPost("~/error")]
    public IActionResult Error()
    {
        var response = HttpContext.GetOpenIddictServerResponse();

        return View("Error", new ErrorViewModel
        {
            Error = response?.Error,
            ErrorDescription = response?.ErrorDescription
        });
    }
}
