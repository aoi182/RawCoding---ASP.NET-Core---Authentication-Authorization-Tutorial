using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace MyWebApp.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        [Authorize]
        public ActionResult Secret()
        {
            return View();
        }

        [Authorize(Policy = "Claim.DoB")]
        public ActionResult SecretPolicy()
        {
            return View(nameof(Secret));
        }

        [Authorize(Roles = "Admin")]
        public ActionResult SecretRole()
        {
            return View(nameof(Secret));
        }

        [Authorize(Policy = "Claim.Role.Admin")]
        public ActionResult SecretAdminPolicy()
        {
            return View(nameof(Secret));
        }

        [AllowAnonymous]
        public ActionResult Authenticate()
        {
            var grandmaClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, "Bob"),
                new Claim(ClaimTypes.Email, "Bob@fmail.co"),
                new Claim(ClaimTypes.DateOfBirth, "11/11/2000"),
                new Claim(ClaimTypes.Role, "Admin"),
                new Claim("Grandma.Says", "Vwery nice boy."),
            };

            var licenseClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, "Bob-182"),
                new Claim("DrivingLicense", "A8457+?++2."),
            };

            var grandmaIdentity = new ClaimsIdentity(grandmaClaims, "Grandma Identity");
            var licenseIdentity = new ClaimsIdentity(licenseClaims, "Government");


            var userPrincipal = new ClaimsPrincipal(new[] { grandmaIdentity, licenseIdentity });

            HttpContext.SignInAsync(userPrincipal);

            return RedirectToAction("Index");
        }

        public async Task<IActionResult> DoStuff([FromServices]IAuthorizationService authorizationService)
        {
            var builder = new AuthorizationPolicyBuilder("Schema");
            var customPolicy = builder.RequireClaim("Hello").Build();

            var authResult = await authorizationService.AuthorizeAsync(User, customPolicy);

            if (authResult.Succeeded)
            {
                return View("Index");
            }

            return View("Index");
        }
    }
}