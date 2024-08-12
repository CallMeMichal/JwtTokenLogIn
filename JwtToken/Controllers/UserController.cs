using JwtToken.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
namespace JwtToken.Controllers
{
    public class UserController : Controller
    {
        private readonly ApplicationDbContext _dbContext;

        public UserController(ApplicationDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public IActionResult Login()
        {
            return View();
        }

        [AllowAnonymous]
        [HttpPost]
        public async Task<IActionResult> Login(User user)
        {
            var email = user.Email;
            var password = user.Pass;

            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(password))
            {
                ModelState.AddModelError("", "Please enter both email and password.");
                return View();
            }

            var appUserInfo = await _dbContext.Users
                .FirstOrDefaultAsync(u => u.Email == email && u.Pass == password);

            if (appUserInfo == null)
            {
                ViewBag.ErrorMessage = "User not found or invalid credentials. Please try again.";
                return View();
            }

            // Generowanie tokena JWT
            var role = appUserInfo.RoleId;
            var jwtToken = Authentication.GenerateJWTAuthentication(email, role.ToString());

            // Ustawienie ciasteczka JWT
            Response.Cookies.Append("jwt", jwtToken, new CookieOptions
            {
                HttpOnly = true,
                // Secure = true, // Odkomentuj, jeśli aplikacja działa przez HTTPS
            });

            // Ustawienie sesji użytkownika
            HttpContext.Session.SetString("UserID", appUserInfo.Id.ToString());
            HttpContext.Session.SetString("UserName", appUserInfo.Name);

            return RedirectToAction("LoggedIn");
        }


        [JwtAuthentication("1", "2")]
        public IActionResult LoggedIn()
        {

            if (HttpContext.Session.Id != null)
            {

                var userId = HttpContext.Session.GetString("UserID");
                var userName = HttpContext.Session.GetString("UserName");
                var jwtToken = HttpContext.Request.Cookies["jwt"];
                // Możesz ustawić dane w ViewBag,
                ViewBag.UserID = userId;
                ViewBag.UserName = userName;
                ViewBag.JwtToken = jwtToken;

                // Możesz również przekazać dane bezpośrednio do widoku
                // return View(new LoggedInViewModel { UserID = userId, UserName = userName });

                return View();
            }
            else
            {
                return RedirectToAction("Login");
            }
        }

        [HttpGet]
        [JwtAuthentication("2")]
        public IActionResult Create()
        {
            return View();
        }

        [HttpPost]
        [JwtAuthentication("2")]
        public IActionResult Create(User user)
        {
            if (ModelState.IsValid)
            {
                _dbContext.Users.Add(user);
                _dbContext.SaveChangesAsync();
                return RedirectToAction("LoggedIn");
            }

            return View(user);
        }
        [JwtAuthentication("1", "2")]
        public IActionResult Logout()
        {
            // Usunięcie ciasteczka JWT
            if (Request.Cookies.ContainsKey("jwt"))
            {
                Response.Cookies.Delete("jwt");
            }

            // Usunięcie sesji użytkownika
            HttpContext.Session.Clear();

            // Wylogowanie użytkownika
            //HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme).Wait();

            return RedirectToAction("Login", "User");
        }
    }
}