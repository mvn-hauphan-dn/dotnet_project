using Project.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Project.Services;
using Project.Dtos.Users;

namespace Project.Controllers
{
    [Route("api/v1/auth")]
    [ApiController]
    public class AuthenticateController : ControllerBase
    {
        private readonly UserManager<User> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailService _emailService;
        private readonly IUserService _userService;

        public AuthenticateController(
            UserManager<User> userManager,
            RoleManager<IdentityRole> roleManager,
            IEmailService emailService,
            IUserService userService)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _emailService = emailService;
            _userService = userService;
        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] Register register)
        {
            var response = await _userService.Register(register);

            if (response.StatusCode == 200)
                return Ok();

            return BadRequest(response.Errors);
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] Login login)
        {
            var response = await _userService.Login(login);

            if (response.StatusCode == 200)
                return Ok(new {
                    response.AccessToken,
                    response.Expiration
                });

            if (response.StatusCode == 404)
                return NotFound(response.Errors);

            return BadRequest(response.Errors);
        }

        [HttpGet]
        [Route("confirm-email")]
        public async Task<IActionResult> ConfirmEmail(string id, string token)
        {
            var response = await _userService.ConfirmEmail(id, token);

            if (response.StatusCode == 200)
                return Ok();

            if (response.StatusCode == 404)
                return NotFound(response.Errors);

            return BadRequest(response.Errors);
        }

        [HttpGet]
        [Route("reset-password")]
        public async Task<IActionResult> ResetPassword(string id, string token)
        {
            var response = await _userService.ResetPassword(id, token);

            if (response.StatusCode == 200)
                return Ok();

            if (response.StatusCode == 404)
                return NotFound(response.Errors);

            return BadRequest(response.Errors);
        }

            //[HttpPost]
            //[Route("login")]
            //public async Task<IActionResult> Login([FromBody] Login model)
            //{
            //    var user = await _userManager.FindByNameAsync(model.Username);

        //    if (user == null) return BadRequest("Invalid user name");

        //    if (await _userManager.CheckPasswordAsync(user, model.Password))
        //    {
        //        var userRoles = await _userManager.GetRolesAsync(user);

        //        var authClaims = new List<Claim>
        //        {
        //            new Claim(ClaimTypes.Name, user.UserName),
        //            new Claim(JwtRegisteredClaimNames.Jti,
        //                      Guid.NewGuid().ToString())
        //        };

        //        foreach (var userRole in userRoles)
        //        {
        //            authClaims.Add(new Claim(ClaimTypes.Role, userRole));
        //        }

        //        var token = GetToken(authClaims);
        //        var refreshToken = GenerateRefreshToken();

        //        _ = int.TryParse(_configuration["JWT:RefreshTokenValidityInDays"], out int refreshTokenValidityInDays);

        //        user.RefreshToken = refreshToken;
        //        user.RefreshTokenExpiryTime = DateTime.Now.AddDays(refreshTokenValidityInDays);

        //        await _userManager.UpdateAsync(user);

        //        return Ok(new
        //        {
        //            token = new JwtSecurityTokenHandler().WriteToken(token),
        //            RefreshToken = refreshToken,
        //            expiration = token.ValidTo
        //        });
        //    }
        //    return Unauthorized();
        //}

        //[HttpPost]
        //[Route("register-admin")]
        //public async Task<IActionResult> RegisterAdmin([FromBody] Register model)
        //{
        //    var userExists = await _userManager.FindByNameAsync(model.Username);
        //    if (userExists != null)
        //        return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User already exists!" });

        //    User user = new()
        //    {
        //        Email = model.Email,
        //        SecurityStamp = Guid.NewGuid().ToString(),
        //        UserName = model.Username
        //    };
        //    var result = await _userManager.CreateAsync(user, model.Password);
        //    if (!result.Succeeded)
        //        return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });

        //    if (!await _roleManager.RoleExistsAsync("Admin"))
        //        await _roleManager.CreateAsync(new IdentityRole("Admin"));
        //    if (!await _roleManager.RoleExistsAsync("User"))
        //        await _roleManager.CreateAsync(new IdentityRole("User"));

        //    if (await _roleManager.RoleExistsAsync("Admin"))
        //    {
        //        await _userManager.AddToRoleAsync(user, "Admin");
        //    }
        //    if (await _roleManager.RoleExistsAsync("Admin"))
        //    {
        //        await _userManager.AddToRoleAsync(user, "User");
        //    }
        //    return Ok(new Response { Status = "Success", Message = "User created successfully!" });
        //}

        //    [HttpPost]
        //    [Route("refresh-token")]
        //    public async Task<IActionResult> RefreshToken(Token tokenModel)
        //    {
        //        if (tokenModel is null)
        //        {
        //            return BadRequest("Invalid client request");
        //        }

        //        string accessToken = tokenModel.AccessToken!;
        //        string? refreshToken = tokenModel.RefreshToken;

        //        var principal = GetPrincipalFromExpiredToken(accessToken);
        //        if (principal == null)
        //        {
        //            return BadRequest("Invalid access token or refresh token");
        //        }

        //        string? username = principal.Identity!.Name;

        //        var user = await _userManager.FindByNameAsync(username);

        //        if (user == null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
        //        {
        //            return BadRequest("Invalid access token or refresh token");
        //        }

        //        var newAccessToken = GetToken(principal.Claims.ToList());
        //        var newRefreshToken = GenerateRefreshToken();

        //        user.RefreshToken = newRefreshToken;
        //        await _userManager.UpdateAsync(user);

        //        return new ObjectResult(new
        //        {
        //            accessToken = new JwtSecurityTokenHandler().WriteToken(newAccessToken),
        //            refreshToken = newRefreshToken
        //        });
        //    }

        //    [Authorize]
        //    [HttpPost]
        //    [Route("revoke/{username}")]
        //    public async Task<IActionResult> Revoke(string username)
        //    {
        //        var user = await _userManager.FindByNameAsync(username);
        //        if (user == null) return BadRequest("Invalid user name");

        //        user.RefreshToken = null;
        //        await _userManager.UpdateAsync(user);

        //        return NoContent();
        //    }

        //    [Authorize]
        //    [HttpPost]
        //    [Route("revoke-all")]
        //    public async Task<IActionResult> RevokeAll()
        //    {
        //        var users = _userManager.Users.ToList();
        //        foreach (var user in users)
        //        {
        //            user.RefreshToken = null;
        //            await _userManager.UpdateAsync(user);
        //        }

        //        return NoContent();
        //    }

        //    [Authorize(Roles = "Admin")]
        //    [HttpPost]
        //    [Route("reset-password-admin")]
        //    public async Task<IActionResult> ResetPasswordAdmin([FromBody] ResetPasswordAdmin model)
        //    {
        //        var user = await _userManager.FindByNameAsync(model.Username);

        //        if(user == null) return NotFound("Invalid user name.");

        //        if (string.Compare(model.NewPassword, model.ConfirmNewPassword) != 0) return BadRequest("Password and confirm password doesn't match.");

        //        var token = await _userManager.GeneratePasswordResetTokenAsync(user);

        //        var result = await _userManager.ResetPasswordAsync(user, token, model.NewPassword);

        //        if (!result.Succeeded)
        //        {
        //            var errors = new List<string>();

        //            foreach (var error in result.Errors) errors.Add(error.Description);

        //            return Unauthorized("Invalid token.");
        //        }

        //        return Ok("Password reset successfully.");
        //    }

        //    [HttpPost]
        //    [Route("reset-password-token")]
        //    public async Task<IActionResult> ResetPasswordToken([FromBody] ResetPasswordToken model)
        //    {
        //        var user = await _userManager.FindByNameAsync(model.Username);

        //        if (user == null) return NotFound("Invalid user name.");

        //        var token = await _userManager.GeneratePasswordResetTokenAsync(user);

        //        EmailDto email = new EmailDto();

        //        email.To = user.Email;
        //        email.Subject = "Reset Password";
        //        email.Body = token;

        //        _emailService.SendEmail(email);

        //        return Ok("Check your email.");
        //    }

        //    [HttpPost]
        //    [Route("reset-password-user")]
        //    public async Task<IActionResult> ResetPasswordUser([FromBody] ResetPasswordUser model)
        //    {
        //        var user = await _userManager.FindByNameAsync(model.Username);

        //        if (user == null) return NotFound("Invalid user name.");

        //        if (string.Compare(model.NewPassword, model.ConfirmNewPassword) != 0) return BadRequest("Password and confirm password doesn't match.");

        //        if (string.IsNullOrEmpty(model.Token)) return Unauthorized("Invalid token.");

        //        var result = await _userManager.ResetPasswordAsync(user, model.Token, model.NewPassword);

        //        if (!result.Succeeded)
        //        {
        //            var errors = new List<string>();

        //            foreach (var error in result.Errors) errors.Add(error.Description);

        //            return Unauthorized("Invalid token.");
        //        }

        //        return Ok("Password reset successfully.");
        //    }

        //    [HttpPost]
        //    [Route("confirm-email")]
        //    public async Task<IActionResult> ConfirmEmail([FromBody] ResetPasswordToken model)
        //    {
        //        var user = await _userManager.FindByNameAsync(model.Username);

        //        if (user == null) return NotFound("Invalid user name.");

        //        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

        //        EmailDto email = new EmailDto();

        //        email.To = user.Email;
        //        email.Subject = "Reset Password";
        //        email.Body = token;

        //        _emailService.SendEmail(email);

        //        return Ok("Check your email.");
        //    }

        //    private JwtSecurityToken GetToken(List<Claim> authClaims)
        //    {
        //        var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

        //        var token = new JwtSecurityToken(
        //            issuer: _configuration["JWT:ValidIssuer"],
        //            audience: _configuration["JWT:ValidAudience"],
        //            expires: DateTime.Now.AddHours(3),
        //            claims: authClaims,
        //            signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
        //            );

        //        return token;
        //    }

        //    private static string GenerateRefreshToken()
        //    {
        //        var randomNumber = new byte[64];
        //        using var rng = RandomNumberGenerator.Create();
        //        rng.GetBytes(randomNumber);

        //        return Convert.ToBase64String(randomNumber);
        //    }

        //    private ClaimsPrincipal? GetPrincipalFromExpiredToken(string? token)
        //    {
        //        var tokenValidationParameters = new TokenValidationParameters
        //        {
        //            ValidateAudience = false,
        //            ValidateIssuer = false,
        //            ValidateIssuerSigningKey = true,
        //            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"])),
        //            ValidateLifetime = false
        //        };

        //        var tokenHandler = new JwtSecurityTokenHandler();
        //        var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
        //        if (securityToken is not JwtSecurityToken jwtSecurityToken || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
        //            throw new SecurityTokenException("Invalid token");

        //        return principal;
        //    }
        }
}