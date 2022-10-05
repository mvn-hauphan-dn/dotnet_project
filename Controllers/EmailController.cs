using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.AspNetCore.Mvc;
using MimeKit;
using MimeKit.Text;
using Project.Dtos;
using Project.Services;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Project.Controllers
{
    [Route("api/v1/[controller]")]
    public class EmailController : Controller
    {
        public readonly IEmailService _emailService;

        public EmailController(IEmailService emailService )
        {
            _emailService = emailService;
        }

        [HttpPost]
        public IActionResult SendEmail([FromBody] EmailDto request)
        {
            _emailService.SendEmail(request);
            return Ok();
        }
    }
}

