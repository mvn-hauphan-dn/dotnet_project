using Microsoft.AspNetCore.Identity;

namespace Project.Authentication
{
    public class ProjectUser: IdentityUser
    {
      [PersonalData]
      public string ? Name { get; set; }
      [PersonalData]
      public DateTime DOB { get; set; }
    }
}