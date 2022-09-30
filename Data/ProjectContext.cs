using Microsoft.EntityFrameworkCore;
using Project.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

namespace Project.Data
{
    public class ProjectContext : IdentityDbContext<User>
    {   
        static ProjectContext()
        {
             AppContext.SetSwitch("Npgsql.EnableLegacyTimestampBehavior", true);
        }
        public ProjectContext(DbContextOptions<ProjectContext> options) : base(options)
        {
        }

        public DbSet<Pizza> Pizzas => Set<Pizza>();
        public DbSet<Topping> Toppings => Set<Topping>();
        public DbSet<Sauce> Sauces => Set<Sauce>();

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
        }
    }
}