using Microsoft.EntityFrameworkCore;
using Project.Models;
using Project.Authentication;

namespace Project.Data
{
    public class ProjectContext : DbContext
    {
        public DbSet<Pizza> Pizzas => Set<Pizza>();
        public DbSet<Topping> Toppings => Set<Topping>();
        public DbSet<Sauce> Sauces => Set<Sauce>();

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
            => optionsBuilder.UseNpgsql("Host=localhost;Database=project;Username=postgres;Password=Trumgame9xqn98.");
    }
}