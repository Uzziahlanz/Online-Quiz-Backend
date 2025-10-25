using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OnlineQuiz.Controllers;
using OnlineQuiz.Data;
using Xunit;

namespace OnlineQuiz.Tests.Controllers
{
    public class HealthControllerTests
    {
        private OnlineQuizDbContext CreateDbContext()
        {
            var options = new DbContextOptionsBuilder<OnlineQuizDbContext>()
                .UseInMemoryDatabase($"HealthControllerTests_{Guid.NewGuid()}")
                .Options;
            return new OnlineQuizDbContext(options);
        }

        private static T GetProperty<T>(object obj, string name)
        {
            var prop = obj.GetType().GetProperty(name);
            Assert.NotNull(prop);
            return (T)prop!.GetValue(obj)!;
        }

        [Fact]
        public async Task HealthCheck_ReturnsOkAndHealthy()
        {
            var context = CreateDbContext();
            var controller = new HealthController(context);

            var result = await controller.HealthCheck();
            var ok = Assert.IsType<OkObjectResult>(result);

            var status = GetProperty<string>(ok.Value!, "status");
            Assert.Equal("healthy", status);
            var database = GetProperty<object>(ok.Value!, "database");
            var connected = GetProperty<bool>(database, "connected");
            Assert.True(connected);
        }
    }
}