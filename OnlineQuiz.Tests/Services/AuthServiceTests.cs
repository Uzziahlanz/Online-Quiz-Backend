using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Moq;
using OnlineQuiz.Configuration;
using OnlineQuiz.Data;
using OnlineQuiz.DTOs;
using OnlineQuiz.IRepository;
using OnlineQuiz.Models;
using OnlineQuiz.Models.Response;
using OnlineQuiz.Services;
using Xunit;

namespace OnlineQuiz.Tests.Services
{
    public class AuthServiceTests
    {
        public AuthServiceTests()
        {
            // Ensure pepper is set for refresh token hashing/verification
            // Use a valid Base64 string for pepper
            Environment.SetEnvironmentVariable("REFRESH_TOKEN_PEPPER", "dGVzdC1wZXBwZXI=");
        }
        private OnlineQuizDbContext CreateDbContext()
        {
            var options = new DbContextOptionsBuilder<OnlineQuizDbContext>()
                .UseInMemoryDatabase($"AuthServiceTests_{Guid.NewGuid()}")
                .Options;
            return new OnlineQuizDbContext(options);
        }

        private IConfiguration CreateConfig()
        {
            var inMemorySettings = new Dictionary<string, string?>
            {
                {"JwtSettings:Issuer", "TestIssuer"},
                {"JwtSettings:Audience", "TestAudience"},
                {"JwtSettings:SecretKey", "a-very-long-secret-key-for-tests-1234567890"},
                {"JwtSettings:AccessTokenExpirationInMinutes", "15"},
                {"JwtSettings:RefreshTokenExpirationInDays", "7"},
            };
            return new ConfigurationBuilder().AddInMemoryCollection(inMemorySettings!).Build();
        }

        private UserModel SeedUser(OnlineQuizDbContext context)
        {
            var role = new RoleModel { RoleId = 1, Name = "Admin" };
            var user = new UserModel
            {
                UserId = 100,
                Email = "user@example.com",
                FullName = "Test User",
                PasswordHash = OnlineQuiz.Utilities.PasswordHelper.HashPassword("password"),
                Status = "Active",
                UserRoles = new List<UserRoleModel> { new UserRoleModel { Role = role, RoleId = role.RoleId, UserId = 100 } }
            };
            context.Roles.Add(role);
            context.Users.Add(user);
            context.SaveChanges();
            return user;
        }

        [Fact]
        public async Task AuthenticateAsync_ReturnsTokensAndUserSummary_OnValidCredentials()
        {
            // Arrange
            var context = CreateDbContext();
            var configuration = CreateConfig();
            var user = SeedUser(context);

            var loginRepoMock = new Mock<ILoginRepository>();
            var loginDto = new LoginDto { Email = user.Email!, Password = "password" };
            var loginResponse = new LoginResponseDto
            {
                AccessToken = "dummy",
                User = new UserSummaryDto { Id = user.UserId, Email = user.Email!, FullName = user.FullName!, Roles = new List<string> { "Admin" } },
            };
            loginRepoMock.Setup(r => r.AuthenticateAsync(It.IsAny<LoginDto>()))
                .ReturnsAsync(new ServiceResponse<LoginResponseDto>
                {
                    Success = true,
                    Data = loginResponse,
                    Message = "OK"
                });

            var service = new AuthService(loginRepoMock.Object, configuration, context);

            // Act
            var result = await service.AuthenticateAsync(loginDto);

            // Assert
            Assert.True(result.Success);
            Assert.NotNull(result.Data);
            Assert.False(string.IsNullOrEmpty(result.Data!.AccessToken));
            Assert.NotNull(result.Data.RefreshToken);
            Assert.Equal("Bearer", result.Data.TokenType);
            Assert.True(result.Data.ExpiresIn > 0);
            Assert.True(result.Data.RefreshExpiresIn > 0);

            // Verify refresh token stored hashed
            var stored = await context.RefreshTokens.FirstOrDefaultAsync(rt => rt.UserId == user.UserId);
            Assert.NotNull(stored);
            Assert.NotEqual(result.Data.RefreshToken, stored!.TokenHash);
        }

        [Fact]
        public async Task AuthenticateAsync_InvalidInput_ReturnsError()
        {
            var context = CreateDbContext();
            var configuration = CreateConfig();
            var loginRepoMock = new Mock<ILoginRepository>();

            var service = new AuthService(loginRepoMock.Object, configuration, context);

            var result = await service.AuthenticateAsync(new LoginDto { Email = "", Password = "" });
            Assert.False(result.Success);
            Assert.Equal("Email is required", result.Message);
        }

        [Fact]
        public async Task ValidateUserCredentialsAsync_DelegatesToRepository()
        {
            var context = CreateDbContext();
            var configuration = CreateConfig();
            var loginRepoMock = new Mock<ILoginRepository>();
            loginRepoMock.Setup(r => r.ValidateUserCredentialsAsync("e@x.com", "p"))
                .ReturnsAsync(new ServiceResponse<UserModel> { Success = true, Data = new UserModel { UserId = 1 } });

            var service = new AuthService(loginRepoMock.Object, configuration, context);
            var result = await service.ValidateUserCredentialsAsync("e@x.com", "p");
            Assert.True(result.Success);
            Assert.NotNull(result.Data);
        }

        [Fact]
        public async Task RefreshTokenAsync_InvalidToken_ReturnsError()
        {
            var context = CreateDbContext();
            var configuration = CreateConfig();
            var loginRepoMock = new Mock<ILoginRepository>();
            var service = new AuthService(loginRepoMock.Object, configuration, context);

            var res = await service.RefreshTokenAsync(new RefreshTokenDto { RefreshToken = "invalid" });
            Assert.False(res.Success);
            Assert.Equal("Invalid or expired refresh token", res.Message);
        }

        [Fact]
        public async Task RefreshTokenAsync_ValidToken_ReturnsNewTokens()
        {
            var context = CreateDbContext();
            var configuration = CreateConfig();
            var user = SeedUser(context);

            var loginRepoMock = new Mock<ILoginRepository>();
            var loginDto = new LoginDto { Email = user.Email!, Password = "password" };
            var loginResponse = new LoginResponseDto
            {
                AccessToken = "dummy",
                User = new UserSummaryDto { Id = user.UserId, Email = user.Email!, FullName = user.FullName!, Roles = new List<string> { "Admin" } },
            };
            loginRepoMock.Setup(r => r.AuthenticateAsync(It.IsAny<LoginDto>()))
                .ReturnsAsync(new ServiceResponse<LoginResponseDto>
                {
                    Success = true,
                    Data = loginResponse,
                    Message = "OK"
                });

            var service = new AuthService(loginRepoMock.Object, configuration, context);

            // First authenticate to create a stored refresh token
            var auth = await service.AuthenticateAsync(loginDto);
            Assert.True(auth.Success);
            Assert.NotNull(auth.Data!.RefreshToken);

            // Use the returned refresh token to request new tokens
            var refresh = await service.RefreshTokenAsync(new RefreshTokenDto { RefreshToken = auth.Data.RefreshToken! });
            Assert.True(refresh.Success);
            Assert.NotNull(refresh.Data);
            Assert.False(string.IsNullOrEmpty(refresh.Data!.AccessToken));
            Assert.False(string.IsNullOrEmpty(refresh.Data.RefreshToken));
            Assert.Equal("Bearer", refresh.Data.TokenType);
            Assert.True(refresh.Data.ExpiresIn > 0);
            Assert.True(refresh.Data.RefreshExpiresIn > 0);

            // Verify old token revoked and new token stored hashed
            var tokens = await context.RefreshTokens.Where(rt => rt.UserId == user.UserId).ToListAsync();
            Assert.Contains(tokens, t => t.RevokedAt != null);
            var latest = tokens.OrderByDescending(t => t.CreatedAt).First();
            Assert.NotEqual(refresh.Data.RefreshToken, latest.TokenHash);
        }

        [Fact]
        public async Task LogoutAsync_RevokesActiveRefreshTokens()
        {
            var context = CreateDbContext();
            var configuration = CreateConfig();
            var user = SeedUser(context);

            var loginRepoMock = new Mock<ILoginRepository>();
            loginRepoMock.Setup(r => r.AuthenticateAsync(It.IsAny<LoginDto>()))
                .ReturnsAsync(new ServiceResponse<LoginResponseDto>
                {
                    Success = true,
                    Data = new LoginResponseDto
                    {
                        AccessToken = "dummy",
                        User = new UserSummaryDto { Id = user.UserId, Email = user.Email!, FullName = user.FullName!, Roles = new List<string> { "Admin" } }
                    },
                    Message = "OK"
                });

            var service = new AuthService(loginRepoMock.Object, configuration, context);

            // Create a refresh token
            var authRes = await service.AuthenticateAsync(new LoginDto { Email = user.Email!, Password = "password" });
            Assert.True(authRes.Success);

            // Verify token initially active
            var before = await context.RefreshTokens.Where(rt => rt.UserId == user.UserId).ToListAsync();
            Assert.NotEmpty(before);
            Assert.All(before, t => Assert.Null(t.RevokedAt));

            var logout = await service.LogoutAsync(user.UserId);
            Assert.Equal("Logged out successfully", logout.Message);

            var after = await context.RefreshTokens.Where(rt => rt.UserId == user.UserId).ToListAsync();
            Assert.NotEmpty(after);
            Assert.All(after, t => Assert.NotNull(t.RevokedAt));
        }

        [Fact]
        public async Task GenerateJwtTokenAsync_ReturnsTokenString()
        {
            var context = CreateDbContext();
            var configuration = CreateConfig();
            var loginRepoMock = new Mock<ILoginRepository>();
            var service = new AuthService(loginRepoMock.Object, configuration, context);

            var user = new UserModel { UserId = 123, Email = "jwt@example.com", FullName = "JWT User" };
            var res = await service.GenerateJwtTokenAsync(user);

            var tokenString = res.Data ?? res.Message;
            Assert.False(string.IsNullOrEmpty(tokenString));
            // Basic JWT format check: three dot-separated Base64Url parts
            Assert.Matches("^[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+$", tokenString!);
        }

        [Fact]
        public async Task GenerateJwtTokenAsync_MissingSecret_ReturnsError()
        {
            var context = CreateDbContext();
            var inMemorySettings = new Dictionary<string, string?>
            {
                {"JwtSettings:Issuer", "TestIssuer"},
                {"JwtSettings:Audience", "TestAudience"},
                // Intentionally omit SecretKey
                {"JwtSettings:AccessTokenExpirationInMinutes", "15"},
                {"JwtSettings:RefreshTokenExpirationInDays", "7"},
            };
            var configuration = new ConfigurationBuilder().AddInMemoryCollection(inMemorySettings!).Build();
            var service = new AuthService(new Mock<ILoginRepository>().Object, configuration, context);

            var res = await service.GenerateJwtTokenAsync(new UserModel { UserId = 1, Email = "x@example.com", FullName = "X" });
            Assert.False(res.Success);
            Assert.Equal("JWT secret key not configured", res.Message);
        }
    }
}