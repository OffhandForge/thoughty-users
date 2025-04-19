package com.biezbardis.thoughtyusers;

import com.biezbardis.thoughtyusers.dto.AuthenticationResponse;
import com.biezbardis.thoughtyusers.utils.JsonToObjectMapper;
import com.biezbardis.thoughtyusers.utils.JwtUtils;
import com.redis.testcontainers.RedisContainer;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.util.Arrays;
import java.util.Date;

import static org.hamcrest.Matchers.matchesPattern;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@AutoConfigureMockMvc
public class ThoughtyUsersApplicationTests {

    public static final String TOKEN_PATTERN = "^eyJhbG[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_.+/=]*$";
    public static final String UUID_REGEX = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$";

    @Container
    static final PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:17.4-bookworm")
            .withDatabaseName("testdb")
            .withUsername("test_user")
            .withPassword("test_pass")
            .withReuse(true);

    @Container
    static final RedisContainer redis = new RedisContainer(DockerImageName.parse("redis:7.4-bookworm"))
            .withExposedPorts(6379)
            .withReuse(true);

    @Autowired
    private MockMvc mockMvc;

    @BeforeAll
    static void beforeAll() {
        postgres.start();
        redis.start();
    }

    @AfterAll
    static void afterAll() {
        postgres.stop();
        redis.stop();
    }

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        // PostgreSQLContainer
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");

        // RedisContainer
        registry.add("spring.data.redis.host", redis::getHost);
        registry.add("spring.data.redis.port", () -> redis.getFirstMappedPort().toString());
    }

    @Test
    @Order(1)
    @DisplayName("Test user registration")
    void register_shouldSuccessfullyRegisterUserAndReturnTokensWhenProvidedCorrectUserData() throws Exception {
        String json = """
                {
                  "username": "testuser",
                  "email": "test@example.com",
                  "password": "password123"
                }
                """;

        mockMvc.perform(post("/api/v1/register")
                        .contentType("application/json")
                        .content(json))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.accessToken").value(matchesPattern(TOKEN_PATTERN)))
                .andExpect(cookie().exists("refresh_token"))
                .andExpect(cookie().httpOnly("refresh_token", true))
                .andExpect(cookie().secure("refresh_token", true))
                .andExpect(cookie().value("refresh_token", matchesPattern(UUID_REGEX)))
                .andExpect(cookie().path("refresh_token", "/api/v1/refresh-token"))
                .andExpect(cookie().sameSite("refresh_token", "Strict"))
                .andExpect(cookie().maxAge("refresh_token", 604800));
    }

    @Test
    @Order(2)
    @DisplayName("Test user login")
    void login_shouldSuccessfullyAuthenticateUserAndReturnTokensWhenProvidedValidUserData() throws Exception {
        String json = """
                {
                	"username": "testuser",
                	"password": "password123"
                }
                """;

        mockMvc.perform(post("/api/v1/login")
                        .contentType("application/json")
                        .content(json))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.accessToken").value(matchesPattern(TOKEN_PATTERN)))
                .andExpect(cookie().exists("refresh_token"))
                .andExpect(cookie().httpOnly("refresh_token", true))
                .andExpect(cookie().secure("refresh_token", true))
                .andExpect(cookie().value("refresh_token", matchesPattern(UUID_REGEX)))
                .andExpect(cookie().path("refresh_token", "/api/v1/refresh-token"))
                .andExpect(cookie().sameSite("refresh_token", "Strict"))
                .andExpect(cookie().maxAge("refresh_token", 604800));
    }

    @Test
    @Order(3)
    @DisplayName("Renew access token")
    void refreshToken_shouldSuccessfullyReturnRenewedAccessTokenWhenProvidedValidRefreshToken() throws Exception {
        String json = """
                {
                  "username": "testuser2",
                  "email": "test2@example.com",
                  "password": "password1234"
                }
                """;

        MvcResult mvcResult = mockMvc.perform(post("/api/v1/register")
                        .contentType("application/json")
                        .content(json))
                .andExpect(status().isOk())
                .andReturn();

        String content = mvcResult.getResponse().getContentAsString();
        var initialResponse = JsonToObjectMapper.convert(content, AuthenticationResponse.class);
        var initialAccessToken = initialResponse.getAccessToken();

        Cookie[] cookies = mvcResult.getResponse().getCookies();
        Cookie refreshTokenCookie = Arrays.stream(cookies)
                .filter(cookie -> "refresh_token".equals(cookie.getName()))
                .findFirst()
                .orElse(null);


        json = String.format("""
                {
                	"accessToken": "%s"
                }
                """, initialAccessToken);

        MvcResult actual = mockMvc.perform(post("/api/v1/refresh-token")
                        .contentType("application/json")
                        .content(json)
                        .cookie(refreshTokenCookie))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.accessToken").value(matchesPattern(TOKEN_PATTERN)))
                .andReturn();

        String jsonString = actual.getResponse().getContentAsString();
        var response = JsonToObjectMapper.convert(jsonString, AuthenticationResponse.class);
        var newAccessToken = response.getAccessToken();

        Date newTokenExp = JwtUtils.getExpiration(newAccessToken);
        Date initialTokenExp = JwtUtils.getExpiration(initialAccessToken);
        assertTrue(newTokenExp.after(initialTokenExp));
    }
}
