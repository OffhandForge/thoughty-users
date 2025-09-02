package com.biezbardis.thoughtyusers;

import com.biezbardis.thoughtyusers.dto.AuthenticationResponse;
import com.biezbardis.thoughtyusers.dto.ErrorResponse;
import com.biezbardis.thoughtyusers.entity.RefreshToken;
import com.biezbardis.thoughtyusers.repository.redis.RefreshTokenRepository;
import com.biezbardis.thoughtyusers.utils.JsonToObjectMapper;
import com.biezbardis.thoughtyusers.utils.TestUtils;
import com.redis.testcontainers.RedisContainer;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.security.KeyPair;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import static org.hamcrest.Matchers.matchesPattern;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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

    public static final String JWT_PATTERN = "^eyJhbG[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_.+/=]*$";
    public static final String UUID_REGEX = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$";
    public static final String TIMESTAMP_PATTERN = "yyyy-MM-dd HH:mm:ss.SSS";
    public static final String REGISTER_URI = "/api/v1/register";
    public static final String REFRESH_TOKEN_URI = "/api/v1/refresh-token";
    public static final String LOGIN_URI = "/api/v1/login";

    private static final KeyPair KEY_PAIR = TestUtils.getSecurityKeys();
    private @Value("${token.issuer}") String issuer;
    private @Value("${token.audience}") String audience;

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
    @Autowired
    private JdbcTemplate jdbc;
    @Autowired
    private StringRedisTemplate redisTemplate;
    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

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

    @BeforeEach
    void cleanDb() {
        jdbc.execute("TRUNCATE TABLE users CASCADE;");
        Objects.requireNonNull(redisTemplate.getConnectionFactory()).getConnection().serverCommands().flushDb();
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
        registry.add("spring.data.redis.port", redis::getFirstMappedPort);

        // SecurityKeys
        registry.add("token.signing.privateKey", () -> TestUtils.encodePrivateKeyToPEM(KEY_PAIR.getPrivate()));
        registry.add("token.signing.publicKey", () -> TestUtils.encodePublicKeyToPEM(KEY_PAIR.getPublic()));
    }

    @Test
    @DisplayName("Test user registration")
    void register_shouldSuccessfullyRegisterUserAndReturnTokensWhenProvidedCorrectUserData() throws Exception {
        String username = "test_user";
        String email = "test_user@example.com";
        String password = "P@ssword123";

        String json = """
                {
                  "username": "%s",
                  "email": "%s",
                  "password": "%s"
                }
                """.formatted(username, email, password);

        mockMvc.perform(post(REGISTER_URI)
                        .contentType("application/json")
                        .content(json))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.accessToken").value(matchesPattern(JWT_PATTERN)))
                .andExpect(cookie().exists("refresh_token"))
                .andExpect(cookie().httpOnly("refresh_token", true))
                .andExpect(cookie().secure("refresh_token", true))
                .andExpect(cookie().value("refresh_token", matchesPattern(UUID_REGEX)))
                .andExpect(cookie().path("refresh_token", REFRESH_TOKEN_URI))
                .andExpect(cookie().sameSite("refresh_token", "Strict"))
                .andExpect(cookie().maxAge("refresh_token", 604800));
    }

    @Test
    @DisplayName("Test user registration if already exists")
    void register_shouldReturnUserAlreadyExistsErrorWhenProvidedExistedCredentials() throws Exception {
        String username = "test_user";
        String email = "test_user@example.com";
        String password = "P@ssword123";

        String json = """
                {
                  "username": "%s",
                  "email": "%s",
                  "password": "%s"
                }
                """.formatted(username, email, password);

        mockMvc.perform(post(REGISTER_URI)
                        .contentType("application/json")
                        .content(json))
                .andExpect(status().isCreated());

        json = """
                {
                  "username": "%s",
                  "email": "%s",
                  "password": "%s"
                }
                """.formatted(username, email, password + "4");

        String responseString = mockMvc.perform(post(REGISTER_URI)
                        .contentType("application/json")
                        .content(json))
                .andExpect(status().isConflict())
                .andExpect(cookie().doesNotExist("refresh_token"))
                .andReturn().getResponse().getContentAsString();

        ErrorResponse errorResponse = JsonToObjectMapper.convert(responseString, ErrorResponse.class);

        assertNotNull(errorResponse.timestamp());
        assertDoesNotThrow(() -> LocalDateTime.parse(errorResponse.timestamp(), DateTimeFormatter.ofPattern(TIMESTAMP_PATTERN)),
                "Timestamp should be in the format '%s'".formatted(TIMESTAMP_PATTERN));
        assertEquals(HttpStatus.CONFLICT.value(), errorResponse.status());
        assertEquals("Already In Use", errorResponse.error());
        assertEquals("Username \"%s\" is already in use".formatted(username), errorResponse.message());
        assertEquals("uri=%s".formatted(REGISTER_URI), errorResponse.path());
    }

    @Test
    @DisplayName("Test user registration with invalid data")
    void register_shouldReturnValidationFailedErrorWhenProvidedInvalidDataCredentials() throws Exception {
        String username = "@test_user";
        String email = "%test_user@example.com";
        String password = "p@ssword123";

        String json = """
                {
                  "username": "%s",
                  "email": "%s",
                  "password": "%s"
                }
                """.formatted(username, email, password);


        String responseString = mockMvc.perform(post(REGISTER_URI)
                        .contentType("application/json")
                        .content(json))
                .andExpect(status().isBadRequest())
                .andExpect(cookie().doesNotExist("refresh_token"))
                .andReturn().getResponse().getContentAsString();

        ErrorResponse errorResponse = JsonToObjectMapper.convert(responseString, ErrorResponse.class);

        assertNotNull(errorResponse.timestamp());
        assertDoesNotThrow(() -> LocalDateTime.parse(errorResponse.timestamp(), DateTimeFormatter.ofPattern(TIMESTAMP_PATTERN)),
                "Timestamp should be in the format '%s'".formatted(TIMESTAMP_PATTERN));
        assertEquals(HttpStatus.BAD_REQUEST.value(), errorResponse.status());
        assertEquals("Validation Failed", errorResponse.error());
        Map<String, List<String>> messageErrors = (Map<String, List<String>>) errorResponse.message();
        assertEquals("Username must start and end with alphanumeric characters and may contain digits, dot (.), underscore (_), or hyphen (-)",
                messageErrors.get("username").getFirst());
        assertEquals("Invalid email format", messageErrors.get("email").getFirst());
        assertEquals("Password must contains of at least one digit, one small letter, one capital letter and one symbol",
                messageErrors.get("password").getFirst());
        assertEquals("uri=%s".formatted(REGISTER_URI), errorResponse.path());
    }

    @Test
    @DisplayName("Test user login")
    void login_shouldSuccessfullyAuthenticateUserAndReturnTokensWhenProvidedValidUserData() throws Exception {
        String username = "test_user";
        String email = "test_user@example.com";
        String password = "P@ssword123";

        String json = """
                {
                  "username": "%s",
                  "email": "%s",
                  "password": "%s"
                }
                """.formatted(username, email, password);

        mockMvc.perform(post(REGISTER_URI)
                        .contentType("application/json")
                        .content(json))
                .andExpect(status().isCreated());

        json = """
                {
                  "username": "%s",
                  "password": "%s"
                }
                """.formatted(username, password);

        mockMvc.perform(post(LOGIN_URI)
                        .contentType("application/json")
                        .content(json))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.accessToken").value(matchesPattern(JWT_PATTERN)))
                .andExpect(cookie().exists("refresh_token"))
                .andExpect(cookie().httpOnly("refresh_token", true))
                .andExpect(cookie().secure("refresh_token", true))
                .andExpect(cookie().value("refresh_token", matchesPattern(UUID_REGEX)))
                .andExpect(cookie().path("refresh_token", REFRESH_TOKEN_URI))
                .andExpect(cookie().sameSite("refresh_token", "Strict"))
                .andExpect(cookie().maxAge("refresh_token", 604800));
    }

    @Test
    @DisplayName("Test user login with bad password")
    void login_shouldBadCredentialsErrorWhenProvidedWrongPasswordOfExistedUser() throws Exception {
        String username = "test_user";
        String email = "test_user@example.com";
        String password = "P@ssword123";

        String json = """
                {
                  "username": "%s",
                  "email": "%s",
                  "password": "%s"
                }
                """.formatted(username, email, password);

        mockMvc.perform(post(REGISTER_URI)
                        .contentType("application/json")
                        .content(json))
                .andExpect(status().isCreated());

        json = """
                {
                  "username": "%s",
                  "password": "%s"
                }
                """.formatted(username, "bad_password");

        String responseString = mockMvc.perform(post(LOGIN_URI)
                        .contentType("application/json")
                        .content(json))
                .andExpect(status().isUnauthorized())
                .andExpect(cookie().doesNotExist("refresh_token"))
                .andReturn().getResponse().getContentAsString();

        ErrorResponse errorResponse = JsonToObjectMapper.convert(responseString, ErrorResponse.class);

        assertNotNull(errorResponse.timestamp());
        assertDoesNotThrow(() -> LocalDateTime.parse(errorResponse.timestamp(), DateTimeFormatter.ofPattern(TIMESTAMP_PATTERN)),
                "Timestamp should be in the format '%s'".formatted(TIMESTAMP_PATTERN));
        assertEquals(HttpStatus.UNAUTHORIZED.value(), errorResponse.status());
        assertEquals("Unauthorized", errorResponse.error());
        assertEquals("Invalid credentials", errorResponse.message());
        assertEquals("uri=%s".formatted(LOGIN_URI), errorResponse.path());
    }

    @Test
    @DisplayName("Test nonexistent user login")
    void login_shouldBadCredentialsErrorWhenProvidedCredentialsOfNonexistentUser() throws Exception {
        String username = "nonexistent_user";
        String password = "P@ssword123";

        String json = """
                {
                  "username": "%s",
                  "password": "%s"
                }
                """.formatted(username, password);

        String responseString = mockMvc.perform(post(LOGIN_URI)
                        .contentType("application/json")
                        .content(json))
                .andExpect(status().isUnauthorized())
                .andExpect(cookie().doesNotExist("refresh_token"))
                .andReturn().getResponse().getContentAsString();

        ErrorResponse errorResponse = JsonToObjectMapper.convert(responseString, ErrorResponse.class);

        assertNotNull(errorResponse.timestamp());
        assertDoesNotThrow(() -> LocalDateTime.parse(errorResponse.timestamp(), DateTimeFormatter.ofPattern(TIMESTAMP_PATTERN)),
                "Timestamp should be in the format '%s'".formatted(TIMESTAMP_PATTERN));
        assertEquals(HttpStatus.UNAUTHORIZED.value(), errorResponse.status());
        assertEquals("Unauthorized", errorResponse.error());
        assertEquals("Invalid credentials", errorResponse.message());
        assertEquals("uri=%s".formatted(LOGIN_URI), errorResponse.path());
    }

    @Test
    @DisplayName("Renew access token")
    void refreshToken_shouldSuccessfullyReturnRenewedAccessTokenWhenProvidedValidRefreshToken() throws Exception {
        String username = "test_user";
        String email = "test_user@example.com";
        String password = "P@ssword123";

        String json = """
                {
                  "username": "%s",
                  "email": "%s",
                  "password": "%s"
                }
                """.formatted(username, email, password);

        MvcResult mvcResult = mockMvc.perform(post(REGISTER_URI)
                        .contentType("application/json")
                        .content(json))
                .andExpect(status().isCreated())
                .andReturn();

        String content = mvcResult.getResponse().getContentAsString();
        AuthenticationResponse initialResponse = JsonToObjectMapper.convert(content, AuthenticationResponse.class);
        String initialAccessToken = initialResponse.getAccessToken();

        Cookie[] cookies = mvcResult.getResponse().getCookies();
        Cookie refreshTokenCookie = Arrays.stream(cookies)
                .filter(cookie -> "refresh_token".equals(cookie.getName()))
                .findFirst()
                .orElse(null);

        Thread.sleep(1000);

        json = String.format("""
                {
                	"accessToken": "%s"
                }
                """, initialAccessToken);

        MvcResult actual = mockMvc.perform(post(REFRESH_TOKEN_URI)
                        .contentType("application/json")
                        .content(json)
                        .cookie(refreshTokenCookie))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.accessToken").value(matchesPattern(JWT_PATTERN)))
                .andReturn();

        String jsonString = actual.getResponse().getContentAsString();
        var response = JsonToObjectMapper.convert(jsonString, AuthenticationResponse.class);
        var newAccessToken = response.getAccessToken();

        Date newTokenExp = TestUtils.getExpiration(KEY_PAIR.getPublic(), newAccessToken);
        Date initialTokenExp = TestUtils.getExpiration(KEY_PAIR.getPublic(), initialAccessToken);
        assertTrue(newTokenExp.after(initialTokenExp));
    }

    @Test
    @DisplayName("Renew access token with expired access token")
    void refreshToken_shouldSuccessfullyReturnRenewedAccessTokenWhenProvidedExpiredToken() throws Exception {
        String username = "test_user";
        String email = "test_user@example.com";
        String password = "P@ssword123";

        String json = """
                {
                  "username": "%s",
                  "email": "%s",
                  "password": "%s"
                }
                """.formatted(username, email, password);

        MvcResult mvcResult = mockMvc.perform(post(REGISTER_URI)
                        .contentType("application/json")
                        .content(json))
                .andExpect(status().isCreated())
                .andReturn();

        Cookie[] cookies = mvcResult.getResponse().getCookies();
        Cookie refreshTokenCookie = Arrays.stream(cookies)
                .filter(cookie -> "refresh_token".equals(cookie.getName()))
                .findFirst()
                .orElse(null);

        Thread.sleep(1000);

        String expiredToken = TestUtils.generateExpiredAccessToken(
                username,
                KEY_PAIR.getPrivate(),
                issuer,
                audience,
                List.of("POST " + REGISTER_URI));

        json = """
                {
                	"accessToken": "%s"
                }
                """.formatted(expiredToken);

        MvcResult actual = mockMvc.perform(post(REFRESH_TOKEN_URI)
                        .contentType("application/json")
                        .content(json)
                        .cookie(refreshTokenCookie))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.accessToken").value(matchesPattern(JWT_PATTERN)))
                .andReturn();

        String jsonString = actual.getResponse().getContentAsString();
        var response = JsonToObjectMapper.convert(jsonString, AuthenticationResponse.class);
        var newAccessToken = response.getAccessToken();

        Date newTokenExpiration = TestUtils.getExpiration(KEY_PAIR.getPublic(), newAccessToken);
        assertTrue(newTokenExpiration.after(new Date(System.currentTimeMillis())));
    }

    @Test
    @DisplayName("Renew access token with expired refresh token")
    void refreshToken_shouldReturnUnauthorizedErrorWhenProvidedExpiredRefreshToken() throws Exception {
        String username = "test_user";
        String email = "test_user@example.com";
        String password = "P@ssword123";

        String json = """
                {
                  "username": "%s",
                  "email": "%s",
                  "password": "%s"
                }
                """.formatted(username, email, password);

        MvcResult mvcResult = mockMvc.perform(post(REGISTER_URI)
                        .contentType("application/json")
                        .content(json))
                .andExpect(status().isCreated())
                .andReturn();

        String content = mvcResult.getResponse().getContentAsString();
        AuthenticationResponse initialResponse = JsonToObjectMapper.convert(content, AuthenticationResponse.class);
        String initialAccessToken = initialResponse.getAccessToken();

        Cookie[] cookies = mvcResult.getResponse().getCookies();
        Cookie refreshTokenCookie = Arrays.stream(cookies)
                .filter(cookie -> "refresh_token".equals(cookie.getName()))
                .findFirst()
                .orElse(null);

        assert refreshTokenCookie != null;
        UUID uuid = UUID.fromString(refreshTokenCookie.getValue());

        RefreshToken refreshToken = refreshTokenRepository.findById(uuid).orElseThrow();
        refreshToken.setExpiration(new Date(System.currentTimeMillis()));
        refreshTokenRepository.save(refreshToken);

        Thread.sleep(1000);

        json = String.format("""
                {
                	"accessToken": "%s"
                }
                """, initialAccessToken);

        String responseString = mockMvc.perform(post(REFRESH_TOKEN_URI)
                        .contentType("application/json")
                        .content(json)
                        .cookie(refreshTokenCookie))
                .andExpect(status().isUnauthorized())
                .andExpect(cookie().doesNotExist("refresh_token"))
                .andReturn().getResponse().getContentAsString();

        ErrorResponse errorResponse = JsonToObjectMapper.convert(responseString, ErrorResponse.class);

        assertNotNull(errorResponse.timestamp());
        assertDoesNotThrow(() -> LocalDateTime.parse(errorResponse.timestamp(), DateTimeFormatter.ofPattern(TIMESTAMP_PATTERN)),
                "Timestamp should be in the format '%s'".formatted(TIMESTAMP_PATTERN));
        assertEquals(HttpStatus.UNAUTHORIZED.value(), errorResponse.status());
        assertEquals("Unauthorized", errorResponse.error());
        assertEquals("Refresh token is expired", errorResponse.message());
        assertEquals("uri=%s".formatted(REFRESH_TOKEN_URI), errorResponse.path());
    }

    @Test
    @DisplayName("Renew access token with expired refresh token")
    void refreshToken_shouldReturnUnauthorizedErrorWhenProvidedInvalidRefreshToken() throws Exception {
        String username = "test_user";
        String email = "test_user@example.com";
        String password = "P@ssword123";

        String json = """
                {
                  "username": "%s",
                  "email": "%s",
                  "password": "%s"
                }
                """.formatted(username, email, password);

        MvcResult mvcResult = mockMvc.perform(post(REGISTER_URI)
                        .contentType("application/json")
                        .content(json))
                .andExpect(status().isCreated())
                .andReturn();

        String content = mvcResult.getResponse().getContentAsString();
        AuthenticationResponse initialResponse = JsonToObjectMapper.convert(content, AuthenticationResponse.class);
        String initialAccessToken = initialResponse.getAccessToken();

        Cookie[] cookies = mvcResult.getResponse().getCookies();
        Cookie refreshTokenCookie = Arrays.stream(cookies)
                .filter(cookie -> "refresh_token".equals(cookie.getName()))
                .findFirst()
                .orElse(null);

        Objects.requireNonNull(redisTemplate.getConnectionFactory()).getConnection().serverCommands().flushDb();

        Thread.sleep(1000);

        json = String.format("""
                {
                	"accessToken": "%s"
                }
                """, initialAccessToken);

        String responseString = mockMvc.perform(post(REFRESH_TOKEN_URI)
                        .contentType("application/json")
                        .content(json)
                        .cookie(refreshTokenCookie))
                .andExpect(status().isBadRequest())
                .andExpect(cookie().doesNotExist("refresh_token"))
                .andReturn().getResponse().getContentAsString();

        ErrorResponse errorResponse = JsonToObjectMapper.convert(responseString, ErrorResponse.class);

        assertNotNull(errorResponse.timestamp());
        assertDoesNotThrow(() -> LocalDateTime.parse(errorResponse.timestamp(), DateTimeFormatter.ofPattern(TIMESTAMP_PATTERN)),
                "Timestamp should be in the format '%s'".formatted(TIMESTAMP_PATTERN));
        assertEquals(HttpStatus.BAD_REQUEST.value(), errorResponse.status());
        assertEquals("Refresh Token Required", errorResponse.error());
        assertEquals("Invalid or expired refresh token.", errorResponse.message());
        assertEquals("uri=%s".formatted(REFRESH_TOKEN_URI), errorResponse.path());
    }

    @Test
    @DisplayName("Renew access token without refresh token")
    void refreshToken_shouldReturnBadRequestErrorWhenRefreshTokenNotProvided() throws Exception {
        String username = "test_user";
        String email = "test_user@example.com";
        String password = "P@ssword123";

        String json = """
                {
                  "username": "%s",
                  "email": "%s",
                  "password": "%s"
                }
                """.formatted(username, email, password);

        MvcResult mvcResult = mockMvc.perform(post(REGISTER_URI)
                        .contentType("application/json")
                        .content(json))
                .andExpect(status().isCreated())
                .andReturn();

        String content = mvcResult.getResponse().getContentAsString();
        AuthenticationResponse initialResponse = JsonToObjectMapper.convert(content, AuthenticationResponse.class);
        String initialAccessToken = initialResponse.getAccessToken();

        Thread.sleep(1000);

        json = String.format("""
                {
                	"accessToken": "%s"
                }
                """, initialAccessToken);

        String responseString = mockMvc.perform(post(REFRESH_TOKEN_URI)
                        .contentType("application/json")
                        .content(json))
                .andExpect(status().isBadRequest())
                .andExpect(cookie().doesNotExist("refresh_token"))
                .andReturn().getResponse().getContentAsString();

        ErrorResponse errorResponse = JsonToObjectMapper.convert(responseString, ErrorResponse.class);

        assertNotNull(errorResponse.timestamp());
        assertDoesNotThrow(() -> LocalDateTime.parse(errorResponse.timestamp(), DateTimeFormatter.ofPattern(TIMESTAMP_PATTERN)),
                "Timestamp should be in the format '%s'".formatted(TIMESTAMP_PATTERN));
        assertEquals(HttpStatus.BAD_REQUEST.value(), errorResponse.status());
        assertEquals("Cookie Required", errorResponse.error());
        assertEquals("Cookie is not present or malformed.", errorResponse.message());
        assertEquals("uri=%s".formatted(REFRESH_TOKEN_URI), errorResponse.path());
    }

    @Test
    @DisplayName("Renew access token without access token")
    void refreshToken_shouldReturnBadRequestErrorWhenAccessTokenNotProvided() throws Exception {
        String username = "test_user";
        String email = "test_user@example.com";
        String password = "P@ssword123";

        String json = """
                {
                  "username": "%s",
                  "email": "%s",
                  "password": "%s"
                }
                """.formatted(username, email, password);

        MvcResult mvcResult = mockMvc.perform(post(REGISTER_URI)
                        .contentType("application/json")
                        .content(json))
                .andExpect(status().isCreated())
                .andReturn();

        Cookie[] cookies = mvcResult.getResponse().getCookies();
        Cookie refreshTokenCookie = Arrays.stream(cookies)
                .filter(cookie -> "refresh_token".equals(cookie.getName()))
                .findFirst()
                .orElse(null);

        Thread.sleep(1000);

        json = """
                {
                	"accessToken": ""
                }
                """;

        String responseString = mockMvc.perform(post(REFRESH_TOKEN_URI)
                        .contentType("application/json")
                        .content(json)
                        .cookie(refreshTokenCookie))
                .andExpect(status().isBadRequest())
                .andExpect(cookie().doesNotExist("refresh_token"))
                .andReturn().getResponse().getContentAsString();

        ErrorResponse errorResponse = JsonToObjectMapper.convert(responseString, ErrorResponse.class);

        assertNotNull(errorResponse.timestamp());
        assertDoesNotThrow(() -> LocalDateTime.parse(errorResponse.timestamp(), DateTimeFormatter.ofPattern(TIMESTAMP_PATTERN)),
                "Timestamp should be in the format '%s'".formatted(TIMESTAMP_PATTERN));
        assertEquals(HttpStatus.BAD_REQUEST.value(), errorResponse.status());
        assertEquals("Validation Failed", errorResponse.error());
        Map<String, List<String>> messageErrors = (Map<String, List<String>>) errorResponse.message();
        assertEquals("Access token cannot be empty", messageErrors.get("accessToken").getFirst());
        assertEquals("uri=%s".formatted(REFRESH_TOKEN_URI), errorResponse.path());
    }

    @Test
    @DisplayName("Renew access token without request body")
    void refreshToken_shouldBadRequestErrorWhenRequestBodyNotProvided() throws Exception {
        String username = "test_user";
        String email = "test_user@example.com";
        String password = "P@ssword123";

        String json = """
                {
                  "username": "%s",
                  "email": "%s",
                  "password": "%s"
                }
                """.formatted(username, email, password);

        MvcResult mvcResult = mockMvc.perform(post(REGISTER_URI)
                        .contentType("application/json")
                        .content(json))
                .andExpect(status().isCreated())
                .andReturn();

        Cookie[] cookies = mvcResult.getResponse().getCookies();
        Cookie refreshTokenCookie = Arrays.stream(cookies)
                .filter(cookie -> "refresh_token".equals(cookie.getName()))
                .findFirst()
                .orElse(null);

        Thread.sleep(1000);

        String responseString = mockMvc.perform(post(REFRESH_TOKEN_URI)
                        .cookie(refreshTokenCookie))
                .andExpect(status().isBadRequest())
                .andExpect(cookie().doesNotExist("refresh_token"))
                .andReturn().getResponse().getContentAsString();

        ErrorResponse errorResponse = JsonToObjectMapper.convert(responseString, ErrorResponse.class);

        assertNotNull(errorResponse.timestamp());
        assertDoesNotThrow(() -> LocalDateTime.parse(errorResponse.timestamp(), DateTimeFormatter.ofPattern(TIMESTAMP_PATTERN)),
                "Timestamp should be in the format '%s'".formatted(TIMESTAMP_PATTERN));
        assertEquals(HttpStatus.BAD_REQUEST.value(), errorResponse.status());
        assertEquals("Request Body Required", errorResponse.error());
        assertEquals("Request body is missing or malformed.", errorResponse.message());
        assertEquals("uri=%s".formatted(REFRESH_TOKEN_URI), errorResponse.path());
    }
}
