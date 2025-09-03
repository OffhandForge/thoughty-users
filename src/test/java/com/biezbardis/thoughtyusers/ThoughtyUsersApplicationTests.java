package com.biezbardis.thoughtyusers;

import com.biezbardis.thoughtyusers.dto.AuthenticationResponse;
import com.biezbardis.thoughtyusers.dto.ErrorResponse;
import com.biezbardis.thoughtyusers.entity.RefreshToken;
import com.biezbardis.thoughtyusers.repository.redis.RefreshTokenRepository;
import com.biezbardis.thoughtyusers.utils.JsonToObjectMapper;
import com.biezbardis.thoughtyusers.utils.TestUser;
import com.redis.testcontainers.RedisContainer;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
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
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Stream;

import static com.biezbardis.thoughtyusers.utils.TestUtils.createAccessTokenJson;
import static com.biezbardis.thoughtyusers.utils.TestUtils.createLoginJson;
import static com.biezbardis.thoughtyusers.utils.TestUtils.createRegisterJson;
import static com.biezbardis.thoughtyusers.utils.TestUtils.encodePrivateKeyToPEM;
import static com.biezbardis.thoughtyusers.utils.TestUtils.encodePublicKeyToPEM;
import static com.biezbardis.thoughtyusers.utils.TestUtils.generateExpiredAccessToken;
import static com.biezbardis.thoughtyusers.utils.TestUtils.getExpiration;
import static com.biezbardis.thoughtyusers.utils.TestUtils.getRefreshTokenCookie;
import static com.biezbardis.thoughtyusers.utils.TestUtils.getSecurityKeys;
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
    public static final int REFRESH_TOKEN_MAX_AGE_SECONDS = 604800;

    private static final KeyPair KEY_PAIR = getSecurityKeys();
    private static final TestUser VALID_USER = new TestUser("test_user", "test_user@example.com", "P@ssword123");

    private @Value("${token.issuer}") String issuer;
    private @Value("${token.audience}") String audience;

    @Container
    static final PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:17.4-bookworm")
            .withDatabaseName("test_db")
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

    @BeforeEach
    void cleanData() {
        jdbc.execute("TRUNCATE TABLE users CASCADE;");
        Objects.requireNonNull(redisTemplate.getConnectionFactory()).getConnection().serverCommands().flushDb();
    }

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");

        registry.add("spring.data.redis.host", redis::getHost);
        registry.add("spring.data.redis.port", redis::getFirstMappedPort);

        registry.add("token.signing.privateKey", () -> encodePrivateKeyToPEM(KEY_PAIR.getPrivate()));
        registry.add("token.signing.publicKey", () -> encodePublicKeyToPEM(KEY_PAIR.getPublic()));
    }

    @Nested
    @DisplayName("User Registration Tests")
    class RegistrationTests {
        @Test
        @DisplayName("Test user registration")
        void register_shouldSuccessfullyRegisterUserAndReturnTokensWhenProvidedCorrectUserData() throws Exception {
            String json = createRegisterJson(VALID_USER);

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
                    .andExpect(cookie().maxAge("refresh_token", REFRESH_TOKEN_MAX_AGE_SECONDS));
        }

        @Test
        @DisplayName("Test user registration if already exists")
        void register_shouldReturnUserAlreadyExistsErrorWhenProvidedExistedCredentials() throws Exception {
            String json = createRegisterJson(VALID_USER);

            mockMvc.perform(post(REGISTER_URI)
                            .contentType("application/json")
                            .content(json))
                    .andExpect(status().isCreated());

            json = createRegisterJson(new TestUser(VALID_USER.username(), VALID_USER.email(), VALID_USER.password() + 4));

            String responseString = mockMvc.perform(post(REGISTER_URI)
                            .contentType("application/json")
                            .content(json))
                    .andExpect(status().isConflict())
                    .andExpect(cookie().doesNotExist("refresh_token"))
                    .andReturn().getResponse().getContentAsString();

            ErrorResponse errorResponse = JsonToObjectMapper.convert(responseString, ErrorResponse.class);

            assertErrorResponse(errorResponse,
                    HttpStatus.CONFLICT,
                    "Already In Use",
                    "Username \"%s\" is already in use".formatted(VALID_USER.username()),
                    "uri=%s".formatted(REGISTER_URI));
        }

        @ParameterizedTest
        @MethodSource("invalidRegistrationData")
        @DisplayName("Test user registration with invalid data")
        void register_shouldReturnValidationError(TestUser user, Map<String, String> expectedErrors) throws Exception {
            String json = createRegisterJson(user);

            String responseString = mockMvc.perform(post(REGISTER_URI)
                            .contentType("application/json")
                            .content(json))
                    .andExpect(status().isBadRequest())
                    .andExpect(cookie().doesNotExist("refresh_token"))
                    .andReturn().getResponse().getContentAsString();

            ErrorResponse errorResponse = JsonToObjectMapper.convert(responseString, ErrorResponse.class);

            assertErrorResponse(errorResponse,
                    HttpStatus.BAD_REQUEST,
                    "Validation Failed",
                    expectedErrors,
                    "uri=%s".formatted(REGISTER_URI));
        }

        static Stream<Arguments> invalidRegistrationData() {
            return Stream.of(
                    Arguments.of(
                            new TestUser("@invalid", "valid@email.com", "ValidPass1!"),
                            Map.of("username", "Username must start and end with alphanumeric characters and may contain digits, dot (.), underscore (_), or hyphen (-)")
                    ),
                    Arguments.of(
                            new TestUser("valid_Username", "invalid-%@email.com", "ValidPass1!"),
                            Map.of("email", "Invalid email format")
                    ),
                    Arguments.of(
                            new TestUser("valid_Username", "valid@email.com", "invalid_pass1"),
                            Map.of("password", "Password must contains of at least one digit, one small letter, one capital letter and one symbol")
                    )
            );
        }
    }

    @Nested
    @DisplayName("User Authentication Tests")
    class AuthenticationTests {
        @Test
        @DisplayName("Test user login")
        void login_shouldSuccessfullyAuthenticateUserAndReturnTokensWhenProvidedValidUserData() throws Exception {
            String json = createRegisterJson(VALID_USER);

            mockMvc.perform(post(REGISTER_URI)
                            .contentType("application/json")
                            .content(json))
                    .andExpect(status().isCreated());

            json = createLoginJson(VALID_USER);

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
                    .andExpect(cookie().maxAge("refresh_token", REFRESH_TOKEN_MAX_AGE_SECONDS));
        }

        @Test
        @DisplayName("Test user login with bad password")
        void login_shouldBadCredentialsErrorWhenProvidedWrongPasswordOfExistedUser() throws Exception {
            String json = createRegisterJson(VALID_USER);

            mockMvc.perform(post(REGISTER_URI)
                            .contentType("application/json")
                            .content(json))
                    .andExpect(status().isCreated());

            json = createLoginJson(VALID_USER.username(), "bad_password");

            String responseString = mockMvc.perform(post(LOGIN_URI)
                            .contentType("application/json")
                            .content(json))
                    .andExpect(status().isUnauthorized())
                    .andExpect(cookie().doesNotExist("refresh_token"))
                    .andReturn().getResponse().getContentAsString();

            ErrorResponse errorResponse = JsonToObjectMapper.convert(responseString, ErrorResponse.class);

            assertErrorResponse(errorResponse,
                    HttpStatus.UNAUTHORIZED,
                    "Unauthorized",
                    "Invalid credentials",
                    "uri=%s".formatted(LOGIN_URI));
        }

        @Test
        @DisplayName("Test nonexistent user login")
        void login_shouldBadCredentialsErrorWhenProvidedCredentialsOfNonexistentUser() throws Exception {
            String json = createLoginJson("nonexistent_user", "P@ssword123");

            String responseString = mockMvc.perform(post(LOGIN_URI)
                            .contentType("application/json")
                            .content(json))
                    .andExpect(status().isUnauthorized())
                    .andExpect(cookie().doesNotExist("refresh_token"))
                    .andReturn().getResponse().getContentAsString();

            ErrorResponse errorResponse = JsonToObjectMapper.convert(responseString, ErrorResponse.class);

            assertErrorResponse(errorResponse,
                    HttpStatus.UNAUTHORIZED,
                    "Unauthorized",
                    "Invalid credentials",
                    "uri=%s".formatted(LOGIN_URI));
        }
    }

    @Nested
    @DisplayName("Token Refresh Tests")
    class TokenRefreshTests {
        @Test
        @DisplayName("Renew access token")
        void refreshToken_shouldSuccessfullyReturnRenewedAccessTokenWhenProvidedValidRefreshToken() throws Exception {
            String json = createRegisterJson(VALID_USER);

            MvcResult mvcResult = mockMvc.perform(post(REGISTER_URI)
                            .contentType("application/json")
                            .content(json))
                    .andExpect(status().isCreated())
                    .andReturn();

            String content = mvcResult.getResponse().getContentAsString();
            AuthenticationResponse initialResponse = JsonToObjectMapper.convert(content, AuthenticationResponse.class);
            String initialAccessToken = initialResponse.getAccessToken();

            Cookie refreshTokenCookie = getRefreshTokenCookie(mvcResult);

            Thread.sleep(1000);

            json = createAccessTokenJson(initialAccessToken);

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

            Date newTokenExp = getExpiration(KEY_PAIR.getPublic(), newAccessToken);
            Date initialTokenExp = getExpiration(KEY_PAIR.getPublic(), initialAccessToken);
            assertTrue(newTokenExp.after(initialTokenExp));
        }

        @Test
        @DisplayName("Renew access token with expired access token")
        void refreshToken_shouldSuccessfullyReturnRenewedAccessTokenWhenProvidedExpiredToken() throws Exception {
            String json = createRegisterJson(VALID_USER);

            MvcResult mvcResult = mockMvc.perform(post(REGISTER_URI)
                            .contentType("application/json")
                            .content(json))
                    .andExpect(status().isCreated())
                    .andReturn();

            Cookie refreshTokenCookie = getRefreshTokenCookie(mvcResult);

            String expiredToken = generateExpiredAccessToken(
                    VALID_USER.username(),
                    KEY_PAIR.getPrivate(),
                    issuer,
                    audience,
                    List.of("POST " + REGISTER_URI));

            json = createAccessTokenJson(expiredToken);

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

            Date newTokenExpiration = getExpiration(KEY_PAIR.getPublic(), newAccessToken);
            assertTrue(newTokenExpiration.after(new Date(System.currentTimeMillis())));
        }

        @Test
        @DisplayName("Renew access token with expired refresh token")
        void refreshToken_shouldReturnUnauthorizedErrorWhenProvidedExpiredRefreshToken() throws Exception {
            String json = createRegisterJson(VALID_USER);

            MvcResult mvcResult = mockMvc.perform(post(REGISTER_URI)
                            .contentType("application/json")
                            .content(json))
                    .andExpect(status().isCreated())
                    .andReturn();

            String content = mvcResult.getResponse().getContentAsString();
            AuthenticationResponse initialResponse = JsonToObjectMapper.convert(content, AuthenticationResponse.class);
            String initialAccessToken = initialResponse.getAccessToken();

            Cookie refreshTokenCookie = getRefreshTokenCookie(mvcResult);

            assert refreshTokenCookie != null;
            UUID uuid = UUID.fromString(refreshTokenCookie.getValue());

            RefreshToken refreshToken = refreshTokenRepository.findById(uuid).orElseThrow();
            refreshToken.setExpiration(new Date(System.currentTimeMillis()));
            refreshTokenRepository.save(refreshToken);

            json = createAccessTokenJson(initialAccessToken);

            String responseString = mockMvc.perform(post(REFRESH_TOKEN_URI)
                            .contentType("application/json")
                            .content(json)
                            .cookie(refreshTokenCookie))
                    .andExpect(status().isUnauthorized())
                    .andExpect(cookie().doesNotExist("refresh_token"))
                    .andReturn().getResponse().getContentAsString();

            ErrorResponse errorResponse = JsonToObjectMapper.convert(responseString, ErrorResponse.class);

            assertErrorResponse(errorResponse,
                    HttpStatus.UNAUTHORIZED,
                    "Unauthorized",
                    "Refresh token is not valid",
                    "uri=%s".formatted(REFRESH_TOKEN_URI));
        }

        @Test
        @DisplayName("Renew access token with invalid refresh token")
        void refreshToken_shouldReturnUnauthorizedErrorWhenProvidedInvalidRefreshToken() throws Exception {
            String json = createRegisterJson(VALID_USER);

            MvcResult mvcResult = mockMvc.perform(post(REGISTER_URI)
                            .contentType("application/json")
                            .content(json))
                    .andExpect(status().isCreated())
                    .andReturn();

            String content = mvcResult.getResponse().getContentAsString();
            AuthenticationResponse initialResponse = JsonToObjectMapper.convert(content, AuthenticationResponse.class);
            String initialAccessToken = initialResponse.getAccessToken();

            Cookie refreshTokenCookie = getRefreshTokenCookie(mvcResult);

            Objects.requireNonNull(redisTemplate.getConnectionFactory()).getConnection().serverCommands().flushDb();

            json = createAccessTokenJson(initialAccessToken);

            String responseString = mockMvc.perform(post(REFRESH_TOKEN_URI)
                            .contentType("application/json")
                            .content(json)
                            .cookie(refreshTokenCookie))
                    .andExpect(status().isBadRequest())
                    .andExpect(cookie().doesNotExist("refresh_token"))
                    .andReturn().getResponse().getContentAsString();

            ErrorResponse errorResponse = JsonToObjectMapper.convert(responseString, ErrorResponse.class);

            assertErrorResponse(errorResponse,
                    HttpStatus.BAD_REQUEST,
                    "Refresh Token Required",
                    "Invalid or expired refresh token.",
                    "uri=%s".formatted(REFRESH_TOKEN_URI));
        }

        @Test
        @DisplayName("Renew access token without refresh token")
        void refreshToken_shouldReturnBadRequestErrorWhenRefreshTokenNotProvided() throws Exception {
            String json = createRegisterJson(VALID_USER);

            MvcResult mvcResult = mockMvc.perform(post(REGISTER_URI)
                            .contentType("application/json")
                            .content(json))
                    .andExpect(status().isCreated())
                    .andReturn();

            String content = mvcResult.getResponse().getContentAsString();
            AuthenticationResponse initialResponse = JsonToObjectMapper.convert(content, AuthenticationResponse.class);
            String initialAccessToken = initialResponse.getAccessToken();

            json = createAccessTokenJson(initialAccessToken);

            String responseString = mockMvc.perform(post(REFRESH_TOKEN_URI)
                            .contentType("application/json")
                            .content(json))
                    .andExpect(status().isBadRequest())
                    .andExpect(cookie().doesNotExist("refresh_token"))
                    .andReturn().getResponse().getContentAsString();

            ErrorResponse errorResponse = JsonToObjectMapper.convert(responseString, ErrorResponse.class);

            assertErrorResponse(errorResponse,
                    HttpStatus.BAD_REQUEST,
                    "Cookie Required",
                    "Cookie is not present or malformed.",
                    "uri=%s".formatted(REFRESH_TOKEN_URI));
        }

        @Test
        @DisplayName("Renew access token without access token")
        void refreshToken_shouldReturnBadRequestErrorWhenAccessTokenNotProvided() throws Exception {
            String json = createRegisterJson(VALID_USER);

            MvcResult mvcResult = mockMvc.perform(post(REGISTER_URI)
                            .contentType("application/json")
                            .content(json))
                    .andExpect(status().isCreated())
                    .andReturn();

            Cookie refreshTokenCookie = getRefreshTokenCookie(mvcResult);

            json = createAccessTokenJson("");

            String responseString = mockMvc.perform(post(REFRESH_TOKEN_URI)
                            .contentType("application/json")
                            .content(json)
                            .cookie(refreshTokenCookie))
                    .andExpect(status().isBadRequest())
                    .andExpect(cookie().doesNotExist("refresh_token"))
                    .andReturn().getResponse().getContentAsString();

            ErrorResponse errorResponse = JsonToObjectMapper.convert(responseString, ErrorResponse.class);

            assertErrorResponse(errorResponse,
                    HttpStatus.BAD_REQUEST,
                    "Validation Failed",
                    Map.of("accessToken", "Access token cannot be empty"),
                    "uri=%s".formatted(REFRESH_TOKEN_URI));
        }

        @Test
        @DisplayName("Renew access token without request body")
        void refreshToken_shouldBadRequestErrorWhenRequestBodyNotProvided() throws Exception {
            String json = createRegisterJson(VALID_USER);

            MvcResult mvcResult = mockMvc.perform(post(REGISTER_URI)
                            .contentType("application/json")
                            .content(json))
                    .andExpect(status().isCreated())
                    .andReturn();

            Cookie refreshTokenCookie = getRefreshTokenCookie(mvcResult);

            String responseString = mockMvc.perform(post(REFRESH_TOKEN_URI)
                            .cookie(refreshTokenCookie))
                    .andExpect(status().isBadRequest())
                    .andExpect(cookie().doesNotExist("refresh_token"))
                    .andReturn().getResponse().getContentAsString();

            ErrorResponse errorResponse = JsonToObjectMapper.convert(responseString, ErrorResponse.class);

            assertErrorResponse(errorResponse,
                    HttpStatus.BAD_REQUEST,
                    "Request Body Required",
                    "Request body is missing or malformed.",
                    "uri=%s".formatted(REFRESH_TOKEN_URI));
        }
    }

    private void assertErrorResponse(ErrorResponse errorResponse, HttpStatus expectedStatus,
                                     String expectedError, Object expectedMessage, String expectedPath) {
        assertNotNull(errorResponse.timestamp());
        assertDoesNotThrow(() -> LocalDateTime.parse(errorResponse.timestamp(),
                DateTimeFormatter.ofPattern(TIMESTAMP_PATTERN)));
        assertEquals(expectedStatus.value(), errorResponse.status());
        assertEquals(expectedError, errorResponse.error());

        if (expectedMessage instanceof Map && errorResponse.hasValidationErrors()) {
            assertValidationErrors(errorResponse.getValidationErrors(), (Map<String, String>) expectedMessage);
        } else {
            assertEquals(expectedMessage, errorResponse.message());
        }
        assertEquals(expectedPath, errorResponse.path());
    }

    private void assertValidationErrors(Map<String, List<String>> actualErrors, Map<String, String> expectedErrors) {
        expectedErrors.forEach((field, expectedMessage) ->
                assertEquals(expectedMessage, actualErrors.get(field).getFirst()));
    }
}
