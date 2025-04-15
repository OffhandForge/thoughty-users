package com.biezbardis.thoughtyusers.controller;

import com.biezbardis.thoughtyusers.dto.RefreshTokenRequest;
import com.biezbardis.thoughtyusers.dto.RefreshTokenResponse;
import com.biezbardis.thoughtyusers.service.RefreshTokenService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RefreshTokenControllerTest {

    @Mock
    private RefreshTokenService refreshService;
    @InjectMocks
    private RefreshTokenController refreshTokenController;

    @Test
    void refreshToken_shouldReturnRefreshedAccessToken() {
        RefreshTokenRequest request = new RefreshTokenRequest();
        request.setAccessToken("accessToken");
        request.setRefreshToken("refreshToken");

        when(refreshService.refreshAccessToken(request)).thenReturn(new RefreshTokenResponse("newAccessToken"));

        assertEquals("newAccessToken", refreshTokenController.refreshToken(request).getAccessToken());
    }
}