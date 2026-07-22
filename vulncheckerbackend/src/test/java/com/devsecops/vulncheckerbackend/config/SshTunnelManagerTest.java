package com.devsecops.vulncheckerbackend.config;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedConstruction;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class SshTunnelManagerTest {

    private SshTunnelManager manager;

    @AfterEach
    void tearDown() {
        if (manager != null) {
            manager.destroy();
        }
    }

    @Test
    void openTunnel_createsNewSession_whenNotCached() throws Exception {
        try (MockedConstruction<JSch> mocked = mockConstruction(JSch.class, (mock, ctx) -> {
            Session mockSession = mock(Session.class);
            when(mockSession.isConnected()).thenReturn(true);
            when(mockSession.setPortForwardingL(0, "127.0.0.1", 9200)).thenReturn(36251);
            when(mock.getSession(anyString(), anyString(), anyInt())).thenReturn(mockSession);
        })) {
            manager = new SshTunnelManager();
            Session result = manager.openTunnel("10.0.0.1", 22, "root", "password");

            assertNotNull(result);
            assertEquals(36251, manager.getLocalPort(result));
            verify(result).setPassword("password");
            verify(result).connect(10000);
        }
    }

    @Test
    void openTunnel_reusesCachedSession_whenStillConnected() throws Exception {
        try (MockedConstruction<JSch> mocked = mockConstruction(JSch.class, (mock, ctx) -> {
            Session mockSession = mock(Session.class);
            when(mockSession.isConnected()).thenReturn(true);
            when(mockSession.setPortForwardingL(0, "127.0.0.1", 9200)).thenReturn(36251);
            when(mock.getSession(anyString(), anyString(), anyInt())).thenReturn(mockSession);
        })) {
            manager = new SshTunnelManager();
            Session first = manager.openTunnel("10.0.0.1", 22, "root", "password");
            Session second = manager.openTunnel("10.0.0.1", 22, "root", "password");

            assertSame(first, second);
            assertEquals(1, mocked.constructed().size());
        }
    }

    @Test
    void openTunnel_createsNewSession_whenCachedSessionDisconnected() throws Exception {
        Session disconnectedSession = mock(Session.class);
        when(disconnectedSession.isConnected()).thenReturn(false);
        when(disconnectedSession.setPortForwardingL(0, "127.0.0.1", 9200)).thenReturn(36251);

        try (MockedConstruction<JSch> mocked = mockConstruction(JSch.class, (mock, ctx) -> {
            when(mock.getSession(anyString(), anyString(), anyInt())).thenReturn(disconnectedSession);
        })) {
            manager = new SshTunnelManager();
            Session first = manager.openTunnel("10.0.0.1", 22, "root", "password");
            Session second = manager.openTunnel("10.0.0.1", 22, "root", "password");

            assertNotNull(first);
            assertNotNull(second);
            assertSame(first, second);
            verify(disconnectedSession, times(2)).setPassword("password");
            verify(disconnectedSession, times(2)).setPortForwardingL(0, "127.0.0.1", 9200);
            verify(disconnectedSession).disconnect();
            verify(disconnectedSession).delPortForwardingL(36251);
        }
    }

    @Test
    void closeTunnel_doesNothing_whenSessionNull() {
        manager = new SshTunnelManager();
        assertDoesNotThrow(() -> manager.closeTunnel((Session) null));
    }

    @Test
    void destroy_closesAllSessionsAndShutsDown() throws Exception {
        try (MockedConstruction<JSch> mocked = mockConstruction(JSch.class, (mock, ctx) -> {
            Session mockSession = mock(Session.class);
            when(mockSession.isConnected()).thenReturn(true);
            when(mockSession.setPortForwardingL(0, "127.0.0.1", 9200)).thenReturn(36251);
            when(mock.getSession(anyString(), anyString(), anyInt())).thenReturn(mockSession);
        })) {
            manager = new SshTunnelManager();
            manager.openTunnel("10.0.0.1", 22, "root", "password");

            manager.destroy();

            Session session = mocked.constructed().get(0).getSession("root", "10.0.0.1", 22);
            verify(session).disconnect();
        }
    }

    @Test
    void getLocalPort_returnsFallback_whenSessionNotInCache() {
        manager = new SshTunnelManager();
        Session unrelated = mock(Session.class);

        int port = manager.getLocalPort(unrelated);

        assertEquals(9201, port);
    }
}
