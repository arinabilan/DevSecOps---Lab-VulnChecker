package com.devsecops.vulncheckerbackend.config;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedConstruction;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

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
    void closeTunnel_doesNothing_whenSessionNull() throws Exception {
        manager = new SshTunnelManager();
        assertDoesNotThrow(() -> manager.closeTunnel((Session) null));
    }

    @Test
    void closeTunnelPrivate_doesNothing_whenSessionNull() throws Exception {
        manager = new SshTunnelManager();
        Method closePrivate = SshTunnelManager.class.getDeclaredMethod("closeTunnel", Session.class, int.class);
        closePrivate.setAccessible(true);
        closePrivate.invoke(manager, (Session) null, 36251);
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

    @Test
    void getLocalPort_returnsFallback_whenNoMatchingEntryInCache() throws Exception {
        try (MockedConstruction<JSch> mocked = mockConstruction(JSch.class, (mock, ctx) -> {
            Session mockSession = mock(Session.class);
            when(mockSession.isConnected()).thenReturn(true);
            when(mockSession.setPortForwardingL(0, "127.0.0.1", 9200)).thenReturn(36251);
            when(mock.getSession(anyString(), anyString(), anyInt())).thenReturn(mockSession);
        })) {
            manager = new SshTunnelManager();
            manager.openTunnel("10.0.0.1", 22, "root", "password");

            Session differentSession = mock(Session.class);

            int port = manager.getLocalPort(differentSession);
            assertEquals(9201, port);
        }
    }

    @Test
    void closeTunnel_public_closesFromCache_whenFound() throws Exception {
        try (MockedConstruction<JSch> mocked = mockConstruction(JSch.class, (mock, ctx) -> {
            Session mockSession = mock(Session.class);
            when(mockSession.isConnected()).thenReturn(true);
            when(mockSession.setPortForwardingL(0, "127.0.0.1", 9200)).thenReturn(36251);
            when(mock.getSession(anyString(), anyString(), anyInt())).thenReturn(mockSession);
        })) {
            manager = new SshTunnelManager();
            Session session = manager.openTunnel("10.0.0.1", 22, "root", "password");

            manager.closeTunnel(session);

            verify(session).delPortForwardingL(36251);
            verify(session).disconnect();
        }
    }

    @Test
    void closeTunnel_public_fallback_whenSessionNotInCache() throws Exception {
        try (MockedConstruction<JSch> mocked = mockConstruction(JSch.class, (mock, ctx) -> {
            Session mockSession = mock(Session.class);
            when(mockSession.isConnected()).thenReturn(true);
            when(mockSession.setPortForwardingL(0, "127.0.0.1", 9200)).thenReturn(36251);
            when(mock.getSession(anyString(), anyString(), anyInt())).thenReturn(mockSession);
        })) {
            manager = new SshTunnelManager();
            manager.openTunnel("10.0.0.1", 22, "root", "password");

            Session differentSession = mock(Session.class);
            manager.closeTunnel(differentSession);

            verify(differentSession).disconnect();
        }
    }

    @Test
    void closeTunnel_throwsInDelPortForwarding_doesNotPropagate() throws Exception {
        try (MockedConstruction<JSch> mocked = mockConstruction(JSch.class, (mock, ctx) -> {
            Session mockSession = mock(Session.class);
            when(mockSession.isConnected()).thenReturn(true);
            when(mockSession.setPortForwardingL(0, "127.0.0.1", 9200)).thenReturn(36251);
            doThrow(new RuntimeException("del failed")).when(mockSession).delPortForwardingL(36251);
            when(mock.getSession(anyString(), anyString(), anyInt())).thenReturn(mockSession);
        })) {
            manager = new SshTunnelManager();
            manager.openTunnel("10.0.0.1", 22, "root", "password");

            manager.destroy();
        }
    }

    @Test
    void touch_updatesLastUsed_forCachedSession() throws Exception {
        try (MockedConstruction<JSch> mocked = mockConstruction(JSch.class, (mock, ctx) -> {
            Session mockSession = mock(Session.class);
            when(mockSession.isConnected()).thenReturn(true);
            when(mockSession.setPortForwardingL(0, "127.0.0.1", 9200)).thenReturn(36251);
            when(mock.getSession(anyString(), anyString(), anyInt())).thenReturn(mockSession);
        })) {
            manager = new SshTunnelManager();
            Session session = manager.openTunnel("10.0.0.1", 22, "root", "password");

            long before = readLastUsedMs(session);
            Thread.sleep(5);
            manager.touch(session);

            assertTrue(readLastUsedMs(session) > before, "touch debe renovar el timestamp de último uso");
        }
    }

    @Test
    void touch_doesNothing_whenSessionNotInCache() {
        manager = new SshTunnelManager();
        Session unrelated = mock(Session.class);

        assertDoesNotThrow(() -> manager.touch(unrelated));
    }

    @Test
    void touch_doesNothing_whenSessionNull() {
        manager = new SshTunnelManager();

        assertDoesNotThrow(() -> manager.touch(null));
    }

    @Test
    void evictIdleSessions_runsWithoutError_whenCacheEmpty() throws Exception {
        manager = new SshTunnelManager();
        Method evict = SshTunnelManager.class.getDeclaredMethod("evictIdleSessions");
        evict.setAccessible(true);
        evict.invoke(manager);
    }

    private long readLastUsedMs(Session session) throws Exception {
        java.lang.reflect.Field cacheField = SshTunnelManager.class.getDeclaredField("sessionCache");
        cacheField.setAccessible(true);
        @SuppressWarnings("unchecked")
        java.util.Map<String, ?> map = (java.util.Map<String, ?>) cacheField.get(manager);
        if (map.isEmpty()) {
            throw new IllegalStateException("Sesión no encontrada en caché");
        }
        Object cached = map.values().iterator().next();
        java.lang.reflect.Field lastUsed = cached.getClass().getDeclaredField("lastUsedMs");
        lastUsed.setAccessible(true);
        return lastUsed.getLong(cached);
    }
}
