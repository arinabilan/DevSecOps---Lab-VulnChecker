package com.devsecops.vulncheckerbackend.config;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Gestor de túneles SSH hacia el servidor Wazuh.
 * <p>
 * Reutiliza la misma sesión para múltiples sincronizaciones mientras haya actividad,
 * y la cierra automáticamente después de un periodo de inactividad.
 * <p>
 * <b>Puerto dinámico:</b> Cada túnel usa un puerto local asignado automáticamente por el SO
 * (mediante setPortForwardingL(0, ...)). Esto evita conflictos de puerto fijo.
 * </p>
 * <p>
 * <b>Seguridad:</b> La sesión no queda abierta para siempre; se cierra tras 5 minutos sin uso.
 * </p>
 */
@Component
public class SshTunnelManager {

    private static final Logger log = LoggerFactory.getLogger(SshTunnelManager.class);

    // Configuración del destino dentro del túnel (Wazuh API)
    private static final String WAZUH_HOST     = "127.0.0.1";
    private static final int    WAZUH_API_PORT = 9200;

    // Tiempo de inactividad máximo antes de cerrar la sesión (en milisegundos)
    private static final long   IDLE_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutos

    /**
     * Estructura que guarda una sesión junto con el timestamp de su último uso y el puerto local asignado.
     */
    private static class CachedSession {
        final Session session;
        final int localPort;        // puerto local dinámico asignado a este túnel
        volatile long lastUsedMs;

        CachedSession(Session session, int localPort) {
            this.session = session;
            this.localPort = localPort;
            this.lastUsedMs = System.currentTimeMillis();
        }

        void updateLastUsed() {
            this.lastUsedMs = System.currentTimeMillis();
        }
    }

    // Cache de sesiones: clave = "sshHost:sshPort:sshUser"
    private final ConcurrentHashMap<String, CachedSession> sessionCache = new ConcurrentHashMap<>();

    // Scheduler para limpiar sesiones inactivas periódicamente
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    /**
     * Constructor: inicia la tarea de limpieza de sesiones inactivas cada minuto.
     */
    public SshTunnelManager() {
        scheduler.scheduleAtFixedRate(this::evictIdleSessions, 1, 1, TimeUnit.MINUTES);
        log.info("SshTunnelManager inicializado con timeout de inactividad de {} ms", IDLE_TIMEOUT_MS);
    }

    /**
     * Obtiene (o crea) un túnel SSH reutilizable para las credenciales dadas.
     * Si ya existe una sesión activa y no ha expirado por inactividad, se devuelve la misma.
     * En caso contrario, se cierra la anterior (si existe) y se abre una nueva.
     * El túnel se crea con un puerto local dinámico (asignado por el sistema operativo).
     *
     * @param sshHost     IP o nombre del servidor SSH
     * @param sshPort     Puerto SSH (normalmente 22)
     * @param sshUser     Usuario SSH
     * @param sshPassword Contraseña SSH
     * @return Sesión SSH con el túnel ya establecido (puerto local dinámico)
     * @throws Exception si no se puede conectar o establecer el forwarding
     */
    public Session openTunnel(String sshHost, int sshPort, String sshUser, String sshPassword) throws Exception {
        String key = sshHost + ":" + sshPort + ":" + sshUser;
        CachedSession cached = sessionCache.get(key);

        // Si existe y la sesión sigue conectada, la reutilizamos
        if (cached != null && cached.session.isConnected()) {
            log.debug("Reutilizando sesión SSH existente para {} (puerto local {})", key, cached.localPort);
            cached.updateLastUsed();
            return cached.session;
        }

        // Si existía pero estaba desconectada, la removemos del cache
        if (cached != null) {
            log.warn("Sesión SSH cacheada para {} no está conectada, se descarta", key);
            closeTunnel(cached.session, cached.localPort);
            sessionCache.remove(key);
        }

        // Crear nueva sesión
        log.info("Abriendo nueva sesión SSH para {}@{}:{}", sshUser, sshHost, sshPort);
        JSch jsch = new JSch();
        Session session = jsch.getSession(sshUser, sshHost, sshPort);
        session.setPassword(sshPassword);

        // Configuración para evitar verificación de host key (solo entornos controlados)
        Properties config = new Properties();
        config.put("StrictHostKeyChecking", "no");
        session.setConfig(config);

        session.connect(10_000); // timeout 10 segundos

        // Establece el forward con puerto local 0 (el sistema asigna uno libre)
        int assignedPort = session.setPortForwardingL(0, WAZUH_HOST, WAZUH_API_PORT);
        log.info("Túnel SSH establecido: localhost:{} → {}:{}", assignedPort, WAZUH_HOST, WAZUH_API_PORT);

        CachedSession newCached = new CachedSession(session, assignedPort);
        sessionCache.put(key, newCached);
        return session;
    }

    /**
     * Obtiene el puerto local asociado a una sesión activa.
     *
     * @param session la sesión (debe haber sido abierta por este manager)
     * @return puerto local asignado, o 9201 por defecto si no se encuentra
     */
    public int getLocalPort(Session session) {
        // Buscar en el cache la entrada que contenga esta sesión
        for (CachedSession cached : sessionCache.values()) {
            if (cached.session.equals(session)) {
                return cached.localPort;
            }
        }
        log.warn("No se encontró el puerto local para la sesión, usando fallback 9201");
        return 9201; // fallback
    }

    /**
     * Cierra una sesión específica y la elimina del cache.
     * <p>
     * Este método se llama automáticamente por inactividad o al destruir el bean.
     * También se puede llamar explícitamente si se desea forzar el cierre.
     * </p>
     *
     * @param session   la sesión a cerrar (puede ser null)
     * @param localPort el puerto local que se usó en el forwarding
     */
    private void closeTunnel(Session session, int localPort) {
        if (session == null) return;
        try {
            // Eliminar el forwarding del puerto local específico
            session.delPortForwardingL(localPort);
            log.debug("Forwarding del puerto {} eliminado", localPort);
        } catch (Exception e) {
            log.debug("No se pudo eliminar el forwarding del puerto {} (puede que ya no exista)", localPort);
        }
        session.disconnect();
        log.debug("Sesión SSH cerrada explícitamente (puerto local {})", localPort);
    }

    /**
     * Versión pública de cierre que obtiene el puerto del cache.
     * Útil si se tiene la sesión pero no el puerto.
     *
     * @param session la sesión a cerrar
     */
    public void closeTunnel(Session session) {
        if (session == null) return;
        // Buscar el puerto en el cache
        for (CachedSession cached : sessionCache.values()) {
            if (cached.session.equals(session)) {
                closeTunnel(session, cached.localPort);
                return;
            }
        }
        // Si no está en cache, intentamos cerrar sin eliminar forwarding (puede no ser necesario)
        log.warn("Sesión no encontrada en cache, cerrando sin eliminar forwarding específico");
        session.disconnect();
    }

    /**
     * Cierra todas las sesiones activas al detener la aplicación Spring.
     * Libera los recursos y el scheduler.
     */
    @PreDestroy
    public void destroy() {
        log.info("Cerrando SshTunnelManager y todas las sesiones SSH activas");
        scheduler.shutdownNow();
        sessionCache.values().forEach(cached -> closeTunnel(cached.session, cached.localPort));
        sessionCache.clear();
    }

    /**
     * Tarea periódica que cierra las sesiones cuyo último uso supera el tiempo de inactividad.
     */
    private void evictIdleSessions() {
        long now = System.currentTimeMillis();
        sessionCache.values().removeIf(cached -> {
            if (now - cached.lastUsedMs > IDLE_TIMEOUT_MS) {
                log.info("Cerrando sesión SSH inactiva (último uso hace {} ms) - puerto local {}",
                         now - cached.lastUsedMs, cached.localPort);
                closeTunnel(cached.session, cached.localPort);
                return true;
            }
            return false;
        });
    }
}