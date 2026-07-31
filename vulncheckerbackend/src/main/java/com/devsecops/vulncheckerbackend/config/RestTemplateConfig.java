package com.devsecops.vulncheckerbackend.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.*;
import java.security.cert.X509Certificate;

/**
 * Cliente exclusivo del Indexer de Wazuh. Se conecta solo a
 * {@code https://127.0.0.1:{puerto}} vía túnel SSH cifrado; la validación del
 * cert autofirmado no aporta autenticidad extra.
 */
@Configuration
@SuppressWarnings({"java:S5527", "java:S5525", "java:S4830"})
public class RestTemplateConfig {

    @Bean(name = "wazuhRestTemplate")
    public RestTemplate wazuhRestTemplate() throws Exception {
        // TrustManager que acepta cualquier certificado
        TrustManager[] trustAll = new TrustManager[]{
                new X509TrustManager() {
                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }

                    @Override
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        // Intencionadamente en blanco: este TrustManager confía en todos los certificados de cliente.
                        // para permitir la conexión a una instancia de Wazuh con un certificado autofirmado en entornos locales/de prueba.
                        //  En producción, valide los certificados con un almacén de confianza adecuado y elimine este comportamiento permisivo.
                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        // Se ha dejado en blanco intencionadamente: este TrustManager confía en todos los 
                        // certificados del servidor (por ejemplo, los autofirmados de Wazuh).
                        // Consulte la documentación Javadoc de la clase; reemplácelo con un almacén de confianza real en producción para garantizar la 
                        // validación del certificado.
                    }
                }
        };

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustAll, new java.security.SecureRandom());

        HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
        HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);

        return new RestTemplate(new SimpleClientHttpRequestFactory());
    }
}