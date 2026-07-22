package com.devsecops.vulncheckerbackend.config;

import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestTemplate;

import static org.junit.jupiter.api.Assertions.*;

class RestTemplateConfigTest {

    private final RestTemplateConfig config = new RestTemplateConfig();

    @Test
    void wazuhRestTemplate_createsRestTemplate() throws Exception {
        RestTemplate restTemplate = config.wazuhRestTemplate();
        assertNotNull(restTemplate);
    }
}
