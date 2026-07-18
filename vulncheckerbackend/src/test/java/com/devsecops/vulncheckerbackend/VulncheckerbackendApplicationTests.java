package com.devsecops.vulncheckerbackend;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
@Disabled("Requires PostgreSQL database — run with docker-compose or CI")
class VulncheckerbackendApplicationTests {

	@Test
	void contextLoads() {
	}

}
