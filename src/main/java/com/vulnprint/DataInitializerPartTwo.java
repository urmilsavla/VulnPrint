package com.vulnprint;

import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * DataInitializerPartTwo: Historical/Demo Data Loader.
 * Disabled for Production Core deployment to ensure a clean data slate.
 */
@Component
@Order(2)
public class DataInitializerPartTwo implements CommandLineRunner {

    @Override
    public void run(String... args) throws Exception {
        // Historical and Demo data initialization logic has been removed.
        // The system now relies on the Production Core provisioned in DataInitializer.
        System.out.println("[SYSTEM] DataInitializerPartTwo (Demo Data) is inactive.");
    }
}
