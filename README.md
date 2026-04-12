# VulnPrint

VulnPrint is a modern, high-performance pentest reporting and management platform designed for security professionals. This project features a robust Spring Boot backend, a dynamic Thymeleaf/Tailwind CSS frontend, and integrated (intentional) vulnerabilities for educational and testing purposes.

## Key Features
- **Project Registry:** Manage Web, Mobile, API, Infrastructure, and Source Code pentests.
- **Vulnerability Matrix:** Dynamic tracking of findings with CVSS v3.1 scoring and automated risk index calculation.
- **Evidence Management:** Seamless intake of reproduction steps and POC images.
- **Real-time Metrics:** Global and project-specific risk scoring.
- **System Alerts:** Integrated notification system (supports intentional XSS testing).

## Technical Stack
- **Backend:** Java 17, Spring Boot 3.2.4, Spring Data JPA.
- **Database:** PostgreSQL.
- **Frontend:** HTML5, Thymeleaf, Tailwind CSS, JavaScript.
- **API:** RESTful architecture with integrated Swagger documentation.

## Security Note
This application is **intentionally vulnerable** to specific security flaws (e.g., SQL Injection, XSS, Path Traversal) to facilitate security training and tool testing. It is intended for use in controlled, authorized environments only.

## Setup
1. Configure your PostgreSQL instance in `src/main/resources/application.properties`.
2. Ensure the database timezone is set to `UTC`.
3. Run the application using Maven: `./mvnw spring-boot:run`.
