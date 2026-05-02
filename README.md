# VulnPrint

VulnPrint is a modern, high-performance pentest reporting and management platform designed for security professionals. It features a robust Spring Boot backend, a sleek "Security Terminal" themed frontend, and integrated report design capabilities.

## Key Features
- **Sleek Tiled UI:** A consistent, high-tech interface with interactive, collapsible tiles and neon-green accents.
- **Project Lifecycle Management:** Track assessments from initialization to completion across various categories (Web, Mobile, API, Network, Source Code).
- **Vulnerability Registry:** Detailed documentation of findings with support for reproduction steps, request/response captures, and source code context.
- **Automated CVSS v3.1:** Integrated calculator for real-time risk scoring and vector generation.
- **Report Designer:** Modular, drag-and-drop report customization including legal disclaimers, methodology selection, and analytics visualization.
- **API Mapping Registry:** Comprehensive documentation for template tags and dynamic data mapping.
- **Administrative Suite:** Manage users, roles, and global organizational branding.

## Architecture
- **Backend:** Spring Boot (Java 17), Spring Data JPA, Hibernate.
- **Database:** PostgreSQL (with UTC timezone enforcement).
- **Frontend:** Thymeleaf templates, Tailwind CSS, Vanilla JavaScript, Chart.js, SortableJS.
- **UI System:** "Cyber-Industrial Terminal" aesthetic with charcoal surfaces (`#0e0e0e`) and neon primary accents (`#4FFE49`).

## Documentation
- **API Guide:** Accessible via `/swagger.html` when the server is running.
- **Template Mapping:** Comprehensive documentation available at `/template-guide`.

## Security Warning
This application is designed for security professionals to manage authorized pentest data. Ensure it is deployed in controlled, authorized environments only.

## License
MIT License - See the project repository for details.
