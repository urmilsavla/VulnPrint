# Setup Guide: VulnPrint Deployment

Follow these steps to get the VulnPrint project up and running on your local machine.

## 1. Prerequisites
Ensure you have the following installed:
- **Java Development Kit (JDK) 17**
- **Maven 3.8+**
- **PostgreSQL 14+**
- **Git**

## 2. Database Configuration
1. Create a new PostgreSQL database named `vulnprint`.
2. Create a user `vulnuser` with password `vulnpassword`.
3. Update `src/main/resources/application.properties` if you wish to use different credentials.
   ```properties
   spring.datasource.url=jdbc:postgresql://localhost:5432/vulnprint?options=-c%20timezone=UTC
   spring.datasource.username=vulnuser
   spring.datasource.password=vulnpassword
   ```

## 3. Clone and Initialize
```bash
git clone <repository-url>
cd VulnPrint
```

## 4. Run the Application
You can start the server using Maven:
```bash
mvn spring-boot:run
```
The application will be accessible at `http://localhost:8080`.

## 5. Initial Access
- **Default Login:** Use the credentials established by the `DataInitializer` (typically `admin` / `password123`).
- **Authorization System:** The login screen provides secure entry into the platform.

## 6. Project Structure
- `/dashboard`: High-level metrics and active projects.
- `/pentest/add`: Initialize new security audits.
- `/user-management`: System-wide user and role configuration.
- `/organization-settings`: Global reporting identity management.
- `/template-guide`: API mapping reference for report designers.

## Troubleshooting
- **Port Conflict:** If port `8080` is in use, change `server.port` in `application.properties`.
- **Timezone Errors:** Ensure the PostgreSQL connection string includes `?options=-c%20timezone=UTC`.
- **Upload Limits:** Max file size is configured to 50MB for evidence captures.
