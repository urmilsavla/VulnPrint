# Setup Guide: Running VulnPrint from Scratch

Follow these steps to get the VulnPrint project up and running on your local machine.

## 1. Prerequisites
Ensure you have the following installed:
- **Java Development Kit (JDK) 17** or higher.
- **Apache Maven 3.8+** (or use the provided `./mvnw` wrapper).
- **PostgreSQL 15+**.
- **Git** (for cloning the repository).

## 2. Database Configuration
1. **Start PostgreSQL:** Ensure your PostgreSQL server is active.
2. **Create Database:** Open your terminal or a tool like `pgAdmin` and create a new database named `vulnprint`:
   ```sql
   CREATE DATABASE vulnprint;
   ```
3. **Create User:** Create a dedicated user for the application (matches default project settings):
   ```sql
   CREATE USER vulnuser WITH PASSWORD 'vulnpassword';
   GRANT ALL PRIVILEGES ON DATABASE vulnprint TO vulnuser;
   ```

## 3. Application Properties
Open `src/main/resources/application.properties` and verify the settings:
- **Datasource URL:** `jdbc:postgresql://localhost:5432/vulnprint?options=-c%20timezone=UTC`
- **Credentials:** Username `vulnuser` and Password `vulnpassword`.
- **Timezone:** It is critical that the database connection uses `UTC` to prevent startup errors.

## 4. Build and Run
Navigate to the project root directory and execute:

### Using Maven Wrapper (Recommended)
**Windows:**
```cmd
mvnw.cmd clean install
mvnw.cmd spring-boot:run
```

**Linux/macOS:**
```bash
./mvnw clean install
./mvnw spring-boot:run
```

## 5. Access the Application
- **Frontend UI:** Open your browser and go to `http://localhost:8080/`.
- **Initial Login:** Use the credentials seeded by `DataInitializer.java`:
  - **Username:** `admin`
  - **Password:** `admin123`
- **API Documentation:** View the Swagger UI at `http://localhost:8080/swagger.html`.

## 6. (Optional) Using Docker
If you prefer Docker, you can start the database using the provided `docker-compose.yml`:
```bash
docker-compose up -d
```
Then run the Spring Boot application locally.

## Troubleshooting
- **Port Conflict:** If port `8080` is already in use, change `server.port` in `application.properties`.
- **Timezone Error:** If you see `FATAL: invalid value for parameter "TimeZone"`, ensure the connection URL includes `?options=-c%20timezone=UTC`.
