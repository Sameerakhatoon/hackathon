# Use OpenJDK 17 as base image
FROM openjdk:17-jdk-slim

# Set working directory
WORKDIR /app

# Copy Maven files first (for better Docker layer caching)

# Copy Maven files first (for better Docker layer caching)
COPY pom.xml .
COPY src ./src

# Build the application using system Maven
RUN apt-get update && apt-get install -y maven && rm -rf /var/lib/apt/lists/*
RUN mvn dependency:go-offline -B
RUN mvn clean package -B

# Create final image
FROM openjdk:17-jdk-slim

# Install curl for health checks
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the built JAR file
COPY --from=0 /app/target/anti-phishing-ai-gateway-*.jar app.jar

# Create non-root user for security
RUN addgroup --system spring && adduser --system --group spring
# Create logs directory for logback and set ownership
RUN mkdir -p /app/logs && chown spring:spring /app/logs
USER spring:spring

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/actuator/health || exit 1

# Run the application
ENTRYPOINT ["java", "-jar", "/app/app.jar"]