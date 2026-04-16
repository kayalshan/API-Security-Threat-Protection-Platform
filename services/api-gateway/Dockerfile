# Stage 1: Build
FROM maven:3.9.9-eclipse-temurin-21 AS builder

WORKDIR /build
COPY pom.xml ./pom.xml
COPY services/api-gateway/pom.xml ./services/api-gateway/pom.xml
COPY services/api-gateway/src ./services/api-gateway/src

RUN mvn -f services/api-gateway/pom.xml clean package -DskipTests

# Stage 2: Run
FROM eclipse-temurin:21-jdk-jammy

WORKDIR /app

COPY --from=builder /build/services/api-gateway/target/*.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java","-jar","/app/app.jar"]