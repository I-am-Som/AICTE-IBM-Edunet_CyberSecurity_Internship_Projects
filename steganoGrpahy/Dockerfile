# Use an official Java runtime as a parent image
FROM eclipse-temurin:21-jdk

# Set the working directory inside the container
WORKDIR /app

# Copy the project files to the container
COPY . .

# Build the project inside the container
RUN ./mvnw clean package -DskipTests

# Copy the built JAR to the container
RUN cp target/*.jar app.jar

# Expose the application port
EXPOSE 8080

# Run the application
CMD ["java", "-jar", "app.jar"]
