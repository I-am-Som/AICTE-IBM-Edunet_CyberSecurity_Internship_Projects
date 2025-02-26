# Use an official Java runtime as a parent image
FROM eclipse-temurin:21-jdk

# Set the working directory
WORKDIR /app

# Install OpenCV system libraries and Java bindings
RUN apt-get update && \
    apt-get install -y libopencv-dev openjdk-21-jdk && \
    apt-get install -y libopencv-java

# Copy Maven wrapper files
COPY mvnw .
COPY .mvn .mvn
COPY pom.xml .

# Download dependencies before copying the entire project
RUN ./mvnw dependency:go-offline

# Copy the entire project
COPY src src

# Build the project
RUN ./mvnw clean package -DskipTests

# Copy the built JAR to the container
RUN cp target/*.jar app.jar

# Expose the application port
EXPOSE 8080

# Run the application with correct OpenCV path
CMD ["java", "-Djava.library.path=/usr/lib/x86_64-linux-gnu/", "-jar", "app.jar"]
