FROM openjdk:17-jdk-alpine
LABEL maintainer="codejon.com"
COPY target/*.jar app.jar
ENTRYPOINT ["java","-jar","/app.jar"]