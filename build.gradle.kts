plugins {
    kotlin("jvm") version "2.0.21"
    application
}

group = "scanner"
version = "1.0.0"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(kotlin("test"))
}

kotlin {
    jvmToolchain(17)
}

application {
    mainClass.set("scanner.MainKt")
}

tasks.test {
    useJUnitPlatform()
}
