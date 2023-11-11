plugins {
    id("java")
}

group = "ch.swaechter"
version = "0.0.1"

repositories {
    mavenCentral()
}

dependencies {
    // Testing
    testImplementation(libraries.junit.api)
    testImplementation(libraries.junit.engine)
    testRuntimeOnly(libraries.junit.engine)
}

tasks.withType<JavaCompile> {
    sourceCompatibility = JavaVersion.VERSION_21.toString()
    targetCompatibility = JavaVersion.VERSION_21.toString()
    options.encoding = "UTF-8"
}

tasks.withType<Test> {
    useJUnitPlatform()
}

tasks.withType<JavaCompile> {
    options.compilerArgs?.addAll(listOf("--enable-preview"))
}

tasks.withType<Test> {
    jvmArgs = listOf("--enable-preview")
}

tasks.withType<JavaExec> {
    jvmArgs = listOf("--enable-preview")
}
