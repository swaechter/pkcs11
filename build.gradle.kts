plugins {
    id("java")
}

group = "ch.swaechter"
version = "0.0.1"

repositories {
    mavenCentral()
    maven(url = "https://repo.itextsupport.com/artifactory/releases/")
}

dependencies {
    // Testing (General)
    testImplementation(libraries.junit.api)
    testImplementation(libraries.junit.engine)
    testRuntimeOnly(libraries.junit.engine)

    // Testing (PDF signing)
    testImplementation("org.slf4j:slf4j-nop:2.0.9")
    testImplementation("com.itextpdf.licensing:licensing-base:4.1.2")
    testImplementation("com.itextpdf:kernel:8.0.2")
    testImplementation("com.itextpdf:io:8.0.2")
    testImplementation("com.itextpdf:layout:8.0.2")
    testImplementation("com.itextpdf:sign:8.0.2")
    testImplementation("com.itextpdf:bouncy-castle-adapter:8.0.2") {
        exclude(group = "org.bouncycastle", module = "bcpkix-jdk15on")
        exclude(group = "org.bouncycastle", module = "bcprov-jdk15on")
    }
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
