import com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar

plugins {
    alias(libraries.plugins.shadow)
}

dependencies {
    // Project
    implementation(project(":pkcs11-library"))

    // PDF signing
    implementation(libraries.slf4j.nop)
    implementation(libraries.itext.kernel)
    implementation(libraries.itext.io)
    implementation(libraries.itext.layout)
    implementation(libraries.itext.sign)
    implementation(libraries.itext.bouncycastle) {
        exclude(group = "org.bouncycastle", module = "bcpkix-jdk15on")
        exclude(group = "org.bouncycastle", module = "bcprov-jdk15on")
    }

    // Testing (General)
    testImplementation(libraries.junit.api)
    testImplementation(libraries.junit.engine)
    testRuntimeOnly(libraries.junit.engine)
}

tasks {
    named<ShadowJar>("shadowJar") {
        archiveBaseName.set("pkcs11-cli")
        mergeServiceFiles()
        manifest {
            attributes(mapOf("Main-Class" to "ch.swaechter.pkcs11.cli.Pkcs11Application"))
        }
    }

    build {
        dependsOn(shadowJar)
    }
}
