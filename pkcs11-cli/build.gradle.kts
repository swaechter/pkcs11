import com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar

plugins {
    alias(libraries.plugins.shadow)
}

dependencies {
    // Project
    implementation(project(":pkcs11-library"))
}

tasks {
    named<ShadowJar>("shadowJar") {
        archiveBaseName.set("pkcs11-cli")
        mergeServiceFiles()
        manifest {
            attributes(mapOf("Main-Class" to "ch.swaechter.pkcs11.cli.Application"))
        }
    }

    build {
        dependsOn(shadowJar)
    }
}
