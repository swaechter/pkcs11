rootProject.name = "pkcs11"

include("pkcs11-cli")
include("pkcs11-library")
include("pkcs11-testing")

dependencyResolutionManagement {
    versionCatalogs {
        create("libraries") {
            // Plugins
            plugin("shadow", "com.github.johnrengelman.shadow").version("8.1.1")

            // Testing (General)
            library("junit-api", "org.junit.jupiter:junit-jupiter-api:5.10.2")
            library("junit-engine", "org.junit.jupiter:junit-jupiter-engine:5.10.2")

            // Testing (PDF signing)
            library("slf4j-nop", "org.slf4j:slf4j-nop:2.0.12")
            library("itext-kernel", "com.itextpdf:kernel:8.0.3")
            library("itext-io", "com.itextpdf:io:8.0.3")
            library("itext-layout", "com.itextpdf:layout:8.0.3")
            library("itext-sign", "com.itextpdf:sign:8.0.3")
            library("itext-bouncycastle", "com.itextpdf:bouncy-castle-adapter:8.0.3")
        }
    }
}
