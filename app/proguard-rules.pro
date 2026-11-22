# DoctorG ProGuard / R8 Rules (com.python.doctorg)

-keepattributes SourceFile,LineNumberTable,*Annotation*,Signature,InnerClasses,EnclosingMethod

# Keep DoctorG models, Room entities, and Serialization classes
-keep class com.python.doctorg.data.local.entity.** { *; }
-keep class com.python.doctorg.data.remote.model.** { *; }
-keep class com.python.doctorg.domain.model.** { *; }
-keep class com.python.doctorg.receiver.** { *; }
-keep class com.python.doctorg.service.** { *; }
-keep class com.python.doctorg.widget.** { *; }

# Kotlinx Serialization
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.AnnotationsKt
-keepclassmembers class kotlinx.serialization.json.** {
    *** Companion;
}
-keepclasseswithmembers class kotlinx.serialization.json.** {
    kotlinx.serialization.KSerializer serializer(...);
}
-keep,includedescriptorclasses class com.python.doctorg.**$$serializer { *; }
-keepclassmembers class com.python.doctorg.** {
    *** Companion;
}
-keepclasseswithmembers class com.python.doctorg.** {
    kotlinx.serialization.KSerializer serializer(...);
}

# SQLCipher 16KB native bindings
-keep class net.zetetic.database.** { *; }
-keep class net.zetetic.database.sqlcipher.** { *; }

# LiteRT / TensorFlow Lite
-keep class org.tensorflow.lite.** { *; }

# Retrofit & Moshi
-keepattributes Signature, Exceptions
-keep class retrofit2.** { *; }
-keep class com.squareup.moshi.** { *; }

# Hilt & Dagger
-keep class dagger.hilt.** { *; }
-keep class javax.inject.** { *; }
-keep class * extends androidx.lifecycle.ViewModel {
    <init>(...);
}

# Glance AppWidget
-keep class androidx.glance.** { *; }
