# WorkManager (see Reminders.kt) has Room create its database by
# reflection, R8 drops that constructor in release builds otherwise.
-keep class * extends androidx.room.RoomDatabase {
    <init>();
}
