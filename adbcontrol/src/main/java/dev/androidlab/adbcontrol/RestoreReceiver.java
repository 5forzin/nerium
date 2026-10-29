package dev.androidlab.adbcontrol;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.provider.Settings;

public final class RestoreReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context context, Intent intent) {
        boolean dryRun = context.getSharedPreferences(MainActivity.PREFS, Context.MODE_PRIVATE)
                .getBoolean("dry_run", false);
        MainActivity.record(context, "recovery_fired", dryRun);
        int original = context.getSharedPreferences(MainActivity.PREFS, Context.MODE_PRIVATE)
                .getInt("original_adb", -1);
        if (original == 0 || original == 1) {
            Settings.Global.putInt(context.getContentResolver(), Settings.Global.ADB_ENABLED, original);
            MainActivity.record(context, "recovery_applied", dryRun);
        }
    }
}
