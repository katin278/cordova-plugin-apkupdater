package de.kolbasa.apkupdater.tools;

import android.app.PendingIntent;
import android.app.admin.DevicePolicyManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInstaller;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.provider.Settings;
import android.os.PowerManager;
import android.app.admin.DeviceAdminReceiver;
import android.Manifest;


import androidx.core.content.FileProvider;

import com.scottyab.rootbeer.RootBeer;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;

import de.kolbasa.apkupdater.exceptions.InstallationFailedException;
import de.kolbasa.apkupdater.exceptions.InvalidPackageException;
import de.kolbasa.apkupdater.exceptions.RootException;

import android.content.ComponentName;

public class ApkInstaller {

    private static Uri getUpdate(Context context, File update) throws IOException {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            String fileProvider = context.getPackageName() + ".apkupdater.provider";
            return FileProvider.getUriForFile(context, fileProvider, update);
        } else {
            File externalPath = new File(context.getExternalCacheDir(), update.getName());
            FileTools.copy(update, externalPath);
            return Uri.fromFile(externalPath);
        }
    }

    public static void install(Context context, File update) throws IOException {
        Intent intent;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            intent = new Intent(Intent.ACTION_INSTALL_PACKAGE);
            intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            intent.setData(getUpdate(context, update));
        } else {
            intent = new Intent(Intent.ACTION_VIEW);
            intent.setDataAndType(getUpdate(context, update), "application/vnd.android.package-archive");
        }
        if (WindowStatus.isWindowed(context)) {
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
            intent.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
        }
        context.startActivity(intent);
    }

    public static boolean isDeviceRooted(Context context) {
        RootBeer rootBeer = new RootBeer(context);
        return (rootBeer.checkSuExists() && (rootBeer.checkForRWPaths() || rootBeer.checkForRootNative()));
    }

    /**
     * https://stackoverflow.com/a/39420232
     */
    public static boolean requestRootAccess() throws RootException {
        Process process = null;
        try {
            process = Runtime.getRuntime().exec(new String[]{"su", "-c", "id"});
            BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String output = in.readLine();
            return output != null && output.toLowerCase().contains("uid=0");
        } catch (Exception e) {
            throw new RootException(e);
        } finally {
            if (process != null) {
                process.destroy();
            }
        }
    }

    public static void rootInstall(Context context, File update) throws IOException,
            PackageManager.NameNotFoundException, InvalidPackageException, RootException {
        String packageName = context.getPackageName();
        Intent launchIntent = context.getPackageManager().getLaunchIntentForPackage(packageName);
        String mainActivity = launchIntent.getComponent().getClassName();

        // -r Reinstall if needed
        // -d Downgrade if needed
        String command = "pm install -r -d '" + update.getCanonicalPath() + "'";

        if (AppData.getPackageInfo(context, update).getPackageName().equals(packageName)) {
            // Restart app if same package
            command += " && am start -n " + packageName + "/" + mainActivity;
        }

        Process process = null;
        try {
            process = Runtime.getRuntime().exec(new String[]{"su", "-c", command});
            StringBuilder builder = new StringBuilder();

            BufferedReader stdOut = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String s;
            while ((s = stdOut.readLine()) != null) {
                builder.append(s);
            }
            BufferedReader stdError = new BufferedReader(new InputStreamReader(process.getErrorStream()));
            while ((s = stdError.readLine()) != null) {
                builder.append(s);
            }

            process.waitFor();
            stdOut.close();
            stdError.close();

            if (builder.length() > 0 && !builder.toString().equals("Success")) {
                throw new InstallationFailedException(builder.toString());
            }
        } catch (Exception e) {
            throw new RootException(e);
        } finally {
            if (process != null) {
                process.destroy();
            }
        }
    }

    public static boolean isDeviceOwner(Context context) {
        DevicePolicyManager mDPM = (DevicePolicyManager) context.getSystemService(Context.DEVICE_POLICY_SERVICE);
        return mDPM.isDeviceOwnerApp(context.getPackageName());
    }

    /**
     * 使用设备管理员权限重启设备
     * @param context 上下文
     * @throws SecurityException 如果应用不是设备管理员或没有重启权限
     */
    public static void rebootDevice(Context context) throws SecurityException {
        DevicePolicyManager mDPM = (DevicePolicyManager) context.getSystemService(Context.DEVICE_POLICY_SERVICE);
        ComponentName admin = new ComponentName(context, DAReceiver.class);
        
        if (!mDPM.isDeviceOwnerApp(context.getPackageName())) {
            throw new SecurityException("应用程序不是设备管理员");
        }

        try {
            // 首先尝试使用 adb shell 命令重启
            try {
                Process process = Runtime.getRuntime().exec("am broadcast -a android.intent.action.REBOOT");
                process.waitFor();
                
                // 如果广播命令执行成功但设备没有重启，尝试直接重启命令
                process = Runtime.getRuntime().exec("reboot");
                process.waitFor();
                
                // 如果还是没有重启，尝试使用 su 命令
                if (isDeviceRooted(context)) {
                    process = Runtime.getRuntime().exec(new String[]{"su", "-c", "reboot"});
                    process.waitFor();
                }
                
                // 读取命令执行的输出和错误信息
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
                StringBuilder error = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    error.append(line).append("\n");
                }
                
                if (error.length() > 0) {
                    logError("shell命令重启", new Exception(error.toString()));
                }
                
                // 给系统一些时间来处理重启请求
                Thread.sleep(1000);
                
            } catch (Exception e) {
                logError("shell命令重启", e);
                
                // 如果 shell 命令失败，尝试使用系统 API
                try {
                    PowerManager pm = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
                    pm.reboot(null);
                    Thread.sleep(1000);
                } catch (Exception ex) {
                    logError("PowerManager重启", ex);
                }
            }

        } catch (Exception e) {
            throw new SecurityException("重启失败: " + e.getMessage());
        }
    }

    /**
     * 请求设备管理员所需的所有权限
     * @param context 上下文
     * @return 是否成功设置所有权限
     */
    public static boolean requestPermissions(Context context) {
        if (!isDeviceOwner(context)) {
            return false;
        }

        DevicePolicyManager mDPM = (DevicePolicyManager) context.getSystemService(Context.DEVICE_POLICY_SERVICE);
        ComponentName admin = new ComponentName(context, DAReceiver.class);

        mDPM.setPermissionGrantState(
            admin,
            context.getPackageName(),
            Manifest.permission.ACCESS_FINE_LOCATION,
            DevicePolicyManager.PERMISSION_GRANT_STATE_GRANTED
        );
        mDPM.setPermissionGrantState(
            admin,
            context.getPackageName(),
            Manifest.permission.ACCESS_BACKGROUND_LOCATION,
            DevicePolicyManager.PERMISSION_GRANT_STATE_GRANTED
        );
        mDPM.setPermissionGrantState(
            admin,
            context.getPackageName(),
            Manifest.permission.ACCESS_COARSE_LOCATION,
            DevicePolicyManager.PERMISSION_GRANT_STATE_GRANTED
        );
         mDPM.setPermissionGrantState(
            admin,
            context.getPackageName(),
            Manifest.permission.MANAGE_EXTERNAL_STORAGE,
            DevicePolicyManager.PERMISSION_GRANT_STATE_GRANTED
        );
         mDPM.setPermissionGrantState(
            admin,
            context.getPackageName(),
            Manifest.permission.WRITE_SECURE_SETTINGS,
            DevicePolicyManager.PERMISSION_GRANT_STATE_GRANTED
        );
        mDPM.setPermissionGrantState(
            admin,
            context.getPackageName(),
            Manifest.permission.INSTALL_LOCATION_PROVIDER,
            DevicePolicyManager.PERMISSION_GRANT_STATE_GRANTED
        );
        
        return true;
    }

    public static void ownerInstall(Context context, File update) throws IOException {
        if (!isDeviceOwner(context)) {
            throw new SecurityException("App is not device owner");
        }

        InputStream in = context.getContentResolver().openInputStream(getUpdate(context, update));

        PackageManager pm = context.getPackageManager();
        PackageInstaller pi = pm.getPackageInstaller();
        PackageInstaller.SessionParams params = new PackageInstaller.SessionParams(
                PackageInstaller.SessionParams.MODE_FULL_INSTALL);

        int sessionId = pi.createSession(params);
        PackageInstaller.Session s = pi.openSession(sessionId);
        OutputStream out = s.openWrite(update.getName(), 0, -1);
        byte[] buffer = new byte[65536];
        int chunk;
        while ((chunk = in.read(buffer)) != -1) {
            out.write(buffer, 0, chunk);
        }
        s.fsync(out);
        in.close();
        out.close();

        PendingIntent pendingIntent = PendingIntent.getBroadcast(context, 0, new Intent(),
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.M ? PendingIntent.FLAG_IMMUTABLE : 0);

        s.commit(pendingIntent.getIntentSender());
        s.close();
    }

    private static void logError(String method, Exception e) {
        System.err.println("重启方法 " + method + " 失败: " + e.getMessage());
        e.printStackTrace();
    }

}
