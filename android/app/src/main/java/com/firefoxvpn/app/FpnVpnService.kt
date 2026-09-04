package com.firefoxvpn.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import core.AndroidBridge
import core.Core

class FpnVpnService : VpnService(), AndroidBridge {

    private var vpnInterface: ParcelFileDescriptor? = null
    private val channelId = "firefox_vpn_channel"

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val accessToken = intent?.getStringExtra("ACCESS_TOKEN") ?: ""
        val node = intent?.getStringExtra("NODE") ?: ""

        // 1. 极其关键：必须在第一时间挂上前台服务通知，防止 Android 闪退
        try {
            val notification = createNotification("Firefox VPN 正在安全连接中...")
            startForeground(1001, notification)
        } catch (e: Exception) {
            e.printStackTrace()
        }

        // 2. 建立系统虚拟网卡
        try {
            vpnInterface = Builder()
                .setSession("FirefoxVPN")
                .addAddress("10.0.0.2", 24)
                .addDnsServer("1.1.1.1")
                .addRoute("0.0.0.0", 0)
                .setMtu(1500)
                .establish()
        } catch (e: Exception) {
            e.printStackTrace()
        }

        // 3. 异步启动 Go 核心，杜绝阻塞主线程
        Thread {
            try {
                Core.startEngine(accessToken, node, this)
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }.start()

        return START_STICKY
    }

    override fun protectSocket(fd: Long): Boolean {
        return protect(fd.toInt())
    }

    override fun onStatusUpdate(status: String?) {
        // 更新通知栏文字
        try {
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.notify(1001, createNotification("状态: $status"))
        } catch (e: Exception) {
            // ignore
        }
    }

    override fun onLog(level: String?, message: String?) {}

    override fun onDestroy() {
        super.onDestroy()
        Core.stopEngine()
        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                channelId,
                "VPN 状态提醒",
                NotificationManager.IMPORTANCE_LOW
            )
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(text: String): Notification {
        return NotificationCompat.Builder(this, channelId)
            .setContentTitle("Firefox VPN")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }
}
