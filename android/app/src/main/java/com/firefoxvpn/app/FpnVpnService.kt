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

    companion object {
        const val ACTION_VPN_LOG = "com.firefoxvpn.app.VPN_LOG"
        const val EXTRA_LOG_LEVEL = "LOG_LEVEL"
        const val EXTRA_LOG_MSG = "LOG_MSG"
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val accessToken = intent?.getStringExtra("ACCESS_TOKEN") ?: ""
        // 接收 MainActivity 传过来的选定节点，默认使用日本东京
        val targetNode = intent?.getStringExtra("TARGET_NODE") ?: "jp0.vpn.mozilla.org:443"

        // 1. 启动前台服务通知（防止系统杀进程）
        try {
            val notification = createNotification("Firefox VPN 正在安全连接中...")
            startForeground(1001, notification)
        } catch (e: Exception) {
            e.printStackTrace()
        }

        // 2. 建立虚拟网卡，拦截全量流量
        try {
            vpnInterface = Builder()
                .setSession("FirefoxVPN")
                .addAddress("10.0.0.2", 24)
                .addDnsServer("8.8.8.8")
                .addDnsServer("1.1.1.1")
                .addRoute("0.0.0.0", 0)
                .setMtu(1500)
                .establish()
        } catch (e: Exception) {
            onLog("ERROR", "Create TUN interface failed: ${e.message}")
        }

        // 3. 核心对齐：调用 3 个参数的 Core.startEngine(targetNode, token, bridge)
        Thread {
            try {
                val localSocks = Core.startEngine(targetNode, accessToken, this)
                onLog("INFO", "VPN Core running at: $localSocks")
            } catch (e: Exception) {
                onLog("ERROR", "StartEngine Exception: ${e.message}")
            }
        }.start()

        return START_STICKY
    }

    override fun protectSocket(fd: Long): Boolean {
        // 核心防回环
        return protect(fd.toInt())
    }

    override fun onStatusUpdate(status: String?) {
        try {
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.notify(1001, createNotification("状态: $status"))
        } catch (e: Exception) {
            // ignore
        }
    }

    override fun onLog(level: String?, message: String?) {
        val intent = Intent(ACTION_VPN_LOG).apply {
            putExtra(EXTRA_LOG_LEVEL, level ?: "INFO")
            putExtra(EXTRA_LOG_MSG, message ?: "")
            setPackage(packageName)
        }
        sendBroadcast(intent)
    }

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
