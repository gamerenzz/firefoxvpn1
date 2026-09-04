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
    private val channelId = "vpn_service_channel"

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val proxyPass = intent?.getStringExtra("PROXY_PASS") ?: ""
        val node = intent?.getStringExtra("NODE") ?: ""

        // Android 8.0+ 必须启动前台通知保活
        val notification = createNotification("Firefox VPN 正在运行...")
        startForeground(1, notification)

        // 1. 建立系统虚拟网卡 (TUN)
        vpnInterface = Builder()
            .setSession("FirefoxVPN")
            .addAddress("10.0.0.2", 24)
            .addDnsServer("1.1.1.1")
            .addRoute("0.0.0.0", 0) // 拦截全量流量
            .setMtu(1500)
            .establish()

        // 2. 调用 Go 核心启动 HTTP/3 隧道
        Thread {
            try {
                // 调用新版 StartEngine，传入自身实现 ProtectSocket 保护底层连接
                val localSocks = Core.startEngine(proxyPass, node, this)
                println("VPN Core Started at: $localSocks")
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }.start()

        return START_STICKY
    }

    override fun protectSocket(fd: Long): Boolean {
        // 核心防回环：保护 Go 底层的 QUIC/UDP 套接字不落入虚拟网卡
        return protect(fd.toInt())
    }

    override fun onStatusUpdate(status: String?) {
        // 状态更新
    }

    override fun onLog(level: String?, message: String?) {
        // 日志
    }

    override fun onDestroy() {
        super.onDestroy()
        Core.stopEngine()
        vpnInterface?.close()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                channelId,
                "VPN 运行状态",
                NotificationManager.IMPORTANCE_LOW
            )
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(content: String): Notification {
        return NotificationCompat.Builder(this, channelId)
            .setContentTitle("Firefox VPN")
            .setContentText(content)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }
}
