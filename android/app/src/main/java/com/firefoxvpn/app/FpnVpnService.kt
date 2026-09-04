package com.firefoxvpn.app

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import core.AndroidBridge
import core.Core

class FpnVpnService : VpnService(), AndroidBridge {

    private var vpnInterface: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val proxyPass = intent?.getStringExtra("PROXY_PASS") ?: ""
        val node = intent?.getStringExtra("NODE") ?: ""

        // 构建虚拟网卡 tun0
        vpnInterface = Builder()
            .setSession("FirefoxVPN")
            .addAddress("10.0.0.2", 24)
            .addDnsServer("1.1.1.1")
            .addRoute("0.0.0.0", 0) // 拦截全量公网 IPv4
            .setMtu(1500)
            .establish()

        val fd = vpnInterface!!.fd

        // 启动 Go 核心并传入自身用于 protectSocket
        Thread {
            Core.startVPN(fd, proxyPass, node, this)
        }.start()

        return START_STICKY
    }

    override fun protectSocket(fd: Long): Boolean {
        // 核心防回环：保护 Go 底层连接不落入虚拟网卡
        return protect(fd.toInt())
    }

    override fun onStatusUpdate(status: String?) {
        // 广播给 UI 刷新
    }

    override fun onDestroy() {
        super.onDestroy()
        Core.stopVPN()
        vpnInterface?.close()
    }
}
