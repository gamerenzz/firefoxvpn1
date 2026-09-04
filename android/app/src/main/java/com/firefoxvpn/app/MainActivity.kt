package com.firefoxvpn.app

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.browser.customtabs.CustomTabsIntent
import core.AndroidBridge
import core.Core

class MainActivity : Activity(), AndroidBridge {

    private lateinit var tvStatus: TextView
    private lateinit var etLogs: EditText
    private lateinit var scrollLog: ScrollView
    private var verifier = ""
    private var token = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        tvStatus = findViewById(R.id.tvStatus)
        etLogs = findViewById(R.id.etLogs)
        scrollLog = findViewById(R.id.scrollLog)

        val btnLogin = findViewById<Button>(R.id.btnLogin)
        val btnConnect = findViewById<Button>(R.id.btnConnect)
        val btnCopyAll = findViewById<Button>(R.id.btnCopyAll)
        val btnClearLog = findViewById<Button>(R.id.btnClearLog)

        // 注册桥接对象，使得还没点连接时的预备日志也能输出
        Core.registerBridge(this)

        // 1. 登录
        btnLogin.setOnClickListener {
            try {
                val session = Core.initAuthURL()
                // gomobile 导出的返回值可以通过属性直接访问
                // 如果是按顺序返回的多元组，gomobile 会封装成具有 Getter 的对象
                onLog("INFO", "Opening CustomTab for login...")
                // 此处填入生成的 AuthURL 与 Verifier
            } catch (e: Exception) {
                onLog("ERROR", "Login exception: ${e.message}")
            }
        }

        // 2. 连接
        btnConnect.setOnClickListener {
            val vpnIntent = VpnService.prepare(this)
            if (vpnIntent != null) {
                startActivityForResult(vpnIntent, 100)
            } else {
                onActivityResult(100, RESULT_OK, null)
            }
        }

        // 3. 一键全选并复制到系统剪贴板
        btnCopyAll.setOnClickListener {
            val fullText = etLogs.text.toString()
            if (fullText.isNotEmpty()) {
                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                val clip = ClipData.newPlainText("VPN Logs", fullText)
                clipboard.setPrimaryClip(clip)
                Toast.makeText(this, "日志已全选复制到剪贴板", Toast.LENGTH_SHORT).show()
            }
        }

        // 4. 清空面板
        btnClearLog.setOnClickListener {
            etLogs.setText("")
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode == 100 && resultCode == RESULT_OK) {
            val intent = Intent(this, FpnVpnService::class.java).apply {
                putExtra("PROXY_PASS", token)
                putExtra("NODE", "tokyo.m1.fastly-masque.net:443")
            }
            startService(intent)
        }
    }

    // --- AndroidBridge 接口实现 ---

    override fun protectSocket(fd: Long): Boolean {
        return true
    }

    override fun onStatusUpdate(status: String?) {
        runOnUiThread {
            tvStatus.text = "状态: $status"
        }
    }

    override fun onLog(level: String?, message: String?) {
        runOnUiThread {
            etLogs.append("[$level] $message\n")
            // 自动滚动到底部
            scrollLog.post {
                scrollLog.fullScroll(ScrollView.FOCUS_DOWN)
            }
        }
    }
}
