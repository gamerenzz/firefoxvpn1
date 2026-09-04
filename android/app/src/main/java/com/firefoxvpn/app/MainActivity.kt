package com.firefoxvpn.app

import android.app.Activity
import android.app.AlertDialog
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

    // 保存本次 PKCE 流程的校验串
    private var verifier = ""
    // 保存换取到的 AccessToken / ProxyPass
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

        // 注册日志回调，确保初始化过程能打出日志
        Core.registerBridge(this)

        // 1. 登录逻辑：生成授权 URL 并调用 Chrome Custom Tabs 打开
        btnLogin.setOnClickListener {
            try {
                onLog("INFO", "Preparing PKCE OAuth parameters...")
                val result = Core.initAuthURL()
                val authUrl = result.authURL
                verifier = result.verifier

                onLog("INFO", "Verifier generated. Launching official login page...")
                
                // 打开手机自带浏览器登录
                val customTabsIntent = CustomTabsIntent.Builder().build()
                customTabsIntent.launchUrl(this, Uri.parse(authUrl))

                // 弹出对话框引导用户粘回登录完成页面的 code
                showCodeInputDialog()
            } catch (e: Exception) {
                onLog("ERROR", "Login initialization failed: ${e.message}")
            }
        }

        // 2. 连接逻辑：检查系统 VPN 权限并启动服务
        btnConnect.setOnClickListener {
            if (token.isEmpty()) {
                onLog("WARN", "No token found. Please click '登录账号' first.")
                Toast.makeText(this, "请先登录获取 Token", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            val vpnIntent = VpnService.prepare(this)
            if (vpnIntent != null) {
                // 系统弹出“是否允许建立 VPN 连接”授权窗
                startActivityForResult(vpnIntent, 100)
            } else {
                // 已经有权限，直接运行
                onActivityResult(100, RESULT_OK, null)
            }
        }

        // 3. 一键全选复制所有日志
        btnCopyAll.setOnClickListener {
            val fullText = etLogs.text.toString()
            if (fullText.isNotEmpty()) {
                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                val clip = ClipData.newPlainText("Firefox VPN Logs", fullText)
                clipboard.setPrimaryClip(clip)
                Toast.makeText(this, "日志已全选复制到剪贴板", Toast.LENGTH_SHORT).show()
            }
        }

        // 4. 清空日志面板
        btnClearLog.setOnClickListener {
            etLogs.setText("")
        }
    }

    /**
     * 弹出输入框接收用户从 accounts.firefox.com 成功页面拷贝的 code 或完整 URL
     */
    private fun showCodeInputDialog() {
        val input = EditText(this).apply {
            hint = "在此粘贴页面显示的授权码或完整 URL"
            isSingleLine = false
            maxLines = 4
        }

        AlertDialog.Builder(this)
            .setTitle("输入授权码")
            .setMessage("在打开的网页登录成功后，复制页面上的 Code 或整个网址，粘贴到下方：")
            .setView(input)
            .setPositiveButton("确认提交") { _, _ ->
                val rawInput = input.text.toString().trim()
                if (rawInput.isNotEmpty()) {
                    handleAuthCode(rawInput)
                }
            }
            .setNegativeButton("稍后手动输入", null)
            .show()
    }

    /**
     * 提取 code 并调用 Go 核心兑换 Token
     */
    private fun handleAuthCode(rawInput: String) {
        // 如果用户复制的是完整 URL，提取其中的 code= 参数
        var code = rawInput
        if (rawInput.contains("code=")) {
            val uri = Uri.parse(rawInput)
            code = uri.getQueryParameter("code") ?: rawInput
        }

        onLog("INFO", "Exchanging code for token...")
        Thread {
            try {
                val accessToken = Core.finishAuthCode(code, verifier)
                token = accessToken
                onLog("INFO", "Authentication SUCCESS! Token ready.")
                runOnUiThread {
                    tvStatus.text = "状态: 登录成功，可连接"
                    Toast.makeText(this, "登录成功！", Toast.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                onLog("ERROR", "Code exchange failed: ${e.message}")
            }
        }.start()
    }

    /**
     * 接收 VPN 权限授权回调
     */
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode == 100 && resultCode == RESULT_OK) {
            onLog("INFO", "VPN permission granted. Starting FpnVpnService...")
            val intent = Intent(this, FpnVpnService::class.java).apply {
                putExtra("PROXY_PASS", token)
                // 这里可以默认选择亚太速度最快的东京 Fastly 节点进行测试
                putExtra("NODE", "tokyo.m1.fastly-masque.net:443")
            }
            startService(intent)
        } else if (requestCode == 100) {
            onLog("WARN", "User denied VPN permission.")
        }
    }

    // ==========================================
    // Core.AndroidBridge 回调接口实现
    // ==========================================

    override fun protectSocket(fd: Long): Boolean {
        // 由 FpnVpnService 在底层负责真正的保护，这里占位返回 true 即可
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
            // 自动滚动到最底部最新的一行
            scrollLog.post {
                scrollLog.fullScroll(ScrollView.FOCUS_DOWN)
            }
        }
    }
}
