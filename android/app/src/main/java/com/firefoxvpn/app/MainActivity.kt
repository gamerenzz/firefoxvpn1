package com.firefoxvpn.app

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import core.AndroidBridge
import core.Core

class MainActivity : Activity(), AndroidBridge {

    private lateinit var tvStatus: TextView
    private lateinit var etLogs: EditText
    private lateinit var scrollLog: ScrollView
    private lateinit var etEmail: EditText
    private lateinit var etPassword: EditText

    private var currentSessionToken = ""
    private var token = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        tvStatus = findViewById(R.id.tvStatus)
        etLogs = findViewById(R.id.etLogs)
        scrollLog = findViewById(R.id.scrollLog)
        etEmail = findViewById(R.id.etEmail)
        etPassword = findViewById(R.id.etPassword)

        val btnLogin = findViewById<Button>(R.id.btnLogin)
        val btnConnect = findViewById<Button>(R.id.btnConnect)
        val btnCopyAll = findViewById<Button>(R.id.btnCopyAll)
        val btnClearLog = findViewById<Button>(R.id.btnClearLog)

        // 注册桥接对象，使得所有阶段日志都能实时输出到底部面板
        Core.registerBridge(this)

        // Android 13+ 提前动态请求通知栏权限（防止前台服务被系统直接闪退）
        checkNotificationPermission()

        // 1. 账号密码直接登录
        btnLogin.setOnClickListener {
            val email = etEmail.text.toString().trim()
            val password = etPassword.text.toString().trim()

            if (email.isEmpty() || password.isEmpty()) {
                Toast.makeText(this, "请输入邮箱和密码", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            onLog("INFO", "Starting direct login for: $email")
            Thread {
                try {
                    val result = Core.loginWithPassword(email, password)
                    if (result.need2FA) {
                        currentSessionToken = result.sessionToken
                        runOnUiThread {
                            show2FADialog()
                        }
                    } else {
                        token = result.accessToken
                        runOnUiThread {
                            tvStatus.text = "状态: 登录成功，可连接"
                            Toast.makeText(this, "登录成功！", Toast.LENGTH_SHORT).show()
                        }
                    }
                } catch (e: Exception) {
                    onLog("ERROR", "Login exception: ${e.message}")
                }
            }.start()
        }

        // 2. 连接 VPN 按钮
        btnConnect.setOnClickListener {
            if (token.isEmpty()) {
                Toast.makeText(this, "请先登录账号", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            // 调用系统 VpnService 鉴权准备
            val vpnIntent = VpnService.prepare(this)
            if (vpnIntent != null) {
                startActivityForResult(vpnIntent, 100)
            } else {
                onActivityResult(100, RESULT_OK, null)
            }
        }

        // 3. 全选复制日志
        btnCopyAll.setOnClickListener {
            val fullText = etLogs.text.toString()
            if (fullText.isNotEmpty()) {
                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                val clip = ClipData.newPlainText("VPN Logs", fullText)
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
     * 针对 Android 13+ 检查并申请 POST_NOTIFICATIONS 权限，防止启动 Service 崩溃
     */
    private fun checkNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(
                    this,
                    arrayOf(Manifest.permission.POST_NOTIFICATIONS),
                    200
                )
            }
        }
    }

    /**
     * 二次验证码弹窗
     */
    private fun show2FADialog() {
        val input = EditText(this).apply {
            hint = "输入邮箱中收到的 6 位验证码"
            inputType = android.text.InputType.TYPE_CLASS_NUMBER
        }

        AlertDialog.Builder(this)
            .setTitle("二次验证码")
            .setMessage("已向您的邮箱发送了登录确认码，请输入：")
            .setView(input)
            .setCancelable(false)
            .setPositiveButton("确认验证") { _, _ ->
                val code = input.text.toString().trim()
                if (code.isNotEmpty()) {
                    Thread {
                        try {
                            val accessToken = Core.submit2FACode(currentSessionToken, code)
                            token = accessToken
                            runOnUiThread {
                                tvStatus.text = "状态: 验证成功，可连接"
                                Toast.makeText(this, "验证成功！", Toast.LENGTH_SHORT).show()
                            }
                        } catch (e: Exception) {
                            onLog("ERROR", "2FA validation failed: ${e.message}")
                        }
                    }.start()
                }
            }
            .show()
    }

    /**
     * 接收 VPN 权限授予回调，启动后台隧道服务
     */
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode == 100 && resultCode == RESULT_OK) {
            onLog("INFO", "VPN permission granted. Launching tunnel service...")
            val intent = Intent(this, FpnVpnService::class.java).apply {
                // 传入刚才登录拿到的官方 AccessToken
                putExtra("ACCESS_TOKEN", token)
                // 默认选择延迟极低的 Fastly 东京节点测试
                putExtra("NODE", "tokyo.m1.fastly-masque.net:443")
            }
            
            // 安全启动前台服务
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    startForegroundService(intent)
                } else {
                    startService(intent)
                }
            } catch (e: Exception) {
                onLog("ERROR", "Failed to start service: ${e.message}")
            }
        } else if (requestCode == 100) {
            onLog("WARN", "User cancelled or denied VPN permission.")
        }
    }

    // ==========================================
    // Core.AndroidBridge 接口实现
    // ==========================================

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
            // 自动滚动到最新日志
            scrollLog.post {
                scrollLog.fullScroll(ScrollView.FOCUS_DOWN)
            }
        }
    }
}
