package com.firefoxvpn.app

import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
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

        Core.registerBridge(this)

        // 1. 原生登录（不再打开浏览器）
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

        // 2. 连接 VPN
        btnConnect.setOnClickListener {
            if (token.isEmpty()) {
                Toast.makeText(this, "请先登录账号", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
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
                Toast.makeText(this, "日志已全选复制", Toast.LENGTH_SHORT).show()
            }
        }

        // 4. 清空日志
        btnClearLog.setOnClickListener { etLogs.setText("") }
    }

    private fun show2FADialog() {
        val input = EditText(this).apply {
            hint = "输入邮箱中收到的 6 位验证码"
            inputType = android.text.InputType.TYPE_CLASS_NUMBER
        }

        AlertDialog.Builder(this)
            .setTitle("二次验证码")
            .setMessage("已向您的邮箱发送了验证码，请输入：")
            .setView(input)
            .setCancelable(false)
            .setPositiveButton("验证") { _, _ ->
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
                            onLog("ERROR", "2FA failed: ${e.message}")
                        }
                    }.start()
                }
            }
            .show()
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

    override fun protectSocket(fd: Long): Boolean = true

    override fun onStatusUpdate(status: String?) {
        runOnUiThread { tvStatus.text = "状态: $status" }
    }

    override fun onLog(level: String?, message: String?) {
        runOnUiThread {
            etLogs.append("[$level] $message\n")
            scrollLog.post { scrollLog.fullScroll(ScrollView.FOCUS_DOWN) }
        }
    }
}
