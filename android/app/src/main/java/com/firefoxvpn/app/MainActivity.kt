package com.firefoxvpn.app

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import core.AndroidBridge
import core.Core
import org.json.JSONArray

class MainActivity : Activity(), AndroidBridge {

    private lateinit var tvStatus: TextView
    private lateinit var tvSelectedNode: TextView
    private lateinit var etLogs: EditText
    private lateinit var scrollLog: ScrollView
    private lateinit var etEmail: EditText
    private lateinit var etPassword: EditText
    private lateinit var rgNodes: RadioGroup

    private var currentSessionToken = ""
    private var token = ""
    // 默认选用离中国大陆最近、100% 具备公网 A 记录解析的日本东京主力节点
    private var selectedNodeAddr = "jp0.vpn.mozilla.org:443"
    private val PREFS_NAME = "FirefoxVPNPrefs"
    private val KEY_SAVED_TOKEN = "SavedProxyToken"

    private val logReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val level = intent?.getStringExtra(FpnVpnService.EXTRA_LOG_LEVEL) ?: "INFO"
            val msg = intent?.getStringExtra(FpnVpnService.EXTRA_LOG_MSG) ?: ""
            onLog(level, msg)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        tvStatus = findViewById(R.id.tvStatus)
        tvSelectedNode = findViewById(R.id.tvSelectedNode)
        etLogs = findViewById(R.id.etLogs)
        scrollLog = findViewById(R.id.scrollLog)
        etEmail = findViewById(R.id.etEmail)
        etPassword = findViewById(R.id.etPassword)
        rgNodes = findViewById(R.id.rgNodes)

        val btnLogin = findViewById<Button>(R.id.btnLogin)
        val btnConnect = findViewById<Button>(R.id.btnConnect)
        val btnRefreshNodes = findViewById<Button>(R.id.btnRefreshNodes)
        val btnPingAll = findViewById<Button>(R.id.btnPingAll)
        val btnCopyAll = findViewById<Button>(R.id.btnCopyAll)
        val btnClearLog = findViewById<Button>(R.id.btnClearLog)

        Core.registerBridge(this)
        checkNotificationPermission()

        val filter = IntentFilter(FpnVpnService.ACTION_VPN_LOG)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(logReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(logReceiver, filter)
        }

        loadSavedToken()

        // 初始化加载候选真实节点
        loadCandidateNodes()

        // 刷新节点列表
        btnRefreshNodes.setOnClickListener {
            loadCandidateNodes()
        }

        // 一键测速所有节点
        btnPingAll.setOnClickListener {
            pingAllNodes()
        }

        // 登录
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
                        runOnUiThread { show2FADialog() }
                    } else {
                        token = result.accessToken
                        saveToken(token)
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

        // 连接选中的节点
        btnConnect.setOnClickListener {
            if (token.isEmpty()) {
                Toast.makeText(this, "请先登录账号，或长按此按钮导入 Token", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            val vpnIntent = VpnService.prepare(this)
            if (vpnIntent != null) {
                startActivityForResult(vpnIntent, 100)
            } else {
                onActivityResult(100, RESULT_OK, null)
            }
        }

        btnConnect.setOnLongClickListener {
            showImportTokenDialog()
            true
        }

        btnCopyAll.setOnClickListener {
            val fullText = etLogs.text.toString()
            if (fullText.isNotEmpty()) {
                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("VPN Logs", fullText))
                Toast.makeText(this, "日志已全选复制", Toast.LENGTH_SHORT).show()
            }
        }

        btnClearLog.setOnClickListener { etLogs.setText("") }
    }

    private fun loadCandidateNodes() {
        onLog("INFO", "Loading verified public node list...")
        Thread {
            try {
                val jsonStr = Core.fetchNodesJSON()
                val jsonArray = JSONArray(jsonStr)
                runOnUiThread {
                    rgNodes.removeAllViews()
                    for (i in 0 until jsonArray.length()) {
                        val item = jsonArray.getJSONObject(i)
                        val name = item.getString("name")
                        val addr = item.getString("addr")

                        val rb = RadioButton(this).apply {
                            text = name
                            id = i
                            tag = addr
                            setTextColor(0xFFCCCCCC.toInt())
                            textSize = 12f
                        }

                        if (addr == selectedNodeAddr || (selectedNodeAddr.isEmpty() && i == 0)) {
                            rb.isChecked = true
                            selectedNodeAddr = addr
                            tvSelectedNode.text = "选中: $name"
                        }

                        rb.setOnClickListener {
                            selectedNodeAddr = addr
                            tvSelectedNode.text = "选中: $name"
                            onLog("INFO", "Target node changed to: $addr")
                        }

                        rgNodes.addView(rb)
                    }
                    onLog("INFO", "Loaded ${jsonArray.length()} verified public nodes")
                }
            } catch (e: Exception) {
                onLog("ERROR", "Failed to load nodes: ${e.message}")
            }
        }.start()
    }

    private fun pingAllNodes() {
        onLog("INFO", "Testing latency for all candidate nodes...")
        val count = rgNodes.childCount
        Thread {
            for (i in 0 until count) {
                val rb = rgNodes.getChildAt(i) as? RadioButton ?: continue
                val addr = rb.tag as? String ?: continue
                val rtt = Core.testNodeDelay(addr)

                runOnUiThread {
                    val originalText = rb.text.toString().replace(Regex("\\[.*?\\]"), "").trim()
                    if (rtt >= 0) {
                        rb.text = "$originalText [ ${rtt}ms ]"
                        rb.setTextColor(0xFF00FF66.toInt())
                    } else {
                        rb.text = "$originalText [ 超时/未响应 ]"
                        rb.setTextColor(0xFFFF4444.toInt())
                    }
                }
            }
            onLog("INFO", "Latency testing finished!")
        }.start()
    }

    private fun loadSavedToken() {
        val prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val saved = prefs.getString(KEY_SAVED_TOKEN, "") ?: ""
        if (saved.isNotEmpty()) {
            token = saved
            tvStatus.text = "状态: 已加载缓存凭证，可连接"
            onLog("INFO", "Loaded cached token from storage (Length: ${token.length})")
        }
    }

    private fun saveToken(t: String) {
        val prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit().putString(KEY_SAVED_TOKEN, t).apply()
    }

    private fun showImportTokenDialog() {
        val input = EditText(this).apply {
            hint = "粘贴 AccessToken 或 Proxy Pass JWT"
            maxLines = 6
        }

        AlertDialog.Builder(this)
            .setTitle("手动导入凭证")
            .setView(input)
            .setPositiveButton("保存并就绪") { _, _ ->
                val text = input.text.toString().trim()
                if (text.isNotEmpty()) {
                    token = text
                    saveToken(token)
                    tvStatus.text = "状态: 凭证已就绪，可连接"
                    onLog("INFO", "Manual token imported (Length: ${text.length})")
                }
            }
            .setNegativeButton("取消", null)
            .show()
    }

    private fun checkNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.POST_NOTIFICATIONS), 200)
            }
        }
    }

    private fun show2FADialog() {
        val input = EditText(this).apply {
            hint = "输入邮箱 6 位验证码"
            inputType = android.text.InputType.TYPE_CLASS_NUMBER
        }

        AlertDialog.Builder(this)
            .setTitle("二次验证码")
            .setMessage("请输入邮箱中的登录验证码：")
            .setCancelable(false)
            .setPositiveButton("确认") { _, _ ->
                val code = input.text.toString().trim()
                if (code.isNotEmpty()) {
                    Thread {
                        try {
                            val accessToken = Core.submit2FACode(currentSessionToken, code)
                            token = accessToken
                            saveToken(token)
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
            onLog("INFO", "Starting tunnel with selected node: $selectedNodeAddr")
            val intent = Intent(this, FpnVpnService::class.java).apply {
                putExtra("ACCESS_TOKEN", token)
                putExtra("TARGET_NODE", selectedNodeAddr)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(intent)
            } else {
                startService(intent)
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        unregisterReceiver(logReceiver)
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
