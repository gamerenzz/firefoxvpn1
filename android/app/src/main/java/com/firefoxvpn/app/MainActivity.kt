package com.firefoxvpn.app

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.browser.customtabs.CustomTabsIntent
import core.Core

class MainActivity : Activity() {

    private var verifier = ""
    private var token = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val btnLogin = findViewById<Button>(R.id.btnLogin)
        val btnConnect = findViewById<Button>(R.id.btnConnect)
        val tvStatus = findViewById<TextView>(R.id.tvStatus)

        btnLogin.setOnClickListener {
            // 生成官方 Android OAuth PKCE 授权地址
            val session = Core.initAuthURL()
            verifier = session.verifier
            CustomTabsIntent.Builder().build().launchUrl(this, Uri.parse(session.authURL))
        }

        btnConnect.setOnClickListener {
            val vpnIntent = VpnService.prepare(this)
            if (vpnIntent != null) {
                startActivityForResult(vpnIntent, 100)
            } else {
                onActivityResult(100, RESULT_OK, null)
            }
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
}
