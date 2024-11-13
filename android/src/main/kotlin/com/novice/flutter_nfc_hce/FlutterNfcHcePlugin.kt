package com.novice.flutter_nfc_hce

import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.nfc.NfcAdapter
import android.os.Build
import android.util.Log
import androidx.annotation.RequiresApi
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result

/** FlutterNfcHcePlugin */
class FlutterNfcHcePlugin: FlutterPlugin, MethodCallHandler, ActivityAware  {
    // add code
    private var mNfcAdapter: NfcAdapter? = null
    private var activity: Activity? = null
    private lateinit var channel : MethodChannel

    override fun onAttachedToEngine(flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
        channel = MethodChannel(flutterPluginBinding.binaryMessenger, "flutter_nfc_hce")
        channel.setMethodCallHandler(this)
    }

    //2023.09.15 refactoring code
    override fun onMethodCall(call: MethodCall, result: Result) {
        when (call.method) {
            "getPlatformVersion" -> {
                result.success("Android ${android.os.Build.VERSION.RELEASE}")
            }
            "startNfcHce" -> {
                val content = call.argument<String>("content")
                val mimeType = call.argument<String>("mimeType")
                val persistMessage = call.argument<Boolean>("persistMessage")
                val iso7816Mode = call.argument<Boolean>("iso7816Mode") ?: false

                if (content != null && mimeType != null && persistMessage != null) {
                    startNfcHce(content, mimeType, persistMessage, iso7816Mode)
                    result.success("success")
                } else {
                    result.success("failure")
                }
            }
            "stopNfcHce" -> {
                stopNfcHce()
                result.success("success")
            }
            "isNfcHceSupported" -> {
                result.success(if (isNfcHceSupported()) "true" else "false")
            }
            "isSecureNfcEnabled" -> {
                result.success(
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && isSecureNfcEnabled()) 
                        "true" else "false"
                )
            }
            "isNfcEnabled" -> {
                result.success(if (isNfcEnabled()) "true" else "false")
            }
            else -> {
                result.notImplemented()
            }
        }
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }

    override fun onDetachedFromActivity() {
        activity = null
        mNfcAdapter = null
    }

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
        activity = binding.activity
        mNfcAdapter = NfcAdapter.getDefaultAdapter(activity)
    }

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activity = binding.activity
        mNfcAdapter = NfcAdapter.getDefaultAdapter(activity)
    }

    override fun onDetachedFromActivityForConfigChanges() {
        activity = null
        mNfcAdapter = null
    }
    private fun startNfcHce(content: String, mimeType: String, persistMessage: Boolean, iso7816Mode: Boolean) {
        if (isNfcHceSupported()) {
            Log.i("NfcHce", "Starting HCE service with ISO7816 mode: $iso7816Mode")
            initService(content, mimeType, persistMessage, iso7816Mode)
        }
    }

    private fun stopNfcHce() {
        val intent = Intent(activity, KHostApduService::class.java)
        activity?.stopService(intent)
    }

    private fun isNfcHceSupported() =
        isNfcEnabled() && activity?.packageManager!!.hasSystemFeature(PackageManager.FEATURE_NFC_HOST_CARD_EMULATION)

    //2023.09.08 add function
    @RequiresApi(Build.VERSION_CODES.Q)
    private fun isSecureNfcEnabled(): Boolean {
        Log.i("TEST", "---------------------->isSecureNfcEnabled: " + mNfcAdapter?.isSecureNfcEnabled)

        return mNfcAdapter?.isSecureNfcEnabled == true
    }

    private fun initService(content: String, mimeType: String, persistMessage: Boolean, iso7816Mode: Boolean) {
        val intent = Intent(activity, KHostApduService::class.java)
        intent.putExtra("content", content)
        intent.putExtra("mimeType", mimeType)
        intent.putExtra("persistMessage", persistMessage)
        intent.putExtra("iso7816Mode", iso7816Mode)
        activity?.startService(intent)
    }

    private fun isNfcEnabled(): Boolean {
        return mNfcAdapter?.isEnabled == true
    }
}
